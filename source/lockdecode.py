"""
Spinlock word decoding, MCS queue reconstruction and lock-address matching
for 'lockinfo'.  Nothing here reads the dump, so it can be checked offline.

qspinlock (include/asm-generic/qspinlock_types.h), one 32-bit word:
  CONFIG_NR_CPUS < 16K   bits 0-7 locked, 8-15 pending, 16-17 tail index,
                         18-31 tail cpu + 1
  CONFIG_NR_CPUS >= 16K  bits 0-7 locked, 8 pending, 9-10 tail index,
                         11-31 tail cpu + 1
The tail names the LAST waiter queued: per-CPU MCS node 'qnodes[idx]' (or
'mcs_nodes[idx]' before 5.0) of 'cpu'.  Waiters are linked head to tail by
node->next, and qnodes[0].count on each CPU says how many of its four nodes
are in use (one per nesting level: task, softirq, hardirq, NMI).  The holder
is never recorded: it is not in the queue.

Ticket spinlock (RHEL7): head is the ticket being served, tail the next one
handed out.  With CONFIG_PARAVIRT_SPINLOCKS tickets step by 2 and bit 0 is
TICKET_SLOWPATH_FLAG.

    python3 lockdecode.py 0x00140101 ...

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import re
import sys


MAX_NODES = 4
Q_LOCKED_MASK = 0xff
Q_LOCKED_VAL = 1
# pvqspinlock: the queue head halted and hashed (lock, node) in pv_lock_hash.
Q_SLOW_VAL = 3


def qspinlock_layout(nr_cpus):
    """(pending bits, tail index offset, tail cpu offset, tail cpu bits) for
    a kernel built with CONFIG_NR_CPUS = nr_cpus."""
    if nr_cpus < (1 << 14):
        return 8, 16, 18, 14
    return 1, 9, 11, 21


def encode_tail(cpu, idx, nr_cpus):
    _, idx_off, cpu_off, _ = qspinlock_layout(nr_cpus)
    return ((cpu + 1) << cpu_off) | (idx << idx_off)


def decode_qspinlock(val, nr_cpus):
    pending_bits, idx_off, cpu_off, cpu_bits = qspinlock_layout(nr_cpus)
    val &= 0xffffffff
    tail_cpu = ((val >> cpu_off) & ((1 << cpu_bits) - 1)) - 1
    return {
        "value": val,
        "locked": val & Q_LOCKED_MASK,
        "pending": 1 if (val >> 8) & ((1 << pending_bits) - 1) else 0,
        "tail_idx": (val >> idx_off) & 0x3,
        "tail_cpu": tail_cpu if tail_cpu >= 0 else None,
    }


def describe_qspinlock(d):
    if d["locked"] == 0:
        state = "unlocked"
    elif d["locked"] == Q_LOCKED_VAL:
        state = "locked"
    elif d["locked"] == Q_SLOW_VAL:
        state = "locked (_Q_SLOW_VAL: the queue head halted, paravirt)"
    else:
        state = "locked byte 0x%x is not a valid value (corrupted?)" % d["locked"]
    if d["pending"]:
        state += ", one CPU pending (spinning outside the queue)"
    if d["tail_cpu"] is not None:
        state += ", queue tail CPU %d slot %d" % (d["tail_cpu"], d["tail_idx"])
    elif d["locked"]:
        state += ", no CPU queued"
    return state


def decode_tickets(head, tail, bits, inc=1):
    """Holder and waiter count of a ticket lock.  inc is __TICKET_LOCK_INC
    (2 with CONFIG_PARAVIRT_SPINLOCKS, where bit 0 is the slowpath flag)."""
    flag = 1 if inc == 2 else 0
    mask = (1 << bits) - 1
    tickets = ((tail & ~flag) - (head & ~flag)) & mask
    tickets //= inc
    return {
        "head": head & mask,
        "tail": tail & mask,
        "held": tickets > 0,
        "waiters": max(tickets - 1, 0),
        "slowpath": bool((head | tail) & flag),
    }


def ticket_position(want, head, bits, inc=1):
    """How many tickets ahead of 'want' are still to be served (0 = next,
    -1 = being served: kicked, not yet running)."""
    flag = 1 if inc == 2 else 0
    mask = (1 << bits) - 1
    return (((want & ~flag) - (head & ~flag)) & mask) // inc - 1


def in_use_slots(count):
    """Queue nodes in use on a CPU whose qnodes[0].count is 'count'.  Past
    MAX_NODES the kernel spins on trylock without a node."""
    return max(0, min(count, MAX_NODES))


def build_queues(nodes):
    """Chains of in-use MCS nodes, head first.

    nodes is {node_addr: (cpu, idx, next_addr)} for in-use nodes only.
    Returns [(chain, broken)] where chain is a list of node addresses and
    broken says the links were not a simple list (a cycle, or two nodes
    claiming the same successor), which a live queue never is."""
    pred = {}
    shared = set()
    for addr, (_, _, nxt) in nodes.items():
        if nxt in nodes and nxt != addr:
            if nxt in pred:
                shared.add(nxt)
            else:
                pred[nxt] = addr

    def order(a):
        return nodes[a][0], nodes[a][1]

    queues = []
    seen = set()
    for start in sorted(nodes, key=order):
        if start in pred or start in seen:
            continue
        chain = []
        addr = start
        broken = False
        while addr in nodes:
            if addr in seen:
                broken = True
                break
            chain.append(addr)
            seen.add(addr)
            if addr in shared:
                broken = True
            addr = nodes[addr][2]
        queues.append((chain, broken))

    # Whatever is left has a predecessor all the way round: a cycle.
    for start in sorted(nodes, key=order):
        if start in seen:
            continue
        chain = []
        addr = start
        while addr in nodes and addr not in seen:
            chain.append(addr)
            seen.add(addr)
            addr = nodes[addr][2]
        queues.append((chain, True))
    return queues


WORD = re.compile(r"\b([0-9a-f]{16})\b")
# 'bt -f' prints where each stack word lives ("ffffb4a1c0237e58:") and each
# frame's stack pointer ("#3 [ffffb4a1c0237e50]"): those are stack slots,
# not values the waiter held.
STACK_SLOT = re.compile(r"^\s*[0-9a-f]{16}:|\[[0-9a-f]{16}\]", re.MULTILINE)
# Lowest kernel address on any layout: 4-level x86 starts at ffff8...,
# 5-level at ff11... (vmalloc ffa0...), 52-bit VA arm64 at fff0....
KERNEL_START = 0xff00000000000000


def candidate_words(text):
    """4-byte aligned kernel addresses held in 'bt -f' output: stack word
    values and exception-frame registers."""
    words = set()
    for m in WORD.finditer(STACK_SLOT.sub(" ", text.lower())):
        addr = int(m.group(1), 16)
        if addr >= KERNEL_START and addr % 4 == 0:
            words.add(addr)
    return words


def match_lock(candidates, read_val, tail_cpu, tail_idx, nr_cpus, exclude=()):
    """Addresses that can be the lock a queue waits for.

    candidates is {cpu: set(addr)} from each waiter's stack and registers;
    read_val(addr) returns the 32-bit word there or None.  A candidate
    matches when its tail field names the queue's tail node, which an
    unrelated word is very unlikely to do.  exclude is [(start, end)] ranges
    (the MCS nodes themselves).  Returns [(addr, decoded, n_cpus)] with the
    address seen on the most waiters' stacks first."""
    seen_on = {}
    for cpu, words in candidates.items():
        for addr in words:
            seen_on.setdefault(addr, set()).add(cpu)

    tail = encode_tail(tail_cpu, tail_idx, nr_cpus)
    _, idx_off, _, _ = qspinlock_layout(nr_cpus)
    tail_mask = 0xffffffff & ~((1 << idx_off) - 1)
    found = []
    for addr, cpus in seen_on.items():
        if any(start <= addr < end for start, end in exclude):
            continue
        val = read_val(addr)
        if val is None or (val & tail_mask) != tail:
            continue
        found.append((addr, decode_qspinlock(val, nr_cpus), len(cpus)))
    found.sort(key=lambda f: (-f[2], f[0]))
    return found


if (__name__ == '__main__'):
    for arg in sys.argv[1:]:
        d = decode_qspinlock(int(arg, 0), 8192)
        print("0x%08x: %s" % (d["value"], describe_qspinlock(d)))
