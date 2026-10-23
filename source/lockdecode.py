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

The holder has to be inferred: a CPU outside the queue that has the lock
(or a pointer just below it) on its stack, and whose preempt depth is not
0 where the kernel keeps one.  A likely holder that is itself queued on
another lock links the two, and a cycle of such links is a deadlock.

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


BT_HEADER = re.compile(r'PID:\s*(\d+)\s+TASK:\s*([0-9a-f]+)\s+CPU:\s*(\d+)'
                       r'\s+COMMAND:\s*"([^"]*)"')
BT_FRAME = re.compile(r"#\d+\s+\[[0-9a-f]+\]\s+(\S+)\s+at\s|"
                      r"\[exception RIP:\s*([A-Za-z0-9_.]+)")
# Functions a CPU spins or halts in while waiting for a spinlock: the
# qspinlock slowpath, the RHEL7 ticket spin inlined in _raw_spin_lock*, and
# the paravirt ticket halt.
SLOWPATH = "queued_spin_lock_slowpath"
SPIN_FUNCS = (SLOWPATH, "_raw_spin_lock",
              "kvm_lock_spinning", "xen_lock_spinning",
              "read_lock_slowpath", "write_lock_slowpath")
# rwlock_t waiters: queued_{read,write}_lock_slowpath.
RW_SPIN_FUNCS = ("read_lock_slowpath", "write_lock_slowpath")
# Waiting for an RCU grace period (percpu_down_write() does, before it
# takes the semaphore: rcu_sync_enter(), RHEL7 synchronize_sched_expedited()).
RCU_WAIT_FUNCS = ("synchronize_rcu", "synchronize_sched", "wait_rcu_gp",
                  "rcu_sync_enter")


def parse_bt(text):
    """The active task and the functions on a 'bt -f -c <cpu>' backtrace,
    innermost first (an exception RIP before the frame it interrupted)."""
    info = {"pid": None, "task": None, "comm": "", "funcs": []}
    m = BT_HEADER.search(text)
    if m:
        info["pid"] = int(m.group(1))
        info["task"] = int(m.group(2), 16)
        info["comm"] = m.group(4)
    for m in BT_FRAME.finditer(text):
        info["funcs"].append(m.group(1) or m.group(2))
    return info


# A pointer this far below the lock may be to the object that contains it.
NEAR_WINDOW = 512


def lock_refs(lock, words):
    """('exact', 0) when the lock's address is among the words, ('near', d)
    for the closest pointer d bytes below it, else None."""
    if lock in words:
        return "exact", 0
    near = [lock - w for w in words if 0 < lock - w <= NEAR_WINDOW]
    if near:
        return "near", min(near)
    return None


# Frames of interrupt or softirq context.  The NMI that stopped a CPU for
# the dump is not one: every CPU but the panicking one shows it.
IRQ_FUNCS = ("do_IRQ", "common_interrupt", "sysvec_", "apic_timer_interrupt",
             "call_function_interrupt", "handle_irq_event", "__do_softirq",
             "do_softirq", "irq_exit")


def rw_wait_lock_frame(funcs):
    """'read' / 'write' when the frame right outside the qspinlock slowpath
    is a qrwlock slowpath: the CPU queues on that rwlock's wait_lock, not
    on a spinlock taken in an interrupt that came in during the rwlock
    spin."""
    for i, f in enumerate(funcs):
        if SLOWPATH not in f:
            continue
        outer = [g for g in funcs[i + 1:] if SLOWPATH not in g]
        if outer:
            if "read_lock_slowpath" in outer[0]:
                return "read"
            if "write_lock_slowpath" in outer[0]:
                return "write"
        return None
    return None


def waits_for_rcu(funcs, frame):
    """Whether an RCU grace-period wait is inner to the first frame
    containing 'frame'."""
    for i, f in enumerate(funcs):
        if frame in f:
            return any(r in g for g in funcs[:i] for r in RCU_WAIT_FUNCS)
    return False


def is_spinning(funcs):
    return any(s in f for f in funcs for s in SPIN_FUNCS)


def in_interrupt(funcs):
    """Whether the spinning runs in interrupt context: an interrupt frame
    outer to the first spin frame (funcs are innermost first).  One inner
    to it, such as the watchdog timer that fired during the spin and
    panicked, is not."""
    spin = [i for i, f in enumerate(funcs) if any(s in f for s in SPIN_FUNCS)]
    start = spin[0] + 1 if spin else 0
    return any(s in f for f in funcs[start:] for s in IRQ_FUNCS)


def pending_targets(words, read_val, nr_cpus, exclude=()):
    """Words that can be the qspinlock a CPU spins on as the pending waiter
    (it takes no queue node): locked byte 1 or _Q_SLOW_VAL and pending set,
    with nothing else in the pending byte on the small layout."""
    pending_bits = qspinlock_layout(nr_cpus)[0]
    found = []
    for addr in sorted(words):
        if any(start <= addr < end for start, end in exclude):
            continue
        val = read_val(addr)
        if val is None:
            continue
        pend = (val >> 8) & ((1 << pending_bits) - 1)
        if pend == 1 and (val & Q_LOCKED_MASK) in (Q_LOCKED_VAL, Q_SLOW_VAL):
            found.append(addr)
    return found


def rank_holders(lock, cpus, waiters, waits_for, preempt, preempt_kept):
    """CPUs that may hold 'lock', most likely first.

    cpus is {cpu: {"words": set, "funcs": [...]}}; waiters the CPUs queued
    on this lock; waits_for {cpu: lock} for CPUs queued or pending on any
    lock; preempt {cpu: preempt_count}.  A non-RT spinlock holder runs with
    preemption disabled, so with preempt_kept (CONFIG_PREEMPT_COUNT) a
    preempt depth of 0 rules a CPU out -- unless that would rule out every
    CPU, since arch_spin_lock() users do not raise it.  A waiter on this
    lock spinning in interrupt context is kept: the code it interrupted may
    hold the lock (AA deadlock).  Returns ([candidate], [ruled out]), each
    {"cpu", "score", "notes"}."""
    candidates = []
    ruled_out = []
    for cpu in sorted(cpus):
        funcs = cpus[cpu]["funcs"]
        own = cpu in waiters or waits_for.get(cpu) == lock
        if own and not in_interrupt(funcs):
            continue
        ref = lock_refs(lock, cpus[cpu]["words"])
        if ref is None:
            continue
        kind, dist = ref
        notes = ["lock address on stack" if kind == "exact" else
                 "pointer to lock-0x%x on stack (containing object?)" % dist]
        score = 2 if kind == "exact" else 1
        count = preempt.get(cpu)
        if count is not None:
            notes.append("preempt depth %d" % (count & 0xff))
        other = waits_for.get(cpu)
        if own:
            notes.append("waits for this lock from interrupt context: possible"
                         " AA deadlock if the interrupted code holds it")
            score = 1
        elif other is not None:
            notes.append("itself waiting for lock 0x%x" % other)
        elif is_spinning(funcs):
            # A ticket waiter, or a qspinlock waiter whose lock was not found:
            # on this lock or another.
            notes.append("spinning on a spinlock not identified (a waiter?)")
            score -= 1
        entry = {"cpu": cpu, "score": score, "notes": notes}
        if preempt_kept and count is not None and (count & 0xff) == 0:
            ruled_out.append(entry)
        else:
            candidates.append(entry)
    if not candidates and ruled_out:
        for entry in ruled_out:
            entry["notes"].append("holds it only if taken with arch_spin_lock()")
        candidates, ruled_out = ruled_out, []
    candidates.sort(key=lambda c: (-c["score"], c["cpu"]))
    return candidates, ruled_out


def find_deadlocks(holders, waits_for):
    """Cycles lock -> likely holder -> lock it waits for -> ... .

    holders is {lock: [cpu, ...]} (the best-scored candidates); waits_for
    {cpu: lock}.  Returns each cycle once as [(lock, cpu), ...]."""
    cycles = []
    seen = set()
    for start in sorted(holders):
        path = []
        lock = start
        on_path = {}
        while lock in holders and lock not in on_path:
            on_path[lock] = len(path)
            nxt = None
            for cpu in holders[lock]:
                if waits_for.get(cpu) not in (None, lock):
                    nxt = (cpu, waits_for[cpu])
                    break
            if nxt is None:
                break
            path.append((lock, nxt[0]))
            lock = nxt[1]
        if lock in on_path:
            cycle = path[on_path[lock]:]
            key = frozenset(cycle)
            if cycle and key not in seen:
                seen.add(key)
                cycles.append(cycle)
    return cycles


# ---- sleeping locks: mutex and rw_semaphore ----
#
# These record their owner.  mutex.owner (4.10+, RHEL8 on) is the owning
# task with MUTEX_FLAG_* in the low 3 bits; the RHEL7 mutex keeps a count
# (1 free, 0 locked, < 0 locked with waiters) and a plain owner pointer.
# rw_semaphore.owner is the writer, or the LAST reader to take it with
# RWSEM_READER_OWNED set -- readers are not tracked.  Waiters sit on
# wait_list in mutex_waiter / rwsem_waiter structs on their own stacks.

MUTEX_FLAGS = ((0x1, "WAITERS"), (0x2, "HANDOFF"), (0x4, "PICKUP"))
RWSEM_READER_OWNED = 0x1
RWSEM_OWNER_FLAGS = 0x3     # READER_OWNED, NONSPINNABLE (RHEL7: ANONYMOUSLY_OWNED)
RWSEM_WAITING_FOR_WRITE = 0
MASK64 = 0xffffffffffffffff


def signed(val, bits):
    val &= (1 << bits) - 1
    return val - (1 << bits) if val >> (bits - 1) else val


def decode_mutex(owner, count=None):
    """owner is the owner word; count is the RHEL7 atomic_t count (None on
    4.10+, where the owner word alone says whether it is locked)."""
    owner &= MASK64
    if count is None:
        task = owner & ~0x7 & MASK64
        flags = [name for bit, name in MUTEX_FLAGS if owner & bit]
        # PICKUP: __mutex_handoff() named the next waiter, which still has
        # to run and take it; nobody holds it meanwhile.
        if "PICKUP" in flags:
            return {"locked": True, "owner": None, "handoff_to": task or None,
                    "flags": flags}
        return {"locked": task != 0, "owner": task or None, "handoff_to": None,
                "flags": flags}
    count = signed(count, 32)
    return {"locked": count < 1, "owner": owner or None, "handoff_to": None,
            "flags": ["WAITERS"] if count < 0 else []}


def decode_rwsem(count, owner, old=False, has_waiters=False):
    """rw_semaphore state.  old is the RHEL7 x86_64 bias layout: the low 32
    bits count active lockers, the high half goes down by one for waiters
    and once more for a writer.  has_waiters (wait_list not empty) settles
    the one case the old count cannot: one reader with waiters and a writer
    alone both read 0xffffffff00000001."""
    count &= MASK64
    owner &= MASK64
    task = owner & ~RWSEM_OWNER_FLAGS & MASK64
    reader_owned = bool(owner & RWSEM_READER_OWNED)
    if old:
        active = count & 0xffffffff
        high = signed(count, 64) >> 32
        writer = active > 0 and ((task != 0 and not reader_owned) or high <= -2 or
                                 (high == -1 and not has_waiters))
        readers = 0 if writer or high < -1 else active
        waiters = high <= -2 or (high == -1 and not writer) or has_waiters
    else:
        writer = bool(count & 0x1)                  # RWSEM_WRITER_LOCKED
        readers = (count >> 8) & ((1 << 55) - 1)    # bits 8-62
        waiters = bool(count & 0x2)                 # RWSEM_FLAG_WAITERS
    return {
        "writer": writer,
        "readers": readers,
        "locked": writer or readers > 0,
        "waiters": waiters,
        "owner": task if task and not reader_owned else None,
        "last_reader": task if task and reader_owned else None,
    }


BT_SLOT_LINE = re.compile(r"^\s*([0-9a-f]{16}):((?:\s+[0-9a-f]{16})+)\s*$",
                          re.MULTILINE)


def bt_slots(text):
    """{stack address: value} from the 'addr: word word' lines of bt -f."""
    slots = {}
    for m in BT_SLOT_LINE.finditer(text.lower()):
        addr = int(m.group(1), 16)
        for i, word in enumerate(m.group(2).split()):
            slots[addr + 8 * i] = int(word, 16)
    return slots


def split_tasks(text):
    """The per-task blocks of 'foreach ... bt' output."""
    blocks = re.split(r"(?m)^(?=PID:)", text)
    return [b for b in blocks if b.startswith("PID:")]


def walk_list(head, read_ptr, slist=False, limit=100000):
    """Entries of a list_head ring at 'head', in order.  With slist (RHEL7
    rwsem) head only points at the first entry and is not on the ring."""
    entries = []
    first = read_ptr(head)
    if first is None or first == head:
        return entries
    stop = first if slist else head
    entry = first
    while entry is not None and len(entries) < limit:
        entries.append(entry)
        entry = read_ptr(entry)
        if entry == stop:
            return entries
    return entries          # broken or too long: what was read


def find_wait_lock(task, slots, words, read_ptr, task_off, list_off, slist=False,
                   is_waiter=None, valid_lock=None, exclude=()):
    """The lock a sleeping task waits on, found from its own waiter struct.

    The waiter (mutex_waiter / rwsem_waiter / wait_queue_entry) lives on
    the task's stack with .task (.private) == task, task_off bytes from its
    list node (negative when the node comes after it).  Its list ring holds the other waiters and the lock's
    wait_list head.  With is_waiter(entry) the head is the one ring entry
    that is not a waiter, and the lock pointer need not be on the stack.
    Otherwise -- or for the RHEL7 rwsem slist, whose head is off the ring
    -- the lock is a stack word whose wait_list is that head (on the ring,
    or for slist pointing into it), not in exclude [(start, end)] and
    passing valid_lock(lock).  Returns (lock or None, waiter or None)."""
    for slot in sorted(slots):
        if slots[slot] != task:
            continue
        waiter = slot - task_off      # its list node
        nxt, prv = read_ptr(waiter), read_ptr(waiter + 8)
        if nxt is None or prv is None or read_ptr(nxt + 8) != waiter or read_ptr(prv) != waiter:
            continue
        ring = set()
        entry = waiter
        while entry is not None and entry not in ring and len(ring) < 100000:
            ring.add(entry)
            entry = read_ptr(entry)
        if not slist and is_waiter is not None:
            heads = [e for e in ring if e != waiter and not is_waiter(e)]
            if len(heads) == 1:
                return heads[0] - list_off, waiter
        for lock in sorted(words):
            head = lock + list_off
            if head == waiter or any(start <= lock < end for start, end in exclude):
                continue
            if not ((not slist and head in ring) or (slist and read_ptr(head) in ring)):
                continue
            if valid_lock is None or valid_lock(lock):
                return lock, waiter
        return None, waiter
    return None, None


def find_by_field(words, read_ptr, field_off, value):
    """Stack words W with *(W + field_off) == value: the percpu_rw_semaphore
    whose rcuwait 'writer' names a task waiting for readers to leave."""
    return [w for w in sorted(words) if read_ptr(w + field_off) == value]


def decode_qrwlock(cnts, old=False):
    """rwlock_t (qrwlock).  The low byte is 0xff while a writer holds it;
    a waiting writer sets bit 8 (_QW_WAITING) and readers count from bit 9.
    old is RHEL7: waiting writer is the low byte == 1, readers from bit 8.
    A reader that finds a writer adds itself, then backs out, so the count
    can include CPUs that are about to wait."""
    cnts &= 0xffffffff
    low = cnts & 0xff
    if old:
        waiting = low == 1
        readers = cnts >> 8
    else:
        waiting = bool(cnts & 0x100)
        readers = cnts >> 9
    writer = low == 0xff
    return {"writer": writer, "waiting_writer": waiting, "readers": readers,
            "locked": writer or readers > 0}


def describe_qrwlock(d):
    if d["writer"]:
        state = "write-locked"
    elif d["readers"]:
        state = "read-locked by %d reader(s)" % d["readers"]
    else:
        state = "unlocked"
    if d["waiting_writer"]:
        state += ", a writer waiting"
    return state


def decode_percpu_rwsem(read_counts, block, writer_waiting=None):
    """percpu_rw_semaphore (5.8+, RHEL8 on).  Readers are the sum of the
    per-CPU read_count (one CPU's count can go negative: a reader may
    release it on another CPU).  'block' is set by a writer, which then
    waits in the rcuwait 'writer' for the readers to leave and, once in,
    is not recorded."""
    readers = sum(signed(c, 32) for c in read_counts)
    block = bool(block)
    return {
        "readers": readers,
        "block": block,
        "writer_waiting": writer_waiting or None,
        "writer": block and readers == 0 and not writer_waiting,
        "locked": block or readers > 0,
    }


def decode_percpu_rwsem_old(fast_counts, slow_read_ctr, write_ctr):
    """RHEL7 percpu_rw_semaphore: readers on the fast path count per CPU,
    slow-path readers in slow_read_ctr; write_ctr counts writers holding or
    waiting for the embedded rw_sem."""
    readers = sum(signed(c, 32) for c in fast_counts) + signed(slow_read_ctr, 32)
    writers = signed(write_ctr, 32)
    return {
        "readers": readers,
        "block": writers > 0,
        "writer_waiting": None,
        "writer": writers > 0 and readers == 0,
        "locked": writers > 0 or readers > 0,
    }


def describe_percpu_rwsem(d):
    if d["writer_waiting"]:
        return "a writer is waiting for %d reader(s) to leave" % d["readers"]
    if d["writer"]:
        return "write-held (the writer is not recorded)"
    if d["readers"] > 0:
        state = "read-held by %d reader(s), which are not recorded" % d["readers"]
        return state + (", blocked for a writer" if d["block"] else "")
    return "blocked for a writer" if d["block"] else "unlocked"


RWBASE_READER_BIAS = 1 << 31
RWBASE_WRITER_BIAS = 1 << 30


def decode_rwbase(readers, rt_owner):
    """PREEMPT_RT rw_semaphore / rwlock_t (rwbase_rt).  While no writer is
    in, readers holds READER_BIAS plus the reader count; a writer removes
    the bias and waits for the count to drain, holding the rt_mutex, then
    sets WRITER_BIAS."""
    readers &= 0xffffffff
    rt_owner &= MASK64
    task = rt_owner & ~1 & MASK64
    if readers & RWBASE_READER_BIAS:
        count, writer, pending = readers - RWBASE_READER_BIAS, False, False
    elif readers == RWBASE_WRITER_BIAS:
        count, writer, pending = 0, True, False
    else:
        count, writer, pending = readers, False, True
    return {
        "writer": writer,
        "readers": count,
        "locked": writer or count > 0 or pending,
        "waiters": bool(rt_owner & 1),
        "owner": task or None,
        "last_reader": None,
        "writer_pending": pending,
    }


def root_owners(owners, waits_for):
    """Follow lock -> owner -> lock the owner waits for, to where each chain
    ends.  owners is {lock: owner}, waits_for {task: lock}.  Returns
    {lock: ("task", owner)} for an owner not waiting for a lock, {lock:
    ("lock", other)} for a chain ending at a lock whose owner is not
    recorded (a read-held rwsem), and {lock: None} on a cycle."""
    roots = {}
    for lock in owners:
        seen = set()
        cur = lock
        root = None
        while True:
            if cur in seen:
                root = None
                break
            seen.add(cur)
            owner = owners[cur]
            if owner not in waits_for:
                root = ("task", owner)
                break
            cur = waits_for[owner]
            if cur not in owners:
                root = ("lock", cur)
                break
        roots[lock] = root
    return roots


if (__name__ == '__main__'):
    for arg in sys.argv[1:]:
        d = decode_qspinlock(int(arg, 0), 8192)
        print("0x%08x: %s" % (d["value"], describe_qspinlock(d)))
