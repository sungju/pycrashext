"""
'lockinfo' command: spinlock and MCS-lock information.

A spinlock does not record its holder.  What the dump does record is who
waits: a qspinlock's tail names the last CPU queued, and each queued CPU's
MCS node links to the one behind it.  lockinfo rebuilds those queues from
the per-CPU nodes in use and, for each queue, finds the lock on the waiters'
stacks by checking that the lock word's tail names the queue's tail.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from pykdump.API import *

from LinuxDump import percpu

import crashcolor
import lockdecode

import sys


NR_CPUS=0

def get_nr_cpus():
    """CONFIG_NR_CPUS: it, not the number of CPUs online, sets the qspinlock
    tail layout."""
    global NR_CPUS

    if NR_CPUS:
        return NR_CPUS
    try:
        for line in exec_crash_command("help -k").splitlines():
            words = line.split(':')
            if words[0].strip() == 'kernel_NR_CPUS' and int(words[1]) > 0:
                NR_CPUS = int(words[1])
                return NR_CPUS
    except:
        pass
    # __per_cpu_offset is __per_cpu_offset[NR_CPUS].
    try:
        NR_CPUS = len(readSymbol("__per_cpu_offset"))
        if NR_CPUS > 0:
            return NR_CPUS
    except:
        pass

    print("CONFIG_NR_CPUS not found: assuming the qspinlock layout of %d CPUs"
          % sys_info.CPUS)
    NR_CPUS = sys_info.CPUS
    return NR_CPUS


def read_u32(addr):
    try:
        return readUInt(addr)
    except:
        return None


def lock_name(addr):
    try:
        sym = addr2sym(addr)
        if sym:
            return " (%s)" % sym
    except:
        pass
    return ""


def mcs_node_layout():
    """(per-CPU symbol, size of one node, offset of its mcs_spinlock).
    5.0 renamed mcs_nodes to qnodes and wrapped each node in struct qnode."""
    if struct_exists("struct qnode"):
        return ("qnodes", getSizeOf("struct qnode"),
                member_offset("struct qnode", "mcs"))
    return "mcs_nodes", getSizeOf("struct mcs_spinlock"), 0


def read_mcs_nodes():
    """({node: (cpu, idx, next)} for the nodes in use, [(start, end)] of
    every CPU's node array, {cpu: count} for CPUs nested past MAX_NODES),
    or None when the kernel has no MCS queue nodes."""
    if not struct_exists("struct mcs_spinlock"):
        return None
    name, stride, mcs_off = mcs_node_layout()
    # get_cpu_var() of a missing symbol reads each CPU's per-CPU base.
    if not symbol_exists(name):
        return None
    try:
        bases = percpu.get_cpu_var(name)
    except:
        return None

    nodes = {}
    ranges = []
    deep = {}
    for cpu, base in enumerate(bases):
        base = int(base)
        ranges.append((base, base + stride * lockdecode.MAX_NODES))
        # Only node 0's count is kept: it is the CPU's nesting depth.
        count = readSU("struct mcs_spinlock", base + mcs_off).count
        if count > lockdecode.MAX_NODES:
            deep[cpu] = count
        for idx in range(lockdecode.in_use_slots(count)):
            addr = base + idx * stride + mcs_off
            mcs = readSU("struct mcs_spinlock", addr)
            nodes[addr] = (cpu, idx, int(mcs.next))
    return nodes, ranges, deep


cpu_bts = {}

def cpu_bt(cpu):
    """{"words", "funcs", "pid", "task", "comm"} of the CPU's active task."""
    if cpu not in cpu_bts:
        try:
            text = exec_crash_command("bt -f -c %d" % cpu)
        except:
            text = ""
        bt = lockdecode.parse_bt(text)
        bt["words"] = lockdecode.candidate_words(text)
        cpu_bts[cpu] = bt
    return cpu_bts[cpu]


def cpu_stack_words(cpu):
    return cpu_bt(cpu)["words"]


preempt_counts = None

def get_preempt_counts():
    """({cpu: preempt_count}, whether the count is kept).  Without
    CONFIG_PREEMPT_COUNT (RHEL8: no preemption, no DEBUG_ATOMIC_SLEEP)
    spin_lock does not raise it, so a 0 proves nothing."""
    global preempt_counts

    if preempt_counts is None:
        preempt_counts = {}
        # RHEL9 and later keep it in pcpu_hot, RHEL8 in __preempt_count,
        # RHEL7 in thread_info (not read).
        if symbol_exists("pcpu_hot"):
            name = "pcpu_hot"
            offset = member_offset("struct pcpu_hot", "preempt_count")
        elif symbol_exists("__preempt_count"):
            name, offset = "__preempt_count", 0
        else:
            name, offset = None, -1
        if name is not None and offset >= 0:
            try:
                for cpu, addr in enumerate(percpu.get_cpu_var(name)):
                    preempt_counts[cpu] = readUInt(int(addr) + offset)
            except:
                preempt_counts.clear()
    kept = symbol_exists("preempt_schedule") or symbol_exists("__might_sleep")
    return preempt_counts, kept


def debug_owner(lock_addr):
    """The owner CONFIG_DEBUG_SPINLOCK records in struct raw_spinlock, as
    (cpu, task), (None, None) when unowned, or None when not recorded."""
    if member_offset("struct raw_spinlock", "owner_cpu") < 0:
        return None
    try:
        raw = readSU("struct raw_spinlock", lock_addr)
        if raw.magic != 0xdead4ead:     # SPINLOCK_MAGIC
            return None
        # owner_cpu is unsigned: -1 reads back as 0xffffffff.
        task = int(raw.owner) & 0xffffffffffffffff
        cpu = int(raw.owner_cpu) & 0xffffffff
        if task in (0, 0xffffffffffffffff) or cpu == 0xffffffff:
            return None, None
        return cpu, task
    except:
        return None


def show_holders(lock_addr, held, waiters, waits_for):
    """Print who may hold the lock; returns the best-scored CPUs."""
    if not held:
        return []
    owner = debug_owner(lock_addr)
    if owner is not None:
        cpu, task = owner
        if cpu is None:
            print("    owner: none recorded (CONFIG_DEBUG_SPINLOCK)")
            return []
        crashcolor.set_color(crashcolor.LIGHTRED)
        print("    owner: CPU %d task 0x%x (CONFIG_DEBUG_SPINLOCK)" % (cpu, task))
        crashcolor.set_color(crashcolor.RESET)
        return [cpu]

    counts, kept = get_preempt_counts()
    cpus = {cpu: cpu_bt(cpu) for cpu in range(sys_info.CPUS)}
    candidates, ruled_out = lockdecode.rank_holders(
        lock_addr, cpus, set(waiters), waits_for, counts, kept)
    if not candidates:
        crashcolor.set_color(crashcolor.LIGHTRED)
        print("    holder: no CPU outside the queue references the lock: an"
              " unlock missed, the holder")
        print("            slept with it held, or the lock word is corrupted")
        crashcolor.set_color(crashcolor.RESET)
    else:
        print("    possible holders (a spinlock does not record its holder):")
    best = candidates[0]["score"] if candidates else None
    for c in candidates:
        bt = cpus[c["cpu"]]
        crashcolor.set_color(crashcolor.LIGHTRED if c["score"] == best
                             else crashcolor.RESET)
        print("      CPU %-4d pid %-7s %-16s %s" %
              (c["cpu"], bt["pid"], bt["comm"], "; ".join(c["notes"])))
    crashcolor.set_color(crashcolor.RESET)
    if ruled_out:
        print("      ruled out, preempt depth 0: CPU %s" %
              ", ".join(str(c["cpu"]) for c in ruled_out))
    return [c["cpu"] for c in candidates if c["score"] == best and best > 0]


def queue_locks(queues, nodes, ranges):
    """[(chain, broken, matches)], {cpu: lock} for every queued CPU whose
    queue's lock was found and every pending spinner, and {lock: [cpu]}
    of the pending spinners."""
    result = []
    waits_for = {}
    for chain, broken in queues:
        matches = find_queue_lock(chain, nodes, ranges)
        result.append((chain, broken, matches))
        if matches:
            for addr in chain:
                waits_for[nodes[addr][0]] = matches[0][0]

    # The first CPU to find a lock held spins as the pending waiter without
    # a queue node, so two CPUs in an ABBA deadlock may have no queue at all.
    queued = set(cpu for cpu, _, _ in nodes.values())
    pending = {}
    for cpu in range(sys_info.CPUS):
        bt = cpu_bt(cpu)
        if cpu in queued or not any(lockdecode.SLOWPATH in f for f in bt["funcs"]):
            continue
        targets = lockdecode.pending_targets(bt["words"], read_u32,
                                             get_nr_cpus(), ranges)
        if len(targets) == 1:
            waits_for[cpu] = targets[0]
            pending.setdefault(targets[0], []).append(cpu)
    return result, waits_for, pending


def show_deadlocks(holders, waits_for):
    cycles = lockdecode.find_deadlocks(holders, waits_for)
    for cycle in cycles:
        crashcolor.set_color(crashcolor.LIGHTRED)
        print("Possible deadlock:")
        for lock, cpu in cycle:
            print("    lock 0x%x%s likely held by CPU %d, which waits for lock 0x%x" %
                  (lock, lock_name(lock), cpu, waits_for[cpu]))
        crashcolor.set_color(crashcolor.RESET)
        print()


def find_queue_lock(chain, nodes, ranges):
    cpus = sorted(set(nodes[addr][0] for addr in chain))
    candidates = {cpu: cpu_stack_words(cpu) for cpu in cpus}
    tail_cpu, tail_idx, _ = nodes[chain[-1]]
    return lockdecode.match_lock(candidates, read_u32, tail_cpu, tail_idx,
                                 get_nr_cpus(), ranges)


def print_queue(chain, broken, nodes):
    if broken:
        crashcolor.set_color(crashcolor.RED)
        print("    links are not a simple list (cycle or shared successor):"
              " the dump caught the queue changing, or a node is corrupted")
        crashcolor.set_color(crashcolor.RESET)
    for i, addr in enumerate(chain):
        cpu, idx, _ = nodes[addr]
        if len(chain) == 1:
            role = "head/tail"
        elif i == 0:
            role = "head"
        elif i == len(chain) - 1:
            role = "tail"
        else:
            role = ""
        if i == 0:
            crashcolor.set_color(crashcolor.LIGHTGREEN)
        print("    %-9s CPU %-4d slot %d  node 0x%x" % (role, cpu, idx, addr))
        crashcolor.set_color(crashcolor.RESET)


def print_queue_lock(matches, chain, nodes):
    nwaiters = len(set(nodes[addr][0] for addr in chain))
    if not matches:
        crashcolor.set_color(crashcolor.LIGHTRED)
        print("    lock: not found on the waiters' stacks")
        crashcolor.set_color(crashcolor.RESET)
        return
    for i, (addr, d, seen) in enumerate(matches):
        crashcolor.set_color(crashcolor.LIGHTYELLOW if i == 0 else crashcolor.RESET)
        print("    %s 0x%x%s: 0x%08x, %s [on %d of %d waiter stacks]" %
              ("lock:" if i == 0 else "  or:", addr, lock_name(addr),
               d["value"], lockdecode.describe_qspinlock(d), seen, nwaiters))
    crashcolor.set_color(crashcolor.RESET)


def queue_legend():
    print("The head spins on the lock word, the others on their own node;"
          " the holder is not")
    print("in the queue.  slot = nesting level (0 task, then usually"
          " softirq, hardirq, NMI).")
    print()


def show_pv_hashed_head(lock_addr, nodes):
    """With _Q_SLOW_VAL the halted queue head put (lock, node) in
    pv_lock_hash so the unlocker can kick it."""
    if not symbol_exists("pv_lock_hash") or not struct_exists("struct pv_hash_entry"):
        return
    try:
        table = int(readSymbol("pv_lock_hash"))
        bits = int(readSymbol("pv_lock_hash_bits"))
        size = getSizeOf("struct pv_hash_entry")
        lock_off = member_offset("struct pv_hash_entry", "lock")
        node_off = member_offset("struct pv_hash_entry", "node")
        for i in range(1 << bits):
            entry = table + i * size
            if readULong(entry + lock_off) != lock_addr:
                continue
            node = readULong(entry + node_off)
            if node in nodes:
                cpu = nodes[node][0]
            else:
                cpu = readSU("struct pv_node", node).cpu
            print("%12s : CPU %d (pv_lock_hash entry %d, node 0x%x)" %
                  ("halted head", cpu, i, node))
            return
        print("%12s : not in pv_lock_hash" % "halted head")
    except:
        pass


def show_qspinlock(lock_addr, options):
    val = read_u32(lock_addr)
    if val is None:
        print("cannot read 0x%x" % lock_addr)
        return
    d = lockdecode.decode_qspinlock(val, get_nr_cpus())

    print("spinlock status".center(26))
    print("=" * 26)
    print("%12s : 0x%08x%s" % ("value", val, lock_name(lock_addr)))
    print("%12s : %s" % ("state", lockdecode.describe_qspinlock(d)))
    print()
    print("%12s : %d" % ("locked", d["locked"]))
    print("%12s : %d" % ("pending", d["pending"]))
    print("%12s : %d" % ("tail index", d["tail_idx"]))
    print("%12s : %d" % ("tail cpu", -1 if d["tail_cpu"] is None else d["tail_cpu"]))

    result = read_mcs_nodes()
    nodes = result[0] if result else {}
    if d["locked"] == lockdecode.Q_SLOW_VAL:
        show_pv_hashed_head(lock_addr, nodes)
    chain = show_qspinlock_waiters(lock_addr, d, result)
    if not d["locked"]:
        return

    waits_for = {}
    if result:
        _, waits_for, _ = queue_locks(lockdecode.build_queues(nodes), nodes, result[1])
    print()
    print("Holder:")
    show_holders(lock_addr, True, [nodes[addr][0] for addr in chain], waits_for)


def show_qspinlock_waiters(lock_addr, d, result):
    """Print the queue the lock's tail names; returns it, head first."""
    if d["tail_cpu"] is None:
        return []
    print()
    if result is None:
        print("no MCS queue nodes (qnodes/mcs_nodes) in this kernel")
        return []
    nodes = result[0]

    tail = [addr for addr, (cpu, idx, _) in nodes.items()
            if (cpu, idx) == (d["tail_cpu"], d["tail_idx"])]
    if not tail:
        crashcolor.set_color(crashcolor.LIGHTRED)
        print("CPU %d slot %d is not queued: the dump caught the lock changing,"
              " or 0x%x is not a qspinlock" % (d["tail_cpu"], d["tail_idx"], lock_addr))
        crashcolor.set_color(crashcolor.RESET)
        return []

    for chain, broken in lockdecode.build_queues(nodes):
        if tail[0] not in chain:
            continue
        if chain[-1] != tail[0]:
            # A waiter queued behind the tail the lock word names.
            broken = True
        print("Waiters, %d queued:" % len(chain))
        queue_legend()
        print_queue(chain, broken, nodes)
        return chain
    return []


def show_ticket_spinlock(lock_addr, options):
    tickets = readSU("struct __raw_tickets", lock_addr)
    bits = member_size("struct __raw_tickets", "head") * 8
    # CONFIG_PARAVIRT_SPINLOCKS: tickets step by 2, bit 0 is the slowpath flag.
    inc = 2 if symbol_exists("pv_lock_ops") else 1
    d = lockdecode.decode_tickets(tickets.head, tickets.tail, bits, inc)

    print("spinlock status".center(26))
    print("=" * 26)
    print("%10s : 0x%x%s" % ("value", readUInt(lock_addr) if bits == 16 else
                             readU16(lock_addr), lock_name(lock_addr)))
    print()
    print("\thead (now_serving) : %d" % (d["head"]))
    print("\ttail (next_ticket) : %d" % (d["tail"]))
    if inc == 2:
        print("\tslowpath flag      : %d" % (d["slowpath"]))
    print()
    if not d["held"]:
        print("No one is holding the lock at the moment")
        return
    print("Held, %d CPU(s) waiting" % (d["waiters"]))
    halted = show_pv_ticket_waiters(lock_addr, d["head"], bits, inc)
    print()
    print("Holder:")
    show_holders(lock_addr, True, halted, {})


def show_pv_ticket_waiters(lock_addr, head, bits, inc):
    """Paravirt ticket waiters that gave up spinning and halted record
    {lock, want} per CPU: klock_waiting on KVM, lock_waiting on Xen.
    Returns those CPUs."""
    halted = []
    for var, stype in (("klock_waiting", "struct kvm_lock_waiting"),
                       ("lock_waiting", "struct xen_lock_waiting")):
        if not symbol_exists(var) or not struct_exists(stype):
            continue
        waiters = []
        for cpu, addr in enumerate(percpu.get_cpu_var(var)):
            w = readSU(stype, int(addr))
            if int(w.lock) == lock_addr:
                waiters.append((lockdecode.ticket_position(w.want, head, bits, inc),
                                cpu, w.want))
        print()
        if not waiters:
            print("No CPU halted waiting in %s (spinning waiters are not recorded)" % var)
            continue
        print("Halted waiters from %s (spinning waiters are not recorded):" % var)
        for pos, cpu, want in sorted(waiters):
            if pos < 0:
                turn = "its turn (kicked, not yet running)"
            elif pos == 0:
                turn = "next"
            else:
                turn = "%d ahead" % pos
            print("\tCPU %-4d ticket %-6d %s" % (cpu, want, turn))
            halted.append(cpu)
    return halted


def show_rt_spinlock(lock_addr):
    """PREEMPT_RT: spinlock_t is a sleeping rt_mutex that records its owner.
    Its first word is the rt_mutex's own wait_lock, a raw spinlock."""
    print("PREEMPT_RT: if 0x%x is a spinlock_t, it is an rt_mutex:" % lock_addr)
    try:
        rtm = readSU("struct rt_mutex_base",
                     lock_addr + member_offset("struct spinlock", "lock"))
        owner = int(rtm.owner) & ~0x1       # RT_MUTEX_HAS_WAITERS
        if owner == 0:
            print("%12s : none" % "owner")
        else:
            task = readSU("struct task_struct", owner)
            print("%12s : pid %d %s (task 0x%x)" % ("owner", task.pid, task.comm, owner))
        print("%12s : %s" % ("waiters", "yes" if int(rtm.owner) & 0x1 else "no"))
    except:
        print("%12s : cannot read struct rt_mutex_base" % "owner")
    print()
    print("If it is a raw_spinlock_t, or for the rt_mutex's wait_lock:")
    print()


def show_spinlock(options):
    try:
        lock_addr = int(options.spinlock, 16)
    except ValueError:
        print("invalid address '%s'" % options.spinlock)
        return

    if member_offset("struct spinlock", "rlock") < 0 and \
       member_offset("struct spinlock", "lock") >= 0:
        show_rt_spinlock(lock_addr)

    # RHEL7 ticket locks; RHEL7 also has struct mcs_spinlock (for mutexes),
    # so its presence does not mean qspinlock.
    if struct_exists("struct __raw_tickets"):
        show_ticket_spinlock(lock_addr, options)
    elif struct_exists("struct qspinlock"):
        show_qspinlock(lock_addr, options)
    else:
        # e.g. RHEL7 ppc64/s390x: an arch-specific lock word.
        val = read_u32(lock_addr)
        print("value 0x%x%s: not a ticket lock or qspinlock, not decoded" %
              (val if val is not None else 0, lock_name(lock_addr)))


def show_mcslock(options):
    result = read_mcs_nodes()
    if result is None:
        print("no MCS queue nodes (qnodes/mcs_nodes) in this kernel")
        return
    nodes, ranges, deep = result

    queues = lockdecode.build_queues(nodes)
    queues.sort(key=lambda q: -len(q[0]))
    if not queues:
        print("No CPU is queued on a spinlock")
        print()
    else:
        queue_legend()
    queues, waits_for, pending = queue_locks(queues, nodes, ranges)
    holders = {}
    for i, (chain, broken, matches) in enumerate(queues):
        print("MCS queue %d: %d waiter(s)" % (i + 1, len(chain)))
        print_queue(chain, broken, nodes)
        print_queue_lock(matches, chain, nodes)
        if matches:
            lock_addr, d, _ = matches[0]
            best = show_holders(lock_addr, d["locked"] != 0,
                                [nodes[addr][0] for addr in chain], waits_for)
            if best:
                holders[lock_addr] = best
        print()

    queue_lock_addrs = set(m[0][0] for _, _, m in queues if m)
    for lock_addr, cpus in sorted(pending.items()):
        if lock_addr in queue_lock_addrs:
            continue
        val = read_u32(lock_addr)
        d = lockdecode.decode_qspinlock(val, get_nr_cpus())
        print("Pending spinner, no queue: CPU %s" % ", ".join(map(str, cpus)))
        print("    lock: 0x%x%s: 0x%08x, %s" % (lock_addr, lock_name(lock_addr),
              val, lockdecode.describe_qspinlock(d)))
        best = show_holders(lock_addr, True, [], waits_for)
        if best:
            holders[lock_addr] = best
        print()
    show_deadlocks(holders, waits_for)

    for cpu, count in sorted(deep.items()):
        print("CPU %d: nested %d deep, past %d nodes: spinning on trylock"
              " without a queue node" % (cpu, count, lockdecode.MAX_NODES))

    if options.show_excluded:
        queued = set(cpu for cpu, _, _ in nodes.values())
        print("\tCPUs not queued:",
              sorted(set(range(sys_info.CPUS)) - queued - set(deep)))


def lockinfo():
    op = OptionParser()
    op.add_option("-s", "--spinlock", dest="spinlock", default="",
                  action="store", type="string",
                  help="Shows spinlock details, the CPUs queued on it and its likely holder")
    op.add_option("-m", "--mcslock", dest="mcslock", default=0,
                  action="store_true",
                  help="Shows every MCS queue, its lock, the likely holders and deadlocks")
    op.add_option("-x", "--excluded", dest="show_excluded", default=0,
                  action="store_true",
                  help="With -m, shows CPUs not in any MCS queue")

    (o, args) = op.parse_args()


    if o.spinlock != "":
        show_spinlock(o)
        sys.exit(0)

    if o.mcslock:
        show_mcslock(o)
        sys.exit(0)


if ( __name__ == '__main__'):
    lockinfo()
