"""
'lockinfo' command: who holds and who waits for spinlocks, mutexes and
rw_semaphores.

Mutexes and rwsems record their owner (readers excepted); -b groups the
hung (UN) tasks by the lock they sleep on and follows owner -> lock ->
owner to the tasks at the end of each chain.

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

import re
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


# ---- sleeping locks: mutex and rw_semaphore ----

# Functions a task sleeps in while waiting for each kind of lock.
SLEEP_FUNCS = (("mutex", ("__mutex_lock",)),
               ("rwsem", ("rwsem_down_read", "rwsem_down_write")))


def read_ptr(addr):
    try:
        return readULong(addr)
    except:
        return None


def offset_or(struct, member, default):
    off = member_offset(struct, member)
    return off if off >= 0 else default


sleep_layouts = {}

def sleep_layout(kind):
    """{"task_off", "type_off", "wl_off", "slist"}: where the waiter struct
    keeps its task and type, where the lock keeps wait_list, and whether
    wait_list is the RHEL7 rwsem's one-pointer slist_head."""
    if kind not in sleep_layouts:
        if kind == "mutex":
            sleep_layouts[kind] = {
                "task_off": offset_or("struct mutex_waiter", "task", 16),
                "type_off": None,
                "wl_off": member_offset("struct mutex", "wait_list"),
                "slist": False,
            }
        else:
            sleep_layouts[kind] = {
                "task_off": offset_or("struct rwsem_waiter", "task", 16),
                "type_off": offset_or("struct rwsem_waiter", "type", 24),
                "wl_off": member_offset("struct rw_semaphore", "wait_list"),
                "slist": member_size("struct rw_semaphore", "wait_list") == 8,
            }
    return sleep_layouts[kind]


def sleep_kind(funcs):
    for kind, names in SLEEP_FUNCS:
        if any(name in f for f in funcs for name in names):
            return kind
    return None


task_infos = {}

def task_info(task):
    """{"pid", "comm", "state", "since"}; since is how long ago it last ran
    ('ps -m')."""
    if task not in task_infos:
        info = {"pid": "?", "comm": "?", "state": "??", "since": ""}
        try:
            line = exec_crash_command("ps -m 0x%x" % task)
            m = re.search(r'\[([\d :.]+)\]\s+\[(\w+)\]\s+PID:\s*(\d+).*COMMAND:\s*"([^"]*)"', line)
            if m:
                info = {"since": m.group(1).strip(), "state": m.group(2),
                        "pid": int(m.group(3)), "comm": m.group(4)}
        except:
            pass
        task_infos[task] = info
    return task_infos[task]


def task_desc(task):
    t = task_info(task)
    return "pid %-7s %-16s %s %s" % (t["pid"], t["comm"], t["state"], t["since"])


blocked_scan = None

def scan_blocked():
    """Every UN task sleeping on a mutex or rwsem: {task: (kind, lock or None)}
    and {task: words on its stack}."""
    global blocked_scan

    if blocked_scan is None:
        waiting = {}
        words = {}
        try:
            text = exec_crash_command("foreach UN bt -f")
        except:
            text = ""
        for block in lockdecode.split_tasks(text):
            bt = lockdecode.parse_bt(block)
            if bt["task"] is None:
                continue
            words[bt["task"]] = lockdecode.candidate_words(block)
            kind = sleep_kind(bt["funcs"])
            if kind is None:
                continue
            waiting[bt["task"]] = (kind, wait_lock_of(bt["task"], kind, block,
                                                      words[bt["task"]]))
        blocked_scan = (waiting, words)
    return blocked_scan


# Upper bound of THREAD_SIZE (16K on x86_64, 32K with KASAN, 64K arm64).
MAX_THREAD_SIZE = 0x10000


def task_stack(task):
    off = member_offset("struct task_struct", "stack")
    base = read_ptr(task + off) if off >= 0 else None
    return (base, base + MAX_THREAD_SIZE) if base else None


def wait_lock_of(task, kind, text, words):
    layout = sleep_layout(kind)
    if layout["wl_off"] < 0:
        return None

    def is_waiter(entry):
        # A waiter struct lives on its own task's stack.
        t = read_ptr(entry + layout["task_off"])
        stack = task_stack(t) if t else None
        return bool(stack) and stack[0] <= entry < stack[1]

    valid_lock = None
    if layout["slist"]:
        count_off = member_offset("struct rw_semaphore", "count")

        def valid_lock(lock):
            # RHEL7 bias layout: waiters make the high half negative.
            count = read_ptr(lock + count_off)
            return count is not None and (lockdecode.signed(count, 64) >> 32) < 0

    stack = task_stack(task)
    lock, _ = lockdecode.find_wait_lock(task, lockdecode.bt_slots(text), words,
                                        read_ptr, layout["task_off"],
                                        layout["wl_off"], layout["slist"],
                                        is_waiter, valid_lock,
                                        [stack] if stack else [])
    return lock


task_waits = {}

def task_waits_for(task):
    """(kind, lock) the task sleeps on, or None: from the blocked scan, else
    from the task's own backtrace (the scan covers UN tasks only, not those
    sleeping interruptibly)."""
    if blocked_scan is not None and task in blocked_scan[0]:
        return blocked_scan[0][task]
    if task not in task_waits:
        task_waits[task] = None
        try:
            text = exec_crash_command("bt -f 0x%x" % task)
            kind = sleep_kind(lockdecode.parse_bt(text)["funcs"])
            if kind is not None:
                task_waits[task] = (kind, wait_lock_of(
                    task, kind, text, lockdecode.candidate_words(text)))
        except:
            pass
    return task_waits[task]


def read_sleeping_lock(kind, addr):
    """Decoded state plus "waiters": [(task, 'read'/'write' or None)], or
    {"error": text}."""
    if kind == "mutex":
        if member_offset("struct mutex", "rtmutex") >= 0:
            owner = read_ptr(addr + member_offset("struct mutex", "rtmutex") +
                             member_offset("struct rt_mutex_base", "owner"))
            if owner is None:
                return {"error": "cannot read 0x%x" % addr}
            d = {"locked": (owner & ~1) != 0, "owner": (owner & ~1) or None,
                 "flags": ["WAITERS"] if owner & 1 else [], "waiters": [],
                 "note": "PREEMPT_RT: waiters are in the rt_mutex tree, not listed"}
            return d
        owner_off = member_offset("struct mutex", "owner")
        owner = read_ptr(addr + owner_off) if owner_off >= 0 else 0
        if owner is None:
            return {"error": "cannot read 0x%x" % addr}
        count_off = member_offset("struct mutex", "count")
        count = readUInt(addr + count_off) if count_off >= 0 else None
        d = lockdecode.decode_mutex(owner, count)
    else:
        if member_offset("struct rw_semaphore", "rwbase") >= 0:
            return {"error": "PREEMPT_RT rw_semaphore (rwbase_rt) is not decoded"}
        count = read_ptr(addr + member_offset("struct rw_semaphore", "count"))
        if count is None:
            return {"error": "cannot read 0x%x" % addr}
        owner_off = member_offset("struct rw_semaphore", "owner")
        owner = (read_ptr(addr + owner_off) or 0) if owner_off >= 0 else 0
        d = None

    layout = sleep_layout(kind)
    waiters = []
    for entry in lockdecode.walk_list(addr + layout["wl_off"], read_ptr, layout["slist"]):
        task = read_ptr(entry + layout["task_off"])
        wtype = None
        if layout["type_off"] is not None:
            try:
                wtype = "write" if readUInt(entry + layout["type_off"]) == \
                        lockdecode.RWSEM_WAITING_FOR_WRITE else "read"
            except:
                pass
        waiters.append((task, wtype))
    if kind == "rwsem":
        old = symbol_exists("rwsem_down_read_failed") and \
              not symbol_exists("rwsem_down_read_slowpath")
        d = lockdecode.decode_rwsem(count, owner, old, bool(waiters))
    d["waiters"] = waiters
    return d


def describe_sleeping_lock(kind, d):
    if kind == "mutex":
        state = "locked" if d["locked"] else "unlocked"
        if d["flags"]:
            state += ", flags " + "|".join(d["flags"])
        return state
    if d["writer"]:
        state = "write-locked"
    elif d["readers"]:
        state = "read-locked by %d reader(s)" % d["readers"]
    else:
        state = "unlocked"
    if d["waiters"]:
        state += ", waiters"
    return state


def show_sleeping_lock(kind, addr, readers_from_scan=False):
    """Print the lock, its owner and its waiters; returns its owner task
    (None when not recorded or reader-owned)."""
    d = read_sleeping_lock(kind, addr)
    print("%s 0x%x%s" % (kind, addr, lock_name(addr)))
    if "error" in d:
        print("    %s" % d["error"])
        return None
    print("    state : %s" % describe_sleeping_lock(kind, d))
    if d.get("note"):
        print("    note  : %s" % d["note"])

    waiter_tasks = set(t for t, _ in d["waiters"])
    owner = d.get("owner")
    if d.get("handoff_to"):
        print("    owner : none: handed off to %s, which has not run to take it" %
              task_desc(d["handoff_to"]).strip())
    elif owner:
        crashcolor.set_color(crashcolor.LIGHTRED)
        print("    owner : %s" % task_desc(owner))
        crashcolor.set_color(crashcolor.RESET)
        if owner in waiter_tasks:
            print("            waits for this lock itself: recursive locking, a self-deadlock")
        else:
            waits = task_waits_for(owner)
            if waits and waits[1]:
                print("            itself waiting for %s 0x%x%s" %
                      (waits[0], waits[1], lock_name(waits[1])))
            elif waits:
                print("            itself sleeping in a %s slowpath (lock not found)" % waits[0])
    elif d["locked"] and kind == "mutex":
        print("    owner : not recorded")
    elif kind == "rwsem" and d["readers"]:
        if d["last_reader"]:
            print("    owner : readers are not recorded; the last reader to take it"
                  " was %s (it may have released it)" % task_desc(d["last_reader"]).strip())
        else:
            print("    owner : readers are not recorded")
        if readers_from_scan:
            show_possible_readers(addr, waiter_tasks)

    if d["waiters"]:
        print("    waiters, in queue order (%d):" % len(d["waiters"]))
        for task, wtype in d["waiters"]:
            if task is None:
                print("      (unreadable waiter)")
                continue
            print("      %s%s" % (task_desc(task), "  [%s]" % wtype if wtype else ""))
    return owner


def show_possible_readers(addr, waiter_tasks):
    """Blocked tasks and running CPUs that have the rwsem on their stack
    without waiting on it: the readers that may hold it."""
    _, words = scan_blocked()
    found = [task for task, w in words.items()
             if task not in waiter_tasks and addr in w]
    for cpu in range(sys_info.CPUS):
        bt = cpu_bt(cpu)
        if bt["task"] and bt["task"] not in waiter_tasks and addr in bt["words"] \
           and bt["task"] not in found:
            found.append(bt["task"])
    if found:
        print("            possible readers (lock address on their stack, not waiting for it):")
        for task in found:
            print("              %s" % task_desc(task))


def show_mutex(options):
    show_one_sleeping_lock("mutex", options.mutex)


def show_rwsem(options):
    show_one_sleeping_lock("rwsem", options.rwsem)


def show_one_sleeping_lock(kind, text):
    try:
        addr = int(text, 16)
    except ValueError:
        print("invalid address '%s'" % text)
        return
    show_sleeping_lock(kind, addr, readers_from_scan=(kind == "rwsem"))


def show_blocked(options):
    waiting, _ = scan_blocked()
    if not waiting:
        print("No UN task is waiting for a mutex or rwsem")
        return

    locks = {}
    lost = []
    for task, (kind, lock) in waiting.items():
        if lock is None:
            lost.append((kind, task))
        else:
            locks.setdefault((kind, lock), []).append(task)

    owners = {}
    order = sorted(locks.items(), key=lambda kv: (-len(kv[1]), kv[0][1]))
    for (kind, lock), tasks in order:
        owner = show_sleeping_lock(kind, lock, readers_from_scan=(kind == "rwsem"))
        if owner:
            owners[lock] = owner
        print()

    waits_for = dict((task, lock) for task, (_, lock) in waiting.items() if lock)
    kinds = dict((lock, kind) for kind, lock in locks)
    # Owners sleeping interruptibly are not in the UN scan.
    for owner in owners.values():
        waits = task_waits_for(owner)
        if owner not in waits_for and waits and waits[1]:
            waits_for[owner] = waits[1]
            kinds.setdefault(waits[1], waits[0])
    show_sleeping_deadlocks(owners, waits_for)
    show_root_owners(owners, waits_for, locks, kinds)

    if lost:
        print("Sleeping in a slowpath, lock not found on the stack:")
        for kind, task in sorted(lost, key=lambda kt: str(task_info(kt[1])["pid"])):
            print("    %-5s %s" % (kind, task_desc(task)))


def show_sleeping_deadlocks(owners, waits_for):
    holders = dict((lock, [owner]) for lock, owner in owners.items())
    for cycle in lockdecode.find_deadlocks(holders, waits_for):
        crashcolor.set_color(crashcolor.LIGHTRED)
        print("Deadlock:")
        for lock, task in cycle:
            print("    lock 0x%x%s is owned by %s, which waits for lock 0x%x" %
                  (lock, lock_name(lock), task_desc(task).strip(), waits_for[task]))
        crashcolor.set_color(crashcolor.RESET)
        print()


def show_root_owners(owners, waits_for, locks, kinds):
    """Where the wait chains end: an owner not waiting for another lock, or
    a lock whose owner is not recorded (read-held rwsem, mutex handed off).
    That is what the blocked tasks wait on in the end, so where to look."""
    blocked = {}
    for lock, root in lockdecode.root_owners(owners, waits_for).items():
        if root is None:
            continue
        tasks = [t for (_, l), ts in locks.items() if l == lock for t in ts]
        blocked.setdefault(root, set()).update(tasks)
    # Locks no owner leads to and with no recorded owner end chains too.
    for (kind, lock), tasks in locks.items():
        if lock not in owners:
            blocked.setdefault(("lock", lock), set()).update(tasks)
    if not blocked:
        return
    print("Where the wait chains end (start here):")
    for root, tasks in sorted(blocked.items(), key=lambda kv: -len(kv[1])):
        what, value = root
        if what == "task":
            print("    %s  blocks %d task(s)" % (task_desc(value), len(tasks)))
            continue
        kind = kinds.get(value, "lock")
        d = read_sleeping_lock(kind, value) if kind in ("mutex", "rwsem") else {}
        if d.get("handoff_to"):
            why = "handed off to %s, not yet taken" % task_desc(d["handoff_to"]).strip()
        elif kind == "rwsem" and d.get("readers"):
            why = "read-held by %d reader(s), which are not recorded" % d["readers"]
            if d.get("last_reader"):
                why += "; last reader %s" % task_desc(d["last_reader"]).strip()
        else:
            why = "owner not recorded"
        print("    %s 0x%x%s  blocks %d task(s): %s" %
              (kind, value, lock_name(value), len(tasks), why))
    print()


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
    op.add_option("-M", "--mutex", dest="mutex", default="",
                  action="store", type="string",
                  help="Shows a mutex's owner and waiters")
    op.add_option("-R", "--rwsem", dest="rwsem", default="",
                  action="store", type="string",
                  help="Shows an rw_semaphore's owner or readers and waiters")
    op.add_option("-b", "--blocked", dest="blocked", default=0,
                  action="store_true",
                  help="Groups UN tasks by the mutex or rwsem they wait for,"
                       " with owners, chains and deadlocks")

    (o, args) = op.parse_args()

    if o.mutex != "":
        show_mutex(o)
        sys.exit(0)

    if o.rwsem != "":
        show_rwsem(o)
        sys.exit(0)

    if o.blocked:
        show_blocked(o)
        sys.exit(0)


    if o.spinlock != "":
        show_spinlock(o)
        sys.exit(0)

    if o.mcslock:
        show_mcslock(o)
        sys.exit(0)


if ( __name__ == '__main__'):
    lockinfo()
