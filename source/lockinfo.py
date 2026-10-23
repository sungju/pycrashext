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


stack_words = {}

def cpu_stack_words(cpu):
    if cpu not in stack_words:
        try:
            text = exec_crash_command("bt -f -c %d" % cpu)
        except:
            text = ""
        stack_words[cpu] = lockdecode.candidate_words(text)
    return stack_words[cpu]


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
    if d["tail_cpu"] is None:
        return
    print()
    if result is None:
        print("no MCS queue nodes (qnodes/mcs_nodes) in this kernel")
        return

    tail = [addr for addr, (cpu, idx, _) in nodes.items()
            if (cpu, idx) == (d["tail_cpu"], d["tail_idx"])]
    if not tail:
        crashcolor.set_color(crashcolor.LIGHTRED)
        print("CPU %d slot %d is not queued: the dump caught the lock changing,"
              " or 0x%x is not a qspinlock" % (d["tail_cpu"], d["tail_idx"], lock_addr))
        crashcolor.set_color(crashcolor.RESET)
        return

    for chain, broken in lockdecode.build_queues(nodes):
        if tail[0] not in chain:
            continue
        if chain[-1] != tail[0]:
            # A waiter queued behind the tail the lock word names.
            broken = True
        print("Waiters, %d queued:" % len(chain))
        queue_legend()
        print_queue(chain, broken, nodes)
        return


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
    show_pv_ticket_waiters(lock_addr, d["head"], bits, inc)


def show_pv_ticket_waiters(lock_addr, head, bits, inc):
    """Paravirt ticket waiters that gave up spinning and halted record
    {lock, want} per CPU: klock_waiting on KVM, lock_waiting on Xen."""
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


def show_spinlock(options):
    try:
        lock_addr = int(options.spinlock, 16)
    except ValueError:
        print("invalid address '%s'" % options.spinlock)
        return

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
    else:
        queue_legend()
    for i, (chain, broken) in enumerate(queues):
        print("MCS queue %d: %d waiter(s)" % (i + 1, len(chain)))
        print_queue(chain, broken, nodes)
        print_queue_lock(find_queue_lock(chain, nodes, ranges), chain, nodes)
        print()

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
                  help="Shows spinlock details and the CPUs queued on it")
    op.add_option("-m", "--mcslock", dest="mcslock", default=0,
                  action="store_true",
                  help="Shows every MCS queue and the lock it waits for")
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
