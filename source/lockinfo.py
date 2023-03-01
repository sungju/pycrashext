"""
 Written by Sungju Kwon <sungju.kwon@gmail.com>
"""
from pykdump.API import *

from LinuxDump import Tasks
from LinuxDump.trees import *
from LinuxDump import percpu

import crashcolor

import sys


NR_CPUS=0

def get_nr_cpus():
    global NR_CPUS

    NR_CPUS = sys_info.CPUS
    return sys_info.CPUS
"""
    lines = exec_crash_command("help -k").splitlines()
    for line in lines:
        words = line.split(':')
        if words[0] == 'kernel_NR_CPUS':
            NR_CPUS = int(words[1])
            return NR_CPUS
"""

def show_qspinlock(options):
    '''
include/asm-generic/qspinlock_types.h
/*
 * Bitfields in the atomic value:
 *
 * When NR_CPUS < 16K
 *  0- 7: locked byte
 *     8: pending
 *  9-15: not used
 * 16-17: tail index
 * 18-31: tail cpu (+1)
 *
 * When NR_CPUS >= 16K
 *  0- 7: locked byte
 *     8: pending
 *  9-10: tail index
 * 11-31: tail cpu (+1)
 */
    '''
    qspinlock = readSU("struct qspinlock", int(options.spinlock, 16))
    get_nr_cpus()

    lock_val = qspinlock.val.counter
    print("spinlock status".center(26))
    print("=" * 26)
    print("%12s : 0x%x" % ("value", lock_val))
    print()
    print("%12s : %d" % ("locked", (lock_val & 0xff)))
    print("%12s : %d" % ("pending", (1 if (lock_val & 0x100) == 0x100 else 0)))
    if NR_CPUS < 16000:
        print("%12s : %d" % ("tail index", ((lock_val >> 16) & 0x3)))
        print("%12s : %d" % ("tail cpu", (((lock_val >> 18) & 0x7ff) - 1)))
    else:
        print("%12s : %d" % ("tail index", ((lock_val >> 9) & 0x3)))
        print("%12s : %d" % ("tail cpu", (((lock_val >> 11) & 0x3fffff) - 1)))



def show_ticket_spinlock(options):
    spinlock = readSU("struct spinlock", int(options.spinlock, 16))
    tickets = spinlock.rlock.raw_lock.tickets
    print("spinlock status".center(26))
    print("=" * 26)
    print("%10s : 0x%x" % ("value", spinlock.rlock.raw_lock.head_tail))
    print()
    print("\thead (now_serving) : %d" % (tickets.head))
    print("\ttail (next_ticket) : %d" % (tickets.tail))
    print()
    my_turn = tickets.tail-tickets.head
    if my_turn == 0:
        print("No one is using the lock at the moment")
    else:
        print("%d pending tasks for this lock" % (my_turn))


def show_ticket_qspinlock(options):
    spinlock = readSU("struct spinlock", int(options.spinlock, 16))
    value = spinlock.rlock.raw_lock.val.counter
    print("spinlock status".center(26))
    print("=" * 26)
    print("%10s : 0x%x" % ("value", value))
    print()
    pass


def show_spinlock(options):
    if struct_exists("struct mcs_spinlock"):
        show_qspinlock(options)
        return

    if struct_exists("struct __raw_tickets"):
        show_ticket_spinlock(options)
        return

    show_ticket_qspinlock(options)


def get_my_mcs(mcs_list, mcs):
    for m_list in mcs_list:
        for node in m_list:
            if node == mcs or node.next == mcs or\
               node == mcs.next or node.next == mcs.next:
                return m_list

    new_list = {}
    mcs_list.append(new_list)
    return new_list


def get_my_prev(starter, mcs):
    for mcs_node in mcs:
        if mcs_node.next == starter:
            return mcs_node


qnodes_details = {}

def mcs_node_color(mcs_node):
    if mcs_node.locked == 0:
        crashcolor.set_color(crashcolor.LIGHTBLUE)
    elif mcs_node.count == 0:
        crashcolor.set_color(crashcolor.LIGHTGREEN)
    else:
        crashcolor.set_color(crashcolor.RED)


def print_mcs(mcs, options):
    global NR_CPUS

    global qnodes_details

    if len(mcs) <= 1:
        return
    cpu_set = set()
    if options.show_excluded:
        get_nr_cpus()
        cpu_set = set(map(lambda cpu:cpu, range(NR_CPUS)))

    for mcs_node in mcs:
        mcs_node_color(mcs_node)
        print("CPU %d (0x%x) -> " % (qnodes_details[mcs_node], Addr(mcs_node)), end="")
        if options.show_excluded:
            cpu_set.discard(qnodes_details[mcs_node])

    print("\b\b\b   \n")

    if options.show_excluded:
        print("\tExcluded CPUs:", cpu_set)
    crashcolor.set_color(crashcolor.RESET)


def add_qnode_list(qnode_list, mcs):
    qnode = mcs[0]
    for mcs_list in qnode_list:
        if qnode in mcs_list:
            return

    if qnode.count == 0:
        return
    my_list = [qnode]
    qnode = qnode.next
    while qnode != 0 and qnode.count > 0:
        my_list.append(qnode)
        for mcs_list in qnode_list:
            if qnode in mcs_list:
                qnode_list.remove(mcs_list)
        qnode = qnode.next

    qnode_list.append(my_list)


def add_mcs_node(mcs_list, mcs_node):
    for mcs in mcs_list:
        idx = 0
        for node in mcs:
            if mcs_node == node.next:
                mcs.insert(idx + 1, mcs_node)
                return
            elif mcs_node.next == node:
                mcs.insert(idx, mcs_node)
                return
            else:
                idx = idx + 1


    new_list = [mcs_node]
    mcs_list.append(new_list)


def show_mcslock(options):
    global qnodes_details

    qnodes_addr = None
    try:
        qnodes_addr = percpu.get_cpu_var("qnodes")
    except:
        print("no qnodes variable defined in this kernel")
        return

    mcs_list = []
    for cpu, addr in enumerate(qnodes_addr):
        #print("CPU %d : 0x%x" % (cpu, addr))
        qnode_array = []
        try:
            qnode_array = readSUArray("struct qnode", addr, 4)
        except:
            print("struct qnode not defined in this kernel")
            return

        count = qnode_array[0].mcs.count
        for qnode in qnode_array:
            mcs = qnode.mcs
            qnodes_details[mcs] = cpu
            if count > 0:
                add_mcs_node(mcs_list, mcs)
            #if mcs.next != 0 and count > 0:
            #    count = count - 1

    qnode_list = []
    for mcs in mcs_list:
        if len(mcs) <= 1:
            continue
        add_qnode_list(qnode_list, mcs)


    for qnode in qnode_list:
        print_mcs(qnode, options)


def lockinfo():
    op = OptionParser()
    op.add_option("-s", "--spinlock", dest="spinlock", default="",
                  action="store", type="string",
                  help="Shows spinlock details")
    op.add_option("-m", "--mcslock", dest="mcslock", default=0,
                  action="store_true",
                  help="Shows mcs_spinlock graph")
    op.add_option("-x", "--excluded", dest="show_excluded", default=0,
                  action="store_true",
                  help="Shows CPUs not in this mcs list")

    (o, args) = op.parse_args()


    if o.spinlock != "":
        show_spinlock(o)
        sys.exit(0)

    if o.mcslock:
        show_mcslock(o)
        sys.exit(0)


if ( __name__ == '__main__'):
    lockinfo()
