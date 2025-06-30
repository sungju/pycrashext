"""
 Written by Daniel Sungju Kwon
"""

from pykdump.API import *

from LinuxDump import Tasks
from LinuxDump import percpu

import sys

def show_softirq_list(options):
    softirq_vec = readSymbol("softirq_vec")
    count = 0
    for softirq in softirq_vec:
        print ("softirq[%d] : 0x%x (%s)" %
               (count, softirq.action,
                addr2sym(softirq.action)))
        count = count + 1

    return


def show_tasklet_list(options):
    addrs = percpu.get_cpu_var("tasklet_vec")
    show_tasklet_list_details(addrs, options)

def show_tasklet_hi_list(options):
    addrs = percpu.get_cpu_var("tasklet_hi_vec")
    show_tasklet_list_details(addrs, options)

def show_tasklet_list_details(tasklet_vec_addr, options):
    for cpu, addr in enumerate(tasklet_vec_addr):
        tasklet_head = readSU("struct tasklet_head", addr)
        print ("CPU %3d, tasklet_head = 0x%x" % (cpu, addr))
        tasklet_addr = tasklet_head.head
        while (tasklet_addr):
            tasklet = readSU("struct tasklet_struct", tasklet_addr)
            state = tasklet.state
            count = tasklet.count
            func = tasklet.func
            data = tasklet.data
            print ("%s(data : 0x%x) at 0x%x. state=%d count=%d" %
                   (addr2sym(func), data, func, state, count))
            tasklet_addr = tasklet.next

    return

def bh():
    op = OptionParser()
    op.add_option("-s", "--softirq", dest="softirq", default=0,
                  action="store_true",
                  help="Show softirq list")
    op.add_option("-t", "--tasklet", dest="tasklet", default=0,
                  action="store_true",
                  help="Show tasklet list")
    op.add_option("-i", "--hitasklet", dest="hitasklet", default=0,
                  action="store_true",
                  help="Show tasklet_hi list")

    (o, args) = op.parse_args()

    if (o.tasklet):
        show_tasklet_list(o)

    if (o.hitasklet):
        show_tasklet_hi_list(o)

    show_softirq_list(o)


if ( __name__ == '__main__'):
    bh()
