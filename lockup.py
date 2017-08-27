"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *

from LinuxDump import Tasks
from LinuxDump.trees import *

import sys

def getKey(rqobj):
    return rqobj.Timestamp

def getDelayKey(taskobj):
    return taskobj.sched_info.run_delay

def print_task_delay(task):
    sched_info = task.sched_info
    print ("%20s (0x%x) : %10.2f seconds delayed in queue" %
            (task.comm, task, sched_info.run_delay / 1000000000))

def show_rq_task_list(runqueue, reverse_sort):
    """
    rq->rq->active->queue[..]

    crash> rq.rt ffff880028376ec0 -ox
    struct rq {
      [ffff880028377048] struct rt_rq rt;
      }
      crash> rt_rq.active ffff880028377048 -ox
      struct rt_rq {
            [ffff880028377048] struct rt_prio_array active;
      }
      crash> rt_prio_array.bitmap ffff880028377048 -ox
      struct rt_prio_array {
            [ffff880028377048] unsigned long bitmap[2];
      }
      crash> rd ffff880028377048 2
      ffff880028377048:  0000000000000001 0000001000000000   ................

      crash> list_head ffff880028377058
      struct list_head {
            next = 0xffff88145f3c16e8,
            prev = 0xffff88145f3d4c78
      }
    """
    head_displayed = False
    rt_array = runqueue.rt.active
    for task_list in rt_array.queue:
        for sched_rt_entity in readSUListFromHead(task_list,
                                       "run_list",
                                       "struct sched_rt_entity"):
            task_offset = member_offset("struct task_struct", "rt")
            task_addr = sched_rt_entity - task_offset
            task = readSU("struct task_struct", task_addr)
            if (not head_displayed):
                print("  RT tasks:")
                head_displayed = True

            print_task_delay(task)



def show_cfs_task_list(runqueue, reverse_sort):
    """
    """
    task_offset = member_offset("struct task_struct", "se")
    task_list = []
#    for sched_entity in readSUListFromHead(runqueue.cfs.tasks,
#                                         "group_node",
#                                         "struct sched_entity"):
    for sched_entity in for_all_rbtree(runqueue.cfs.tasks_timeline,
                                       "struct sched_entity",
                                       "run_node"):
        if (sched_entity == runqueue.cfs.curr):
            continue
        task_addr = sched_entity - task_offset
        task = readSU('struct task_struct', task_addr)
        task_list.append(task)

    sorted_task_list = sorted(task_list,
                              key=getDelayKey,
                              reverse=not reverse_sort)
    if (len(sorted_task_list)):
        print("  CFS tasks:")

    for task in sorted_task_list:
        print_task_delay(task)

def show_prio_array(title, prio_array, reverse_sort):
    print ("%s" % (title))
    has_any_entry = 0
    for idx in range(0,140):
        task_list = []
        for task in readSUListFromHead(prio_array.queue[idx],
                                       "run_list",
                                       "struct task_struct"):
            task_list.insert(0, task)
        if (len(task_list) == 0):
            continue

        has_any_entry = 1
        sorted_task_list = sorted(task_list,
                                  key=getDelayKey,
                                  reverse=not reverse_sort)

        print ("\t[%4d]" % (idx))
        for task in sorted_task_list:
            print_task_delay(task)

    if (has_any_entry == 0):
        print("\tNo entry under this array")

    return


def show_prio_task_list(runqueue, reverse_sort):
    show_prio_array("Active prio_array", runqueue.active, reverse_sort)
    show_prio_array("Expired prio_array", runqueue.expired, reverse_sort)


def show_task_list(runqueue, reverse_sort):
    if (member_offset('struct rq', 'rt') >= 0):
        show_rq_task_list(runqueue, reverse_sort)
    if (member_offset('struct rq', 'cfs') >= 0):
        show_cfs_task_list(runqueue, reverse_sort)
    if (member_offset('struct rq', 'active') >= 0):
        show_prio_task_list(runqueue, reverse_sort)
    print("")


def lockup_display(reverse_sort, show_tasks):
    rqlist = Tasks.getRunQueues()
    rqsorted = sorted(rqlist, key=getKey, reverse=reverse_sort)
    if (reverse_sort):
        now = rqsorted[0].Timestamp
    else:
        now = rqsorted[-1].Timestamp

    for rq in rqsorted:
        print ("CPU %3d: %10.2f sec behind by 0x%x, %s (%d in queue)" %
               (rq.cpu, (now - rq.Timestamp) / 1000000000,
                rq.curr, rq.curr.comm, rq.nr_running))
        if (show_tasks):
            show_task_list(rq, reverse_sort)


def lockup():
    op = OptionParser()
    op.add_option("-r", dest="reverse_sort", default=0,
                  action="store_true",
                  help="show longest holder at top")
    op.add_option("--tasks", dest="show_tasks", default=0,
                  action="store_true",
                  help="show tasks in each runqueue")

    (o, args) = op.parse_args()

    lockup_display(not o.reverse_sort, o.show_tasks)

if ( __name__ == '__main__'):
    lockup()
