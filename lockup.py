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


def get_task_policy_str(policy):
    return {
        0: "N", # SCHED_NORMAL
        1: "F", # SCHED_FIFO
        2: "R", # SCHED_RR
        3: "B", # SCHED_BATCH
        5: "I", # SCHED_IDLE
        6: "D", # SCHED_DEADLINE
    }[policy]


def print_task_delay(task, options):
    try:
        sched_info = task.sched_info
        prio = task.prio
        if (task.policy != 0):
            prio = task.rt_priority

        print ("%20s (0x%x)[%s:%3d] : %10.2f sec delayed in queue" %
               (task.comm, task, get_task_policy_str(task.policy),
                prio, sched_info.run_delay / 1000000000))
        if (options.task_details):
            print ("\t\t\texec_start = %d, exec_max = %d" %
                   (task.se.exec_start, task.se.exec_max))
    except:
        pass


def show_rt_stat_in_rq(rq):
    rt = rq.rt
    rt_period = rt.tg.rt_bandwidth.rt_period.tv64
    print ("CPU %3d: rt_nr_running = %d, rt_throttled = %d\n"
           "\trt_time = %12d, rt_runtime = %10d, rt_period = %d" %
           (rq.cpu, rt.rt_nr_running, rt.rt_throttled, rt.rt_time,
            rt.rt_runtime, rt_period))


def show_rt_stat(options):
    rqlist = Tasks.getRunQueues()
    for rq in rqlist:
        show_rt_stat_in_rq(rq)


def show_rq_task_list(runqueue, reverse_sort, options):
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

            print_task_delay(task, options)


def read_task_from_sched_entity(sched_entity, runqueue):
    if (sched_entity == runqueue.cfs.curr):
        return None
    task_offset = member_offset("struct task_struct", "se")
    task_addr = sched_entity - task_offset
    task = readSU('struct task_struct', task_addr)
    return task


def show_cfs_task_list(runqueue, reverse_sort, options):
    """
    """
    task_list = []
    task_root = None

    if (member_offset('struct rq', 'cfs_tasks') >= 0):
        for sched_entity in readSUListFromHead(runqueue.cfs_tasks,
                                               "group_node",
                                               "struct sched_entity"):
            task = read_task_from_sched_entity(sched_entity,
                                               runqueue)
            if (task != None):
                task_list.append(task)
    elif (member_offset("struct cfs_rq", "tasks_timeline") >= 0):
        for sched_entity in for_all_rbtree(runqueue.cfs.tasks_timeline,
                                           "struct sched_entity",
                                           "run_node"):
            task = read_task_from_sched_entity(sched_entity,
                                               runqueue)
            if (task != None):
                task_list.append(task)
    elif (member_offset("struct cfs_rq", "tasks") >= 0):
        for sched_entity in readSUListFromHead(runqueue.cfs.tasks,
                                             "group_node",
                                             "struct sched_entity"):
            task = read_task_from_sched_entity(sched_entity,
                                               runqueue)
            if (task != None):
                task_list.append(task)
    else:
        task_list = []


    sorted_task_list = sorted(task_list,
                              key=getDelayKey,
                              reverse=not reverse_sort)
    if (len(sorted_task_list)):
        print("  CFS tasks:")

    for task in sorted_task_list:
        print_task_delay(task, options)

def show_prio_array(title, prio_array, reverse_sort, options):
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
            print_task_delay(task, options)

    if (has_any_entry == 0):
        print("\tNo entry under this array")

    return


def show_prio_task_list(runqueue, reverse_sort, options):
    show_prio_array("Active prio_array", runqueue.active,
                    reverse_sort, options)
    show_prio_array("Expired prio_array", runqueue.expired,
                    reverse_sort, options)


def show_task_list(runqueue, reverse_sort, options):
    if (member_offset('struct rq', 'rt') >= 0):
        show_rq_task_list(runqueue, reverse_sort, options)
    if (member_offset('struct rq', 'cfs') >= 0):
        show_cfs_task_list(runqueue, reverse_sort, options)
    if (member_offset('struct rq', 'active') >= 0):
        show_prio_task_list(runqueue, reverse_sort, options)
    print("")


def lockup_display(reverse_sort, show_tasks, options):
    rqlist = Tasks.getRunQueues()
    rqsorted = sorted(rqlist, key=getKey, reverse=reverse_sort)
    if (reverse_sort):
        now = rqsorted[0].Timestamp
    else:
        now = rqsorted[-1].Timestamp

    for rq in rqsorted:
        prio = rq.curr.prio
        if (rq.curr.policy != 0):
            prio = rq.curr.rt_priority

        print ("CPU %3d: %10.2f sec behind by "
               "0x%x, %s [%s:%3d] (%d in queue)" %
               (rq.cpu, (now - rq.Timestamp) / 1000000000,
                rq.curr, rq.curr.comm,
                get_task_policy_str(rq.curr.policy), prio, rq.nr_running))
        if (show_tasks):
            show_task_list(rq, reverse_sort, options)


def lockup():
    op = OptionParser()
    op.add_option("-r", dest="reverse_sort", default=0,
                  action="store_true",
                  help="show longest holder at top")
    op.add_option("--tasks", dest="show_tasks", default=0,
                  action="store_true",
                  help="show tasks in each runqueue")
    op.add_option("--rt", dest="rt_stat", default=0,
                  action="store_true",
                  help="show RT statistics")
    op.add_option("--details", dest="task_details", default=0,
                  action="store_true",
                  help="show task details")

    (o, args) = op.parse_args()

    if (o.rt_stat):
        show_rt_stat(o)
        return


    lockup_display(not o.reverse_sort, o.show_tasks, o)

if ( __name__ == '__main__'):
    lockup()
