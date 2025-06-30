"""
 Written by Daniel Sungju Kwon
"""

from pykdump.API import *

from LinuxDump import Tasks

import sys
import crashcolor

def show_sched_details(sched_class):
    result = exec_crash_command("sched_class %s" %
                                (addr2sym(sched_class)))
    print ("\t%s" % ('\t'.join(result.splitlines(True))))


def show_class_list(show_details):
    """
    crash> sym stop_sched_class
    ffffffff8160cd20 (r) stop_sched_class
    crash> list ffffffff8160cd20 -o sched_class.next \
            -s sched_class.enqueue_task,dequeue_task
    """
    sched_class_highest = readSymbol("stop_sched_class")
    for sched_class in readSUListFromHead(sched_class_highest,
                                    'next',
                                    'struct sched_class'):
        print ("%-18s (0x%x)" % (addr2sym(sched_class), sched_class))
        if (show_details):
            show_sched_details(sched_class)


def show_sched_features(options):
    sched_feat_keys = readSymbol("sched_feat_keys")
    sched_feat_names = readSymbol("sched_feat_names")
    enable_str = crashcolor.get_color(crashcolor.BLUE) + "enabled"
    disable_str = crashcolor.get_color(crashcolor.RED) + "disabled"
    for i in range(0, len(sched_feat_keys)):
        print("%-20s : %s" % (sched_feat_names[i],
                           enable_str if sched_feat_keys[i].enabled.counter > 0 else
                              disable_str))
        crashcolor.set_color(crashcolor.RESET)

def show_rt_details(options):
    reset_color = crashcolor.get_color(crashcolor.RESET)
    red_color = crashcolor.get_color(crashcolor.RED)
    blue_color = crashcolor.get_color(crashcolor.BLUE)
    if symbol_exists("sysctl_sched_rt_period"):
        sysctl_sched_rt_period = readSymbol("sysctl_sched_rt_period")
        print("kernel.sched_rt_period_us = %d" % (sysctl_sched_rt_period))
    else:
        sysctl_sched_rt_period = 0

    if symbol_exists("sysctl_sched_rt_runtime"):
        sysctl_sched_rt_runtime = readSymbol("sysctl_sched_rt_runtime")
        if sysctl_sched_rt_runtime == -1:
            print(red_color, end="")
        print("kernel.sched_rt_runtime_us = %d%s" %
              (sysctl_sched_rt_runtime, reset_color))
        if sysctl_sched_rt_period > 0 and sysctl_sched_rt_runtime > 0:
            usage_percent = (sysctl_sched_rt_runtime / sysctl_sched_rt_period) * 100
            if usage_percent >= 98:
                print(red_color, end="")
            print("\tRT CPU usage allowance = %d%%%s" %
                  (usage_percent, reset_color))

        if sysctl_sched_rt_runtime == -1:
            print(blue_color + "\t-1 for sched_rt_runtime_us may cause "
                  "real-time tasks use up\n\t100% of CPU times which causes"
                  " CPU starvation for normal tasks" + reset_color)


def show_worker_pool(options):
    bold_str = crashcolor.get_color(crashcolor.BOLD)
    blue_str = crashcolor.get_color(crashcolor.BLUE)
    red_str = crashcolor.get_color(crashcolor.RED)
    reset_str = crashcolor.get_color(crashcolor.RESET)

    worker_pool = readSU("struct worker_pool", int(options.worker_pool, 16))
    print(worker_pool)
    print("%sCPU : %d%s" % (bold_str, worker_pool.cpu, reset_str))
    print("%sWork list%s" % (blue_str, reset_str))
    for worker in readSUListFromHead(worker_pool.worklist,
                                    'entry',
                                    'struct worker'):
        print("\t%s" % (worker))
        if worker.current_work != 0:
            print("\tcurrent_work = %s%s%s" %
                  (red_str, addr2sym(worker.current_work), reset_str))

    print("%sIdle list%s" % (blue_str, reset_str))
    for worker in readSUListFromHead(worker_pool.idle_list,
                                    'entry',
                                    'struct worker'):
        print("\t%s" % (worker))
        if worker.current_work != 0:
            print("\tcurrent_work = %s%s%s" %
                  (red_str, addr2sym(worker.current_work), reset_str))
        try:
            if worker.task != 0:
                print("\ttask = %s%d 0x%x %s%s" %
                      (red_str, worker.task.pid, worker.task, worker.task.comm, reset_str))
        except:
            pass

def schedinfo():
    op = OptionParser()
    op.add_option("-c", "--classes", dest="sched_classes", default=0,
                  action="store_true",
                  help="Show scheduling classes")
    op.add_option("-d", "--details", dest="show_details", default=0,
                  action="store_true",
                  help="Show details")
    op.add_option("-f", "--sched_features", dest="sched_features", default=0,
                  action="store_true",
                  help="Show /sys/kernel/debug/sched_features")
    op.add_option("-r", "--rt", dest="rt_details", default=0,
                  action="store_true",
                  help="Show some RT related values")
    op.add_option("-w", "--worker_pool", dest="worker_pool", default="",
                  action="store",
                  help="Show worker pool information")

    (o, args) = op.parse_args()

    if (o.sched_classes):
        show_class_list(o.show_details)

    if (o.sched_features):
        show_sched_features(o)

    if (o.rt_details):
        show_rt_details(o)

    if (o.worker_pool):
        show_worker_pool(o)


if ( __name__ == '__main__'):
    schedinfo()
