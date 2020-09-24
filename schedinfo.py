"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

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

    (o, args) = op.parse_args()

    if (o.sched_classes):
        show_class_list(o.show_details)

    if (o.sched_features):
        show_sched_features(o)


if ( __name__ == '__main__'):
    schedinfo()
