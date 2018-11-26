"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *

from LinuxDump import Tasks

import sys

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


def schedinfo():
    op = OptionParser()
    op.add_option("--classes", dest="sched_classes", default=0,
                  action="store_true",
                  help="Show scheduling classes")
    op.add_option("--details", dest="show_details", default=0,
                  action="store_true",
                  help="Show details")

    (o, args) = op.parse_args()

    if (o.sched_classes):
        show_class_list(o.show_details)

if ( __name__ == '__main__'):
    schedinfo()
