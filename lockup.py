"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *

from LinuxDump import Tasks

import sys

def getKey(rqobj):
    return rqobj.Timestamp

def lockup_display(reverse_sort):
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


def lockup():
    op = OptionParser()
    op.add_option("-r", dest="reverse_sort", default=0,
                  action="store_true",
                  help="show longest holder at top")

    (o, args) = op.parse_args()

    lockup_display(not o.reverse_sort)

if ( __name__ == '__main__'):
    lockup()
