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

def lockup():
    rqlist = Tasks.getRunQueues()
    rqsorted = sorted(rqlist, key=getKey, reverse=True)
    now = -1
    for rq in rqsorted:
        if (now == -1):
            now = rq.Timestamp

        print ("CPU %3d: %10.2f sec behind by 0x%x, %s (%d in queue)" %
               (rq.cpu, (now - rq.Timestamp) / 1000000000,
                rq.curr, rq.curr.comm, rq.nr_running))


if ( __name__ == '__main__'):
    lockup()
