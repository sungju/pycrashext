"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *

import sys

import crashcolor

def vmw_mem():
    try:
        pa = readSymbol('balloon');
        if (pa == 0):
            return
    except:
        print ("VMware balloon symbol does not exist")
        return

    baddr = sym2addr('balloon')
    balloon_result = exec_crash_command('struct vmballoon.size,target,stats 0x%x' % (baddr))
    print ('%s' % (balloon_result))

    crashcolor.set_color(crashcolor.LIGHTRED)
    print ("allocated size (pages)     = %d" % pa.size)
    print ("allocated size (bytes)     = %d, (%.2fGB)" %
           (pa.size * crash.PAGESIZE,
           ((pa.size * crash.PAGESIZE)/1024/1024/1024)))
    print ("required target (pages)    = %d" % pa.target)
    print ("required target (bytes)    = %d, (%.2fGB)" %
           (pa.target * crash.PAGESIZE,
           ((pa.target * crash.PAGESIZE)/1024/1024/1024)))
    crashcolor.set_color(crashcolor.RESET)

    print ("")

    if (member_offset(pa, "n_refused_pages") > -1):
        print ("refuesed pages             = %d" %
               pa.n_refused_pages)
    print ("rate_alloc                 = %d" % pa.rate_alloc)

    if (member_offset(pa, "rate_free") > -1):
        print ("rate_free                  = %d" % pa.rate_free)

    print ("\n")
    """
    print ("** vmballoon_stats **")
    print ("timer = %d" % pa.stats.timer)
    if (member_offset(pa.stats, "alloc") > -1):
        print ("alloc = %d" % pa.stats.alloc)
    if (member_offset(pa.stats, "free") > -1):
        print ("free = %d" % pa.stats.free)
    if (member_offset(pa.stats, "alloc_fail") > -1):
        print ("alloc_fail = %d" % pa.stats.alloc_fail)

    print ("sleep_alloc = %d" % pa.stats.sleep_alloc)
    print ("sleepalloc_fail = %d" % pa.stats.sleep_alloc_fail)

    print ("refused_alloc = %d" % pa.stats.refused_alloc)
    print ("refused_free = %d" % pa.stats.refused_free)

    print ("target = %d" % pa.stats.target)
    print ("target_fail = %d" % pa.stats.target_fail)
    """


if ( __name__ == '__main__'):
    vmw_mem()
