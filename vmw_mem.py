from __future__ import print_function

from pykdump.API import *

import sys

def vmw_mem():
    pa = readSymbol('balloon');
    if (pa == 0):
        return

    print ("allocated size (pages)     = %d" % pa.size)
    print ("allocated size (bytes)     = %d" %
           (pa.size / crash.PAGESIZE))
    print ("required target (pages)    = %d" % pa.target)
    print ("required target (bytes)    = %d" %
           (pa.target / crash.PAGESIZE))
    print ("")
    print ("refuesed pages             = %d" %
           pa.n_refused_pages)
    print ("rate_alloc                 = %d" % pa.rate_alloc)
    print ("rate_free                  = %d" % pa.rate_free)

    print ("\n")
    print ("** vmballoon_stats **")
    print ("timer = %d" % pa.stats.timer)
    print ("alloc = %d" % pa.stats.alloc)
    print ("free = %d" % pa.stats.free)
    print ("alloc_fail = %d" % pa.stats.alloc_fail)

    print ("sleep_alloc = %d" % pa.stats.sleep_alloc)
    print ("sleepalloc_fail = %d" % pa.stats.sleep_alloc_fail)

    print ("refused_alloc = %d" % pa.stats.refused_alloc)
    print ("refused_free = %d" % pa.stats.refused_free)

    print ("target = %d" % pa.stats.target)
    print ("target_fail = %d" % pa.stats.target_fail)

if ( __name__ == '__main__'):
    vmw_mem()
