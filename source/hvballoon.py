"""
 Written by Jay Shin, Skeleton is written by Daniel Sungju Kwon
"""

from pykdump.API import *
import enum

import sys
import crashcolor


def hvballoon_mem(options):
    try:
        pa = readSymbol('dm_device');
        if (pa == 0):
            return
    except:
        print ("Hyper-V balloon symbol does not exist")
        return

    if options.show_details:
        baddr = sym2addr('dm_device')
        balloon_result = exec_crash_command('struct hv_dynmem_device.state,num_pages_ballooned 0x%x' % (baddr))
        print ('%s' % (balloon_result))

    class hv_dm_state(enum.Enum):
	    DM_INITIALIZING = 0
	    DM_INITIALIZED = 1
	    DM_BALLOON_UP = 2
	    DM_BALLOON_DOWN = 3
	    DM_HOT_ADD = 4
	    DM_INIT_ERRO = 5

    crashcolor.set_color(crashcolor.LIGHTRED)
    num_pages_ballooned = pa.num_pages_ballooned
    state = hv_dm_state(pa.state)
    print ("== Hyper-V Ballooning Info ==")
    print ("driver address = %s" % (pa))
    print ("state = %s" % (state.name))
    print ("allocated size (pages)     = %d" % num_pages_ballooned)
    print ("allocated size (bytes)     = %d, (%.2fGB)" %
           (num_pages_ballooned * crash.PAGESIZE,
           ((num_pages_ballooned * crash.PAGESIZE)/1024/1024/1024)))
    num_pages = pa.balloon_wrk.num_pages
    print ("required target (pages)    = %d" % num_pages)
    print ("required target (bytes)    = %d, (%.2fGB)" %
           (num_pages * crash.PAGESIZE,
           ((num_pages * crash.PAGESIZE)/1024/1024/1024)))
    crashcolor.set_color(crashcolor.RESET)

    print ("\n")


def hvballooninfo():
    op = OptionParser()
    op.add_option("-d", "--details", dest="show_details", default=0,
                  action="store_true",
                  help="Show details")

    (o, args) = op.parse_args()

    hvballoon_mem(o)


if ( __name__ == '__main__'):
    hvballooninfo()
