"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *

import sys
import crashcolor


def vmw_mem(options):
    print("VMware virtual machine")
    print("----------------------\n")

    try:
        pa = readSymbol('balloon');
        if (pa == 0):
            return
    except:
        print ("VMware balloon symbol does not exist")
        return

    if options.show_details:
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


def show_hv_details(options, hv_context, dm_device):
    addr = hv_context.cpu_context
    print("\nstruct hv_per_cpu_context")
    for i in range(sys_info.CPUS):
        hv_per_cpu_context = percpu.percpu_ptr(addr, i)
        print("CPU %d : 0x%x" % (i, hv_per_cpu_context))


def hv_mem(options, hv_context):
    dm_device = readSymbol("dm_device")
    if dm_device == 0:
        return

    print("Hyper-V virtual machine")
    print("-----------------------\n")
    print("%22s = %d" % ("num_pages_ballooned", dm_device.num_pages_ballooned))
    print("%22s = %d" % ("num_pages_onlined", dm_device.num_pages_onlined))
    print("%22s = %d" % ("num_pages_added", dm_device.num_pages_added))

    if options.show_details == True:
        show_hv_details(options, hv_context, dm_device)


def balloon_info(options):
    hv_context = readSymbol("hv_context")
    if hv_context != 0 and hv_context.synic_initialized == 1:
        hv_mem(options, hv_context)
    else:
        vmw_mem(options)


def vminfo():
    op = OptionParser()
    op.add_option("-d", "--details", dest="show_details", default=0,
                  action="store_true",
                  help="Show details")

    (o, args) = op.parse_args()


    balloon_info(o)


if ( __name__ == '__main__'):
    vminfo()
