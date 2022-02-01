"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *

import sys
import crashcolor


def vmw_mem(options, balloon):
    print("VMware virtual machine")
    print("----------------------\n")
    if options.show_details:
        baddr = sym2addr('balloon')
        balloon_result = exec_crash_command('struct vmballoon.size,target,stats 0x%x' % (baddr))
        print ('%s' % (balloon_result))

    crashcolor.set_color(crashcolor.LIGHTRED)
    print ("allocated size (pages)     = %d" % balloon.size)
    print ("allocated size (bytes)     = %d, (%.2fGB)" %
           (balloon.size * crash.PAGESIZE,
           ((balloon.size * crash.PAGESIZE)/1024/1024/1024)))
    print ("required target (pages)    = %d" % balloon.target)
    print ("required target (bytes)    = %d, (%.2fGB)" %
           (balloon.target * crash.PAGESIZE,
           ((balloon.target * crash.PAGESIZE)/1024/1024/1024)))
    crashcolor.set_color(crashcolor.RESET)

    print ("")

    if (member_offset(balloon, "n_refused_pages") > -1):
        print ("refuesed pages             = %d" %
               balloon.n_refused_pages)
    print ("rate_alloc                 = %d" % balloon.rate_alloc)

    if (member_offset(balloon, "rate_free") > -1):
        print ("rate_free                  = %d" % balloon.rate_free)

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
    hv_context = 0
    try:
        hv_context = readSymbol("hv_context")
    except:
        pass

    if hv_context != 0 and hv_context.synic_initialized == 1:
        hv_mem(options, hv_context)
        return

    balloon = 0
    try:
        balloon = readSymbol('balloon');
    except:
        pass

    if balloon != 0:
        vmw_mem(options, balloon)
        return

    print("Not VM environment or not recognizable VM")


def show_vmci_handle_arr(vmci_handle_arr, name):
    print("\t%s" % name)
    print("\t\tcapacity: %d" % (vmci_handle_arr.capacity))
    print("\t\tmax_capacity: %d" % (vmci_handle_arr.max_capacity))
    print("\t\tsize: %d" % (vmci_handle_arr.size))
    print("\t\tentries: %d" % (vmci_handle_arr.entries))
    try:
        for i in range(0, vmci_handle_arr.capacity):
            vmci_handle = vmci_handle_arr.entries[i]
            print("\t\t\tentries[%d] : context = %d, resource = %d" %
                  (i, vmci_handle.context, vmci_handle.resource))
    except:
        pass


def show_vmci_context(options, ctx_list):
    for vmci_ctx in readSUListFromHead(ctx_list.head,
                                       "list_item",
                                       "struct vmci_ctx"):
        print(vmci_ctx)
        show_vmci_handle_arr(vmci_ctx.queue_pair_array, "queue_pair_array")
        show_vmci_handle_arr(vmci_ctx.doorbell_array, "doorbell_array")
        show_vmci_handle_arr(vmci_ctx.pending_doorbell_array, "pending_doorbell_array")


def show_vmci_qp_guest_endpoints(options, qp_guest_endpoints):
    for qp_entry in readSUListFromHead(qp_guest_endpoints.head,
                                       "list_item",
                                       "struct qp_entry"):
        print(qp_entry)
        ep = readSU("struct qp_guest_endpoint", qp_entry)
        print(ep)


def show_vm_context(options):
    try:
        ctx_list = readSymbol("ctx_list")
        show_vmci_context(options, ctx_list)

        print("")
        qp_guest_endpoints = readSymbol("qp_guest_endpoints")
        show_vmci_qp_guest_endpoints(options, qp_guest_endpoints)
        return
    except:
        pass


def vminfo():
    op = OptionParser()
    op.add_option("-d", "--details", dest="show_details", default=0,
                  action="store_true",
                  help="Show details")
    op.add_option("-c", "--context", dest="show_context", default=0,
                  action="store_true",
                  help="Show VM Context")

    (o, args) = op.parse_args()

    if o.show_context:
        show_vm_context(o)
        sys.exit(0)

    balloon_info(o)


if ( __name__ == '__main__'):
    vminfo()
