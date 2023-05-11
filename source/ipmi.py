"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *

import sys

def si_state_str(state):
    return {
        0: "SI_NORMAL",
        1: "SI_GETTING_FLAGS",
        2: "SI_GETTING_EVENTS",
        3: "SI_CLEARING_FLAGS",
        4: "SI_GETTING_MESSAGES",
        5: "SI_CHECKING_ENABLES",
        6: "SI_SETTING_ENABLES",
    }[state]

def irq_status(disabled):
    if (disabled):
        return "DISABLED"
    else:
        return "ENABLED"

def show_smi_list(show_details):
    try:
        pa = readSymbol("smi_infos")
        if (pa == 0):
            print ("SMI Info does not exist")
            return
    except:
        print ("SMI Info does not exist")
        return


    print ("%-18s %-18s %-18s %-18s" % ("smi_info",
                                        "ipmi_smi_t",
                                        "struct si_sm_data",
                                        "struct si_sm_handlers"))
    for smi_info  in readSUListFromHead(pa,
                                        'link',
                                        'struct smi_info'):
        print ("0x%x 0x%x 0x%x 0x%x (%s)" % (long(smi_info),
                                             smi_info.intf,
                                             smi_info.si_sm,
                                             smi_info.handlers,
                                             addr2sym(smi_info.handlers)))
        if (show_details):
            print ("%20s : 0x%x" % ("curr_msg", smi_info.curr_msg))
            if (member_offset('struct smi_info', 'waiting_msg') >= 0):
                print ("%20s : 0x%x" % ("waiting_msg", smi_info.waiting_msg))
            print ("%20s : %s" % ("state", si_state_str(smi_info.si_state)))
            print ("%20s : %d" % ("IRQ", smi_info.irq))
            su = readSU("struct task_struct", smi_info.thread);
            print ("%20s : %s (0x%x)" % ("kernel thread",
                                         su.comm if su > 0 else "<None>",
                                         smi_info.thread))


            ipmi_smi = readSU('struct ipmi_smi', smi_info.intf)
            bmc_device = readSU('struct bmc_device', ipmi_smi.bmc)
            if (member_offset('struct bmc_device', 'name') >= 0):
                print ("%20s : %s" % ("BMC name", bmc_device.name))

            ipmi_device_id = readSU('struct ipmi_device_id',
                                    bmc_device.id)
            print ("%20s : 0x%x" % ("Device ID", ipmi_device_id.device_id))
            print ("%20s : 0x%x" % ("Manufacturer ID",
                                    ipmi_device_id.manufacturer_id))
            print ("%20s : 0x%x" % ("IPMI version",
                                    ipmi_device_id.ipmi_version))


        print()


def ipmi():
    op = OptionParser()
    op.add_option("-l", "--smi_list", dest="smi_list", default=0,
                  action="store_true",
                  help="Show info list")
    op.add_option("-d", "--details", dest="show_details", default=0,
                  action="store_true",
                  help="Show detailed information")

    (o, args) = op.parse_args()

    try:
        pa = readSymbol("smi_infos")
        if pa == 0:
            return
    except:
        return

    if (o.smi_list):
        show_smi_list(o.show_details)

if ( __name__ == '__main__'):
    ipmi()
