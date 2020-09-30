"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *

import sys

def run_a_command(command):
    command = "epython " + command
    print ("<%s>" % command)
    exec_command("%s" % (command))


def lockup_test_list():
    return ["lockup", "lockup -r", "lockup --tasks",
           "lockup --tasks -r"]


def sched_test_list():
    return ["sched --classes", "sched --classes --details"]


def cgroupinfo_test_list():
    return ["cgroupinfo --tglist --tree"]


def pstree_test_list():
    return ["pstree", "pstree -p", "pstree -g",
            "pstree -s", "pstree -t 1 -p"]


def modinfo_test_list():
    return ["modinfo", "modinfo --details ext4"]


def vmw_mem_test_list():
    return ["vmw_mem"]


def ipmi_test_list():
    return ["ipmi --smi_list", "ipmi --smi_list --details"]


def show_command_list(cmd_funcs):
    for cmd_set in cmd_funcs:
        print ("cmds_test --cmd %s" % (cmd_set))
        cmd_list = cmd_funcs[cmd_set]()
        for a_cmd in cmd_list:
            print ("\t%s" % (a_cmd))
        print ()


def all_cmds_list(cmd_funcs):
    cmd_list = []
    for cmd in cmd_funcs:
        cmd_list.extend(cmd_funcs[cmd]())

    return cmd_list


def cmds_test():
    cmd_funcs = {\
        'lockup'     : lockup_test_list,\
        'sched'      : sched_test_list,\
        'cgroupinfo' : cgroupinfo_test_list,\
        'pstree'     : pstree_test_list,\
        'modinfo'    : modinfo_test_list,\
        'vmw_mem'    : vmw_mem_test_list,\
        'ipmi'       : ipmi_test_list\
    }

    op = OptionParser()

    op.add_option("--cmd", dest="command", default=None,
                  action="store", type="string",
                  help="The command set to run")
    op.add_option("--list", dest="show_list", default=None,
                  action="store_true",
                  help="Show the command set list")

    (o, args) = op.parse_args()


    if (o.show_list):
        show_command_list(cmd_funcs)
        sys.exit(0)


    cmd = o.command
    if (cmd == "all"):
        print ("PLEASE RUN IT WITH YOUR OWN RISK")
        print ("PyKdump seems not able to handle several calls in one shot")

        cmd_list = all_cmds_list(cmd_funcs)
    else:
        cmd_list = cmd_funcs[cmd]()

    for cmd in cmd_list:
        run_a_command(cmd)

if ( __name__ == '__main__'):
    cmds_test()
