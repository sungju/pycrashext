"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *

from LinuxDump import Tasks

import sys
import operator
import os
from os.path import expanduser
import time


def run_gdb_command(command):
    """exec_gdb_command() is failing to capture the output
    if the command is with '!' which is important to execute
    shell commands. Below will capture it properly."""
    temp_name = expanduser("~") + "/" + time.strftime("%Y%m%d-%H%M%S-pycrashext-edis")
    command = command + " > " + temp_name
    exec_gdb_command(command)
    lines = ""
    if os.path.exists(temp_name):
        with open(temp_name, 'r') as f:
            try:
                lines = "".join(f.readlines())
            except:
                lines = "Failed to read " + temp_name

    os.remove(temp_name)
    return lines


def get_kernel_version():
    sys_output = exec_crash_command("sys")
    for line in sys_output.splitlines():
        words = line.split()
        if words[0] == "RELEASE:":
            release_ver = words[1]
            idx = words[1].rfind(".")
            kernel_ver = words[1][:idx]
            return kernel_ver, release_ver

    return "", ""

def disasm(ins_addr, o, args, cmd_path_list):
    path_list = cmd_path_list.split(':')
    disasm_path = ""
    for path in path_list:
        if os.path.exists(path + "/disasm.py"):
            disasm_path = path + "/disasm.py"
            break

    if disasm_path == "":
        print("Can't find disasm.py in path")
        return

    options = "-l"
    if (o.reverse):
        options = options + " -r"

    cmd_options = ""
    if (o.graph):
        cmd_options = cmd_options + " -g"
    if (o.fullsource):
        cmd_options = cmd_options + " -f"
        if (not o.reverse):
            options = options + " -r"
    if (o.jump_op_list != ""):
        cmd_options = cmd_options + " -j '" + o.jump_op_list + "'"

    if ":" in ins_addr or \
       (not ins_addr.startswith(".") and "." in ins_addr): # It's for ppc
        if ":" not in ins_addr: # Let's make fake line number
            ins_addr = ins_addr + ": 0"
        else:
            words = ins_addr.split(":")
            ins_addr = ""
            for column in words:
                if ins_addr == "":
                    ins_addr = column + ":"
                else:
                    ins_addr = ins_addr + " " + column

            for line_number in args[1:]:
                ins_addr = ins_addr + " " + line_number


        kernel_ver, release_ver = get_kernel_version()
        disasm_str = "/usr/src/debug/kernel-%s/linux-%s/%s" % \
                    (kernel_ver, release_ver, ins_addr)
    else:
        command_str = "dis %s %s" % (options, ins_addr)
        disasm_str = exec_crash_command(command_str)
    if (disasm_str.startswith("symbol not found")):
        print (disasm_str)
        return

    result_str = run_gdb_command("!echo '%s' | python %s %s" % \
                                  (disasm_str, disasm_path, cmd_options))

    print (result_str)


def edis():
    op = OptionParser()
    op.add_option("-r", "--reverse",
                  action="store_true",
                  dest="reverse",
                  default=False,
                  help="displays all instructions from the start of the" \
                    + " routine up to and including the designated address.")


    op.add_option("-l", "--list",
                  action="store_true",
                  dest="list",
                  default=False,
                  help="Dummy argument to match with 'dis -l'")

    op.add_option("-g", "--graph",
                  action="store_true",
                  dest="graph",
                  default=False,
                  help="display jump graph on the left")

    op.add_option("-f", "--full",
                  action="store_true",
                  dest="fullsource",
                  default=False,
                  help="Dispaly full function code")


    op.add_option("-j", "--jump",
                  action="store",
                  type="string",
                  default="",
                  dest="jump_op_list",
                  help="Shows graph for the specified jump operations only")

    (o, args) = op.parse_args()
    disasm(args[0], o, args, os.environ["PYKDUMPPATH"])


if ( __name__ == '__main__'):
    edis()
