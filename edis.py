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

def disasm(ins_addr, o, cmd_path_list):
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

    if ":" in ins_addr or "." in ins_addr: # It's for source code
        if ":" not in ins_addr: # Let's make fake line number
            ins_addr = ins_addr + ": 0"
        else:
            idx = ins_addr.rfind(":")
            ins_addr = ins_addr[:idx] + ": " + ins_addr[idx+1:]

        kernel_ver, release_ver = get_kernel_version()
        disasm_str = "/usr/src/debug/kernel-%s/linux-%s/%s" % \
                    (kernel_ver, release_ver, ins_addr)
    else:
        command_str = "dis %s %s" % (options, ins_addr)
        disasm_str = exec_crash_command(command_str)
    if (disasm_str.startswith("symbol not found")):
        print (disasm_str)
        return

    result_str = exec_gdb_command("!echo '%s' | python %s %s" % \
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

    (o, args) = op.parse_args()
    disasm(args[0], o, os.environ["PYKDUMPPATH"])


if ( __name__ == '__main__'):
    edis()
