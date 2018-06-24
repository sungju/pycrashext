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

    command_str = "dis %s %s" % (options, ins_addr)
    disasm_str = exec_crash_command(command_str)
    result_str = exec_gdb_command("!echo '%s' | python %s" % (disasm_str, disasm_path))

    print (result_str)


def edis():
    op = OptionParser()
    op.add_option("-r", "--reverse",
                  action="store_true",
                  dest="reverse",
                  default=False,
                  help="displays all instructions from the start of the" \
                    + " routine up to and including the designated address.")

    (o, args) = op.parse_args()
    disasm(args[0], o, os.environ["PYKDUMPPATH"])


if ( __name__ == '__main__'):
    edis()
