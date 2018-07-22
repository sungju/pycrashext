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

import crashcolor


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


asm_color_dict = {}
operand_color = crashcolor.YELLOW

def get_colored_asm(asm_op):
    global asm_color_dict

    for op in asm_color_dict:
        if asm_op.startswith(op):
            return asm_color_dict[op]

    return None


def set_asm_colors():
    global asm_color_dict

    arch = sys_info.machine
    if (arch in ("x86_64", "i386", "i686", "athlon")):
        asm_color_dict = {
            "callq" : crashcolor.LIGHTRED | crashcolor.BOLD,
            "j" : crashcolor.BLUE | crashcolor.BOLD,
            "mov" : crashcolor.GREEN,
            "push" : crashcolor.CYAN | crashcolor.UNDERLINE,
        }
    if (sys_info.machine.startswith("arm")):
        asm_color_dict = {
            "bl" : crshcolor.BLUE | crashcolor.BOLD,
            "b" : crashcolor.CYAN | crashcolor.BOLD,
        }
    if (sys_info.machine.startswith("ppc")):
        asm_color_dict = {
            "bl" : crshcolor.BLUE | crashcolor.BOLD,
            "b" : crashcolor.CYAN | crashcolor.BOLD,
        }

def disasm(ins_addr, o, args, cmd_path_list):
    global asm_color_dict

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


    set_asm_colors()
    crashcolor.set_color(crashcolor.RESET)
    for one_line in result_str.splitlines():
        idx = one_line.find("0x")
        if idx >= 0:
            line = one_line[idx:]
            graph = one_line[:idx]
        else: # source line
            prog = re.compile(r"(?P<line_number>[0-9]+)")
            m = prog.search(one_line)
            line = m.group("line_number")
            if line == None:
                prog = re.compile(r"/[a-zA-Z]")
                line = prog.match(one_line)

            if line == None:
                line = one_line
            idx = one_line.find(line)
            line = one_line[idx:]
            graph = one_line[:idx]

        idx = 2
        default_color = crashcolor.RESET
        for char in graph:
            color = default_color
            idx = idx + 1
            if char == '+':
                default_color = idx
                color = default_color
            elif char == '|':
                color = idx
            elif char == '-' or char == '=':
                color = default_color
            elif char == '>' or char == '*':
                color = crashcolor.RED
            else:
                color = crashcolor.RESET

            crashcolor.set_color(color)
            print(char, end='')

            if idx == crashcolor.MAX_COLOR:
                idx = 2

        words = line.split()
        if len(words) > 2:
            color_str = get_colored_asm(words[2].strip())
            if color_str == None:
                print(line)
                continue

            idx = line.find(words[2])
            print(line[:idx], end='')
            crashcolor.set_color(color_str)
            print(line[idx:idx+len(words[2])], end='')
            crashcolor.set_color(operand_color)
            print(line[idx+len(words[2]):])
            crashcolor.set_color(crashcolor.RESET)
        else:
            print(line)


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
