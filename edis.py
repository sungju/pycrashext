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
import crashhelper


def is_command_exist(name):
    from shutil import which

    return which(name) is not None


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
arg_color_dict = {}

operand_color = crashcolor.YELLOW

def get_colored_asm(asm_op):
    global asm_color_dict

    for op in asm_color_dict:
        if asm_op.startswith(op):
            return asm_color_dict[op]

    return None

def get_colored_arg(opvalue):
    global arg_color_dict

    for reg in arg_color_dict:
        if opvalue.find(reg) >= 0:
            return arg_color_dict[reg]

    return None


stackaddr_list = []
funcname = ""
stack_op_dict = {}
cur_count = 0
stack_unit = 0
stack_offset = 0
register_dict = []


def read_stack_data(addr, unit):
    data = 0
    if (unit == 8):
        data = readULong(addr)
    elif (unit == 4):
        data = readUInt(addr)

    return data


def interpret_one_line(one_line):
    global stack_op_dict
    global stackaddr_list
    global cur_count
    global stack_unit
    global stack_offset
    global register_dict

    if len(register_dict) == 0:
        register_dict= { "%rsp" : stackaddr_list, }

    result_str = one_line
    words = one_line.split()
    if len(words) < 3 or one_line.startswith("/") or one_line.startswith(" "):
        return result_str

    for op in stack_op_dict:
        if words[2].startswith(op):
            internal_count = 0
            for stackaddr in stackaddr_list:
                actual_addr = stackaddr - stack_offset - (cur_count * stack_unit)
                data = ("%x" % read_stack_data(actual_addr, stack_unit)).zfill(stack_unit * 2)
                if internal_count == 0:
                    result_str = "%s    ; 0x%s" % (result_str, data)
                else:
                    result_str = "%s, 0x%s" % (result_str, data)
                internal_count = internal_count + 1

            cur_count = cur_count + 1
            break

    if result_str == one_line and len(words) > 3: # Nothing happened in the above loop
        result_str = stack_reg_op(words, result_str)

    return result_str


def stack_reg_op(words, result_str):
    arch = sys_info.machine
    if (arch in ("x86_64", "i386", "i686", "athlon")):
        result_str = x86_stack_reg_op(words, result_str)
    elif (arch.startswith("arm")):
        pass
    elif (arch.startswith("ppc")):
        result_str = ppc_stack_reg_op(words, result_str)

    return result_str


def ppc_stack_reg_op(words, result_str):
    if "(r1)" in words[3]: # std     r17,-120(r1)
        op_words = words[3].split(",")
        for op in op_words:
            if "(r1)" in op:
                offset = int(op[:-4], 10)
                internal_count = 0
                for stackaddr in register_dict["%rsp"]:
                    actual_addr = stackaddr + offset
                    data = ("%x" % read_stack_data(actual_addr, stack_unit)).zfill(stack_unit * 2)
                    if internal_count == 0:
                        result_str = "%s    ; 0x%s" % (result_str, data)
                    else:
                        result_str = "%s, 0x%s" % (result_str, data)
                    internal_count = internal_count + 1

                break

    return result_str


def x86_stack_reg_op(words, result_str):
    if words[2] == "mov" and words[3] == "%rsp,%rbp":
        reg_list = []
        for stackaddr in register_dict["%rsp"]:
            actual_addr = stackaddr - stack_offset - (cur_count * stack_unit)
            reg_list.append(actual_addr)
        register_dict["%rbp"] = reg_list

    elif words[2] == "sub" and words[3].endswith(",%rsp"):
        # sub    $0x40,%rsp
        op_words = words[3].split(",")
        value_to_sub = int(op_words[0][1:], 16)
        reg_list = []
        for stackaddr in register_dict["%rsp"]:
            actual_addr = stackaddr - value_to_sub - (cur_count * stack_unit)
            reg_list.append(actual_addr)
        register_dict["%rsp"] = reg_list

    elif "(%rbp)" in words[3]: # mov    %rax,-0x30(%rbp)
        op_words = words[3].split(",")
        for op in op_words:
            if "(%rbp)" in op:
                offset = int(op[:-6], 16)
                internal_count = 0
                for stackaddr in register_dict["%rbp"]:
                    actual_addr = stackaddr + offset
                    data = ("%x" % read_stack_data(actual_addr, stack_unit)).zfill(stack_unit * 2)
                    if internal_count == 0:
                        result_str = "%s    ; 0x%s" % (result_str, data)
                    else:
                        result_str = "%s, 0x%s" % (result_str, data)
                    internal_count = internal_count + 1

                break

    elif "(%rsp)" in words[3]: # mov    %rdx,0x18(%rsp)
        op_words = words[3].split(",")
        for op in op_words:
            if "(%rsp)" in op:
                offset = int(op[:-6], 16)
                internal_count = 0
                for stackaddr in register_dict["%rsp"]:
                    actual_addr = stackaddr + offset
                    data = ("%x" % read_stack_data(actual_addr, stack_unit)).zfill(stack_unit * 2)
                    if internal_count == 0:
                        result_str = "%s    ; 0x%s" % (result_str, data)
                    else:
                        result_str = "%s, 0x%s" % (result_str, data)
                    internal_count = internal_count + 1

                break

    return result_str


def set_stack_data(disasm_str, disaddr_str):
    global funcname
    global stackaddr_list
    global stack_op_dict
    global cur_count
    global stack_unit
    global stack_offset

    stackaddr_list = []
    cur_count = 0

    bt_str = exec_crash_command("bt")
    funcname = ""
    for one_line in disasm_str.splitlines():
        if one_line.startswith("/") or one_line.startswith(" "):
            continue
        words = one_line.split()
        funcname = words[1][1:-2]
        break

    if funcname == "":  # Not matching with any
        return

    arch = sys_info.machine
    if (arch in ("x86_64", "i386", "i686", "athlon")):
        stack_op_dict = {
            "push" : 0,
        }
        stack_unit = 8
        stack_offset = 8

        stackfound = 0
        for one_line in bt_str.splitlines():
            words = one_line.split()
            if (len(words) < 5):
                continue
            if stackfound == 1:
                stackaddr_list.append(int(words[1][1:-1], 16))
                stackfound = 0

            if words[2] == funcname and words[4] == disaddr_str:
                stackfound = 1
    elif (arch.startswith("arm")):
        stack_op_dict = {}
        stack_unit = 8
        stack_offset = 0
    elif (arch.startswith("ppc")):
        stack_op_dict = {}
        stack_unit = 8
        stack_offset = 0

        stackfound = 0
        for one_line in bt_str.splitlines():
            words = one_line.split()
            if not words[0].startswith("#"):
                continue
            if stackfound == 1:
                stackaddr_list.append(int(words[1][1:-1], 16))
                stackfound = 0

            if words[2] == funcname and words[4] == disaddr_str:
                stackfound = 1


def set_asm_colors():
    global asm_color_dict
    global arg_color_dict

    arch = sys_info.machine
    if (arch in ("x86_64", "i386", "i686", "athlon")):
        asm_color_dict = {
            "callq" : crashcolor.LIGHTRED | crashcolor.BOLD,
            "j" : crashcolor.BLUE | crashcolor.BOLD,
            "mov" : crashcolor.GREEN,
            "push" : crashcolor.RED | crashcolor.UNDERLINE,
        }
        arg_color_dict = {
            "di" : crashcolor.UNDERLINE | crashcolor.CYAN,
            "si" : crashcolor.UNDERLINE | crashcolor.CYAN,
            "dx" : crashcolor.UNDERLINE | crashcolor.CYAN,
            "cx" : crashcolor.UNDERLINE | crashcolor.CYAN,
            "r8" : crashcolor.UNDERLINE | crashcolor.CYAN,
            "r9" : crashcolor.UNDERLINE | crashcolor.CYAN,
        }
    elif (arch.startswith("arm")):
        asm_color_dict = {
            "bl" : crashcolor.LIGHTRED | crashcolor.BOLD,
            "b" : crashcolor.BLUE | crashcolor.BOLD,
        }
    elif (arch.startswith("ppc")):
        asm_color_dict = {
            "bl" : crashcolor.LIGHTRED | crashcolor.BOLD,
            "b" : crashcolor.BLUE | crashcolor.BOLD,
        }
        arg_color_dict = {
            "r3" : crashcolor.UNDERLINE | crashcolor.CYAN,
            "r4" : crashcolor.UNDERLINE | crashcolor.CYAN,
            "r5" : crashcolor.UNDERLINE | crashcolor.CYAN,
            "r6" : crashcolor.UNDERLINE | crashcolor.CYAN,
            "r7" : crashcolor.UNDERLINE | crashcolor.CYAN,
            "r8" : crashcolor.UNDERLINE | crashcolor.CYAN,
            "r9" : crashcolor.UNDERLINE | crashcolor.CYAN,
            "r10" : crashcolor.UNDERLINE | crashcolor.CYAN,
        }


def disasm(ins_addr, o, args, cmd_path_list):
    global asm_color_dict

    global funcname
    global stackaddr_list
    global stack_op_dict

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
    if (o.sourceonly):
        cmd_options = cmd_options + " -s"
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

    if (o.noaction):
        result_str = disasm_str
    else:
        python_list = { "python", "python3", "python2" }
        for python_cmd in python_list:
            if (is_command_exist(python_cmd)):
                result_str = crashhelper.run_gdb_command("!echo '%s' | %s %s %s" % \
                                                    (disasm_str, python_cmd, \
                                                     disasm_path, cmd_options))
                break

    set_stack_data(disasm_str, ins_addr) # To retreive stack data
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
            line = None
            if m is not None:
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

        line = interpret_one_line(line) # Retreive stack data if possible
        words = line.split()
        if len(words) > 2:
            color_str = get_colored_asm(words[2].strip())
            idx = line.find(words[2], len(words[0]) + len(words[1]) + 1)
            print(line[:idx], end='')
            if color_str != None:
                crashcolor.set_color(color_str)
            print(line[idx:idx+len(words[2])], end='')
            if color_str != None:
                crashcolor.set_color(operand_color)
            if len(words) >= 4: # Not handling callq or jmp.
                print(line[idx+len(words[2]):line.find(words[3])],
                     end='')
                idx = line.find(words[3])
                op_list = words[3].split(",")
                line = line[idx:]
                for i in range(0, len(op_list)):
                    opval = op_list[i]
                    color_str = get_colored_arg(opval)
                    if color_str == None:
                        crashcolor.set_color(crashcolor.RESET)
                    else:
                        crashcolor.set_color(color_str)
                    if i < len(op_list) - 1:
                        next_idx = line.find(op_list[i + 1], len(opval))
                    else:
                        next_idx = len(opval)
                    print(line[:next_idx], end='')
                    if color_str == None:
                        crashcolor.set_color(crashcolor.RESET)
                    else:
                        crashcolor.set_color(operand_color)
                    line = line[next_idx:]

                crashcolor.set_color(crashcolor.RESET)
                if len(words) >= 5:
                    if words[4] == ";" or words[4] == "#":
                        crashcolor.set_color(crashcolor.LIGHTYELLOW)
                    elif words[4].startswith("<"):
                        crashcolor.set_color(crashcolor.LIGHTMAGENTA)
                print(line)
                crashcolor.set_color(crashcolor.RESET)
            else:
                print(line[idx+len(words[2]):])
            crashcolor.set_color(crashcolor.RESET)
        else:
            print(line)


    crashcolor.set_color(crashcolor.RESET)


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

    op.add_option("-n", "--noaction",
                  action="store_true",
                  dest="noaction",
                  default=False,
                  help="Only colorising the output and not connection to server")


    op.add_option("-s", "--sourceonly",
                  action="store_true",
                  dest="sourceonly",
                  default=False,
                  help="Display source lines only, but not based on function")


    (o, args) = op.parse_args()
    disasm(args[0], o, args, os.environ["PYKDUMPPATH"])


if ( __name__ == '__main__'):
    edis()
