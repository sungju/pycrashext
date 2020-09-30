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


JUMP_ORIGIN = 0x10000
JUMP_TARGET = 0x20000
JUMP_CORNER = 0x30000

MAX_JMP_LINES = 200

jump_op_set = []
exclude_set = []

def check_jump_op(op_code):
    global jump_op_set
    global exclude_set

    if op_code in exclude_set:
        return False

    for op in jump_op_set:
        if op_code.startswith(op):
            return True

    return False


def set_jump_op_list():
    global jump_op_set
    global exclude_set

    arch = sys_info.machine

    if (arch in ("x86_64", "i386", "i686", "athlon")):
        jump_op_set = [ "j" ]
    elif (arch.startswith("ppc")):
        jump_op_set = [ "b" ]
        exclude_set = [ "bl", "bctrl" ]
    elif (arch.startswith("arm")):
        jump_op_set = [ "b" ]
        exclude_set = [ "bl", "bic", "bics", "blx" ]
    else:
        jump_op_set = [ "j" ]


def draw_branches(disasm_str, jump_op_list):
    result = ""
    asm_addr_dict = {}
    loc = 0
    for line in disasm_str.splitlines():
        if line.startswith("0x"):
            words = line.split()
            asm_addr_dict[words[0]] = loc
        loc = loc + 1

    total_num = loc
    jmp_dict = [[0 for x in range(MAX_JMP_LINES)] for y in range(total_num)]
    has_jmp_dict = [0 for x in range(total_num)]
    loc = 0
    jmp_found = 1
    set_jump_op_list()
    for line in disasm_str.splitlines():
        if line.startswith("0x"):
            words = line.split()
            is_jump_op = False
            if jump_op_list == "":
                if check_jump_op(words[2]):
                    is_jump_op = True
            else:
                if words[2] in jump_op_list:
                    is_jump_op = True

            if is_jump_op:
                if jmp_found >= MAX_JMP_LINES:
                    break

                # Consider a situation that implies the jumping address
                jmpaddr = ""
                if len(words) > 3:
                    jmp_op_words = words[3].split(",")
                    jmpaddr = jmp_op_words[len(jmp_op_words) - 1]

                if jmpaddr != "" and jmpaddr in asm_addr_dict:
                    target_idx = asm_addr_dict[jmpaddr]
                else:
                    target_idx = total_num

                current_idx = loc
                start = min(current_idx, target_idx)
                end = max(current_idx, target_idx)
                if end > total_num:
                    end = total_num

                for i in range(start, end):
                    jmp_dict[i][jmp_found - 1] = jmp_dict[i][jmp_found - 1] + 1
                    has_jmp_dict[i] = has_jmp_dict[i] + 1
                jmp_dict[current_idx][jmp_found] = JUMP_ORIGIN # current
                jmp_dict[current_idx][jmp_found - 1] = JUMP_CORNER # current
                if target_idx < total_num:
                    jmp_dict[target_idx][jmp_found] = JUMP_TARGET # target
                    jmp_dict[target_idx][jmp_found - 1] = JUMP_CORNER # target

                jmp_found = jmp_found + 1
        loc = loc + 1

    result = ""
    loc = 0
    for line in disasm_str.splitlines():
        jmp_str = " "
        line_str = ""
        for i in range(0, jmp_found):
            if (jmp_dict[loc][i] & JUMP_ORIGIN) == JUMP_ORIGIN:
                jmp_str = "-"
            if (jmp_dict[loc][i] & JUMP_TARGET) == JUMP_TARGET:
                jmp_str = "="
            if (jmp_dict[loc][i] & JUMP_CORNER) == JUMP_CORNER:
                jmp_str = "+"
            if jmp_dict[loc][i] > 0 and jmp_str == " ":
                jmp_str = "|"

            if i == jmp_found - 1:
                if jmp_str == "-":
                    jmp_str = "*"
                if jmp_str == "=":
                    jmp_str = ">"

            line_str = line_str + jmp_str
            if jmp_str != "-" and jmp_str != "=" and \
               jmp_str != ">" and jmp_str != '*':
                jmp_str = " "

        result = result + line_str + line + "\n"
        loc = loc + 1

    return result


def is_command_exist(name):
    result_str = crashhelper.run_gdb_command("!which %s" % (name))
    if result_str.startswith("which"):
        return False
    return True


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
    try:
        if (unit == 8):
            data = readULong(addr)
        elif (unit == 4):
            data = readUInt(addr)
    except:
        pass

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
                if len(op) > 4:
                    offset = int(op[:-4], 10)
                else:
                    offset = 0
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
            if "(%rbp)" in op and "%rbp" in register_dict:
                if op.startswith("*"):
                    op = op[1:]
                if len(op) > 6:
                    offset = int(op[:-6], 16)
                else:
                    offset = 0
                internal_count = 0
                for stackaddr in register_dict["%rbp"]:
                    actual_addr = stackaddr + offset + stack_unit
                    if words[2] != "lea": # lea    -0x30(%rbp),%rdi
                        data = ("%x" % read_stack_data(actual_addr, stack_unit)).zfill(stack_unit * 2)
                    else:
                        data = ("%x" % actual_addr)

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
                if op.startswith("*"):
                    op = op[1:]
                if len(op) > 6: # check the case with no offset
                    offset = int(op[:-6], 16)
                else: # (%rsp)
                    offset = 0
                internal_count = 0
                for stackaddr in register_dict["%rsp"]:
                    actual_addr = stackaddr + offset
                    if words[2] != "lea": # lea    -0x30(%rsp),%rdi
                        data = ("%x" % read_stack_data(actual_addr, stack_unit)).zfill(stack_unit * 2)
                    else:
                        data = ("%x" % actual_addr)

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

    try:
        bt_str = exec_crash_command("bt")
    except:
        return # In case stack has corrupted

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
            if len(words) > 0:
                if words[0] == "[exception":
                    if words[2].startswith(funcname + "+"):
                        stackfound = 1
                    continue

            if (len(words) < 5):
                continue
            if words[0].startswith("#") and stackfound == 1:
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
            "pop" : crashcolor.YELLOW | crashcolor.UNDERLINE,
            "ret" : crashcolor.MAGENTA | crashcolor.BOLD,
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

    return


def is_address(str):
    str = str.strip()
    if (str.startswith("0x") and len(str) == ((sys_info.pointersize + 1) * 2)):
        return True

    return False


def find_symbol(str):
    try:
        sym = exec_crash_command("sym %s" % str)
        if sym.startswith("sym:") != True:
            return " <" + "".join(sym.split()[2:]) + ">"
    except:
        pass

    return ""


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

    options = ""
    if (o.noaction == False):
        options = "-l"
    if (o.reverse):
        options = options + " -r"

    cmd_options = ""
    if (o.sourceonly):
        cmd_options = cmd_options + " -s"
    if (o.fullsource):
        cmd_options = cmd_options + " -f"
        if (not o.reverse):
            options = options + " -r"

    if ins_addr.startswith("/"):
        ins_addr = ins_addr[1:] # get rid of the first slash

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

    result_str = ""
    if (o.noaction or not disasm_str.startswith("/")):
        result_str = disasm_str
    else:
        python_list = { "python", "python3", "python2" }
        for python_cmd in python_list:
            if (is_command_exist(python_cmd)):
                kerver, relver = get_kernel_version()
                ver_line = ""
                if kerver.find(".rt") >= 0: # rt kernel
                    relver = relver[:relver.find("-")]
                    ver_line = "/usr/src/debug/kernel-%s/linux-%s/" % \
                            (relver, kerver)
                else:
                    ver_line = disasm_str.splitlines()[0]

                disasm_str = ver_line + "\n" + disasm_str
                result_str = crashhelper.run_gdb_command("!echo '%s' | %s %s %s" % \
                                                    (disasm_str, python_cmd, \
                                                     disasm_path, cmd_options))
                break

    if (o.graph):
        result_str = draw_branches(result_str, o.jump_op_list)

    set_stack_data(disasm_str, ins_addr) # To retreive stack data
    if o.stackaddr != "":
        stackaddr_list = [int(o.stackaddr, 16)]

    set_asm_colors()
    crashcolor.set_color(crashcolor.RESET)
    for one_line in result_str.splitlines():
        idx = one_line.find("0x")
        if idx >= 0:
            line = one_line[idx:]
            graph = one_line[:idx]
            is_disasm_line = True
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
            is_disasm_line = False

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
            if idx == 7: # For black background situation
                idx = idx + 1

        if is_disasm_line == True:
            line = interpret_one_line(line) # Retreive stack data if possible
        words = line.split()
        if len(words) > 2:
            if (o.symbol and is_address(words[-1]) == True): # Translate address into symbol
                line = ("%s%s" % (words[-1], find_symbol(words[-1]))).join(line.rsplit(words[-1], 1))
            color_str = get_colored_asm(words[2].strip())
            idx = line.find(words[2], len(words[0]) + len(words[1]) + 1)
            print(line[:idx], end='')
            if color_str != None:
                crashcolor.set_color(color_str)
            print(line[idx:idx+len(words[2])], end='')
            if color_str != None:
                crashcolor.set_color(operand_color)
            if len(words) >= 4: # Not handling callq or jmp.
                line = line[idx:]
                print("%s" % line[len(words[2]):line.find(words[3])],
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

                if (is_disasm_line):
                    comment_idx = line.find(";")
                    if comment_idx > -1:
                        print(line[:comment_idx], end='')
                        crashcolor.set_color(crashcolor.LIGHTYELLOW)
                        print(line[comment_idx:])
                    else:
                        comment_idx = line.find("<")
                        if comment_idx > -1:
                            print(line[:comment_idx], end='')
                            crashcolor.set_color(crashcolor.LIGHTMAGENTA)
                            print(line[comment_idx:])
                        else:
                            print("%s" % line)
                else:
                    print(line)

                crashcolor.set_color(crashcolor.RESET)
            else:
                print(line[idx+len(words[2]):])
            crashcolor.set_color(crashcolor.RESET)
        else:
            print(line)


    crashcolor.set_color(crashcolor.RESET)


class LineType(object):
    LINE_SPACE = 0,
    LINE_FIRST = 1,
    LINE_BRANCH = 2,
    LINE_LAST = 3,
    LINE_VERT = 4


line_type = ["    ", "-+- ", " |- ", " `- ", " |  "]
branch_bar = []
branch_locations = []

def print_branch(depth, first):
    global branch_locations
    global branch_bar

    if (first and depth > 0):
        print ("%s" % (line_type[1]), end='')
        return

    for i in range(0, depth):
        for j in range (0, branch_locations[i]):
            print (" ", end='')

        k = branch_bar[i]
        if (type(k) == tuple):
            k = k[0]
        print("%s" % (line_type[k]), end='')


def show_callgraph_func(func_name, depth, first, options):
    global branch_locations

    print_branch(depth, first)

    print_str = ("{%s} " % (func_name))
    start_char = func_name[0]
    if start_char == '*' or start_char == '0':
        crashcolor.set_color(crashcolor.BLUE)
    print("%s" % (print_str), end='')
    if start_char == '*' or start_char == '0':
        crashcolor.set_color(crashcolor.RESET)
    if (len(branch_locations) <= depth):
        branch_locations.append(len(print_str))
    else:
        branch_locations[depth] = len(print_str)

    return 1


call_op_set = []
call_exclude_set = []

def set_call_op_list():
    global call_op_set
    global call_exclude_set

    arch = sys_info.machine

    if (arch in ("x86_64", "i386", "i686", "athlon")):
        call_op_set = [ "call", "callq" ]
    elif (arch.startswith("ppc")):
        call_op_set = [ "bl", "ctrl" ]
    elif (arch.startswith("arm")):
        call_op_set = [ "bl", "bic", "bics", "blx" ]
    else:
        call_op_set = ["callq" ]


def show_callgraph(func_name, depth, options):
    global branch_bar
    global call_op_set

    if depth >= options.max_depth:
        print("...", end="")
        return

    depth = depth + 1
    while (len(branch_bar) <= depth):
        branch_bar.append(LineType.LINE_SPACE)

    first = True
    disasm_str = exec_crash_command("dis %s" % (func_name))
    disasm_list = disasm_str.splitlines()
    call_list = []
    for line in disasm_list:
        if line == "":
            break
        words = line.split()
        if len(words) <= 2:
            continue
        if words[2] in call_op_set:
            if len(words) > 4:
                if words[4].startswith("<"):
                    call_list.append(words[4][1:-1])
                elif words[4].startswith("#") and len(words) > 5:
                    call_list.append("0x%x" % readULong(int(words[5], 16)))
            elif len(words) == 4:
                call_list.append(words[3])

    len_call_list = len(call_list)
    for idx, func_name in enumerate(call_list):
        if (idx == len_call_list - 1):
            branch_bar[depth - 1] = LineType.LINE_LAST
        else:
            branch_bar[depth - 1] = LineType.LINE_BRANCH

        printed = show_callgraph_func(func_name, depth, first, options)
        first = False

        if (idx == len_call_list - 1):
            branch_bar[depth - 1] = LineType.LINE_SPACE
        else:
            branch_bar[depth - 1] = LineType.LINE_VERT

        show_callgraph(func_name, depth, options)
        if (idx != len_call_list - 1):
            if (printed > 0):
                print()


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

    op.add_option("-S", "--stack",
                  action="store",
                  type="string",
                  default="",
                  dest="stackaddr",
                  help="Set stack address for disasm operation")

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


    op.add_option("-b", "--symbol",
                  action="store_true",
                  dest="symbol",
                  default=False,
                  help="Translate symbols if possible")

    op.add_option("-j", "--jump",
                  action="store",
                  type="string",
                  default="",
                  dest="jump_op_list",
                  help="Shows graph for the specified jump operations only")


    try:
        encode_url = os.environ['CRASHEXT_SERVER'] + '/api/disasm'
    except:
        encode_url = ""

    if encode_url != None and encode_url != "":
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

    op.add_option("-c", "--callgraph",
                  action="store_true",
                  dest="callgraph",
                  default=False,
                  help="Shows call graph for a function")

    MAX_DEPTH = 2
    op.add_option("-m", "--max_depth",
                  action="store",
                  type="int",
                  dest="max_depth",
                  default=MAX_DEPTH,
                  help="Maximum depth of graph for callgraph. default=%s" %
                        MAX_DEPTH)

    (o, args) = op.parse_args()

    if o.callgraph == True:
        set_call_op_list()
        show_callgraph_func(args[0], 0, True, o)
        show_callgraph(args[0], 0, o)
        sys.exit(0)

    if len(args) != 0:
        disasm(args[0], o, args, os.environ["PYKDUMPPATH"])
    else:
        print("ERROR> edis needs an address or a symbol\n",
              "\ti.e) edis 0xffffffff81c76fca or edis hugetlb_init")


if ( __name__ == '__main__'):
    edis()
