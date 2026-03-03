"""
 Written by Daniel Sungju Kwon
"""

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
    elif (arch.startswith("s390") or arch in ("s390x")):
        jump_op_set = [ "j", "brc", "brct" ]
        exclude_set = [ "brasl", "bras" ]
    elif (arch.startswith("riscv") or arch in ("riscv64", "riscv32")):
        jump_op_set = [ "j", "b" ]
        exclude_set = [ "jal", "jalr" ]
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
    if result_str.find(":") >= 0:
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
stack_debug_enabled = False
stack_debug_lines = []


def reset_stack_debug():
    global stack_debug_lines
    stack_debug_lines = []


def add_stack_debug(msg):
    if stack_debug_enabled:
        stack_debug_lines.append(msg)


def get_stack_debug():
    return stack_debug_lines[:]


def get_operand_explanation(one_line):
    words = one_line.split(None, 3)
    if len(words) < 3:
        return ""

    opcode = words[2].strip()
    operands = words[3].strip() if len(words) > 3 else ""
    arch = sys_info.machine

    ops = [o.strip() for o in operands.split(",")] if operands else []

    if arch in ("x86_64", "i386", "i686", "athlon"):
        if opcode.startswith("mov") and len(ops) == 2:
            return "move value from %s to %s" % (ops[0], ops[1])
        if opcode == "lea" and len(ops) == 2:
            return "compute address %s into %s (no memory read)" % (ops[0], ops[1])
        if opcode in ("push", "pushq") and len(ops) == 1:
            return "push %s onto stack (rsp decreases)" % ops[0]
        if opcode in ("pop", "popq") and len(ops) == 1:
            return "pop top of stack into %s (rsp increases)" % ops[0]
        if opcode in ("sub", "add") and operands.find("%rsp") >= 0:
            return "adjust stack pointer with %s" % operands
        if opcode.startswith("call"):
            return "function call (return address pushed on stack)"
        if opcode.startswith("ret"):
            return "return from function"
        if "(%rsp)" in operands or "(%rbp)" in operands:
            return "stack/frame memory access via %s" % ("rsp/rbp")
        return ""

    if arch.startswith("arm") or arch in ("aarch64"):
        if opcode == "stp" and operands:
            return "store register pair to memory%s" % (" with writeback" if operands.find("]!") >= 0 else "")
        if opcode == "ldp" and operands:
            return "load register pair from memory%s" % (" with writeback" if operands.find("],") >= 0 else "")
        if opcode.startswith("str"):
            return "store register to memory%s" % (" with writeback" if operands.find("]!") >= 0 or operands.find("],") >= 0 else "")
        if opcode.startswith("ldr"):
            return "load register from memory%s" % (" with writeback" if operands.find("]!") >= 0 or operands.find("],") >= 0 else "")
        if opcode == "mov" and len(ops) == 2:
            return "copy %s to %s" % (ops[1], ops[0])
        if opcode in ("add", "sub") and operands.find("sp") >= 0:
            return "update stack pointer/frame with %s" % operands
        if opcode in ("bl", "blr"):
            return "branch with link (function call)"
        if opcode in ("ret",):
            return "return from function"
        return ""

    if arch.startswith("ppc"):
        if opcode in ("stdu", "stwu") and operands.find("(r1)") >= 0:
            return "store with update: write value and update stack pointer r1"
        if opcode in ("std", "stw", "stb", "sth"):
            return "store register to memory"
        if opcode in ("ld", "lwz", "lbz", "lhz", "lha", "lmw"):
            return "load register from memory"
        if opcode == "addi" and operands.startswith("r1,r1,"):
            return "adjust stack pointer r1 by immediate"
        if opcode == "bl":
            return "branch with link (function call)"
        if opcode.startswith("b"):
            return "branch/jump control flow"
        return ""

    if arch.startswith("s390") or arch in ("s390x"):
        if opcode in ("stg", "stmg", "st", "sty"):
            return "store register(s) to memory"
        if opcode in ("lg", "lmg", "l", "ly"):
            return "load register(s) from memory"
        if opcode in ("aghi", "lay") and operands.find("r15") >= 0:
            return "adjust stack pointer register r15"
        if opcode in ("brasl", "bras"):
            return "branch and save return (function call)"
        if opcode.startswith("j") or opcode.startswith("br"):
            return "jump/branch control flow"
        return ""

    if arch.startswith("riscv") or arch in ("riscv64", "riscv32"):
        if opcode in ("sd", "sw", "sh", "sb"):
            return "store register to memory"
        if opcode in ("ld", "lw", "lh", "lhu", "lb", "lbu"):
            return "load register from memory"
        if opcode == "addi" and operands.startswith("sp,sp,"):
            return "adjust stack pointer by immediate"
        if opcode == "mv" and (operands == "s0,sp" or operands == "fp,sp"):
            return "set frame pointer from stack pointer"
        if opcode in ("jal", "jalr", "call"):
            return "jump and link (function call)"
        if opcode == "ret":
            return "return from function"
        return ""

    return ""


def read_stack_data(addr, unit):
    """
    Safely read stack data from memory.

    Args:
        addr: Memory address to read from
        unit: Size in bytes (1, 2, 4, or 8)

    Returns:
        int: Data value, or 0 if read fails
    """
    data = 0
    try:
        if unit == 8:
            data = readULong(addr)
        elif unit == 4:
            data = readUInt(addr)
        elif unit == 2:
            data = readU16(addr)
        elif unit == 1:
            data = readU8(addr)
        else:
            # Invalid unit size, return 0
            return 0
    except Exception as e:
        # Memory read failed - this is expected for invalid addresses
        pass

    return data


def interpret_one_line(one_line):
    global stack_op_dict
    global stackaddr_list
    global cur_count
    global stack_unit
    global stack_offset
    global register_dict

    reset_stack_debug()

    if len(register_dict) == 0:
        register_dict= { "%rsp" : stackaddr_list, }

    result_str = one_line
    words = one_line.split()
    if len(words) < 3 or one_line.startswith("/") or one_line.startswith(" "):
        return result_str

    arch = sys_info.machine
    explain = get_operand_explanation(one_line)
    if explain != "":
        add_stack_debug("hint=%s" % explain)

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
            if stack_debug_enabled and "%rsp" in register_dict and arch in ("x86_64", "i386", "i686", "athlon"):
                vsp = []
                for a in register_dict["%rsp"]:
                    vsp.append(a - stack_offset - (cur_count * stack_unit))
                add_stack_debug("sp update: push -> virtual rsp=%s" %
                                (",".join(["0x%x" % a for a in vsp])))
            break

    if result_str == one_line and len(words) > 3: # Nothing happened in the above loop
        result_str = stack_reg_op(words, result_str)

    return result_str


def s390x_stack_reg_op(words, result_str):
    """Enhanced s390x (IBM Z) stack register operations handler"""

    # Ensure we have stack pointer initialized
    if "%rsp" not in register_dict:
        return result_str

    # Handle stack pointer adjustment: aghi r15, -160 or lay r15, -160(r15)
    if words[2] == "aghi" and len(words) >= 4 and words[3].startswith("r15,"):
        # Extract offset: r15,-160 -> -160
        offset_str = words[3].split(",")[-1]
        offset = parse_offset(offset_str)
        reg_list = []
        for stackaddr in register_dict["%rsp"]:
            actual_addr = stackaddr + offset
            reg_list.append(actual_addr)
        register_dict["%rsp"] = reg_list
        add_stack_debug("sp update: r15 += %d => %s" %
                        (offset, ",".join(["0x%x" % a for a in register_dict["%rsp"]])))

    elif words[2] == "lay" and len(words) >= 4 and words[3].startswith("r15,"):
        # lay r15, -160(r15) - load address
        if "(r15)" in words[3]:
            offset_str = words[3].split(",")[1].split("(")[0]
            offset = parse_offset(offset_str)
            reg_list = []
            for stackaddr in register_dict["%rsp"]:
                actual_addr = stackaddr + offset
                reg_list.append(actual_addr)
            register_dict["%rsp"] = reg_list
            add_stack_debug("sp update: lay r15,%d(r15) => %s" %
                            (offset, ",".join(["0x%x" % a for a in register_dict["%rsp"]])))

    # Handle store operations: stg r14, 112(r15) or stmg r6,r14,48(r15)
    elif words[2] in ("stg", "stmg", "st", "sty") and len(words) > 3:
        if "(r15)" in words[3]:
            # Extract offset from format: 112(r15)
            parts = words[3].split(",")
            for part in parts:
                if "(r15)" in part:
                    offset_str = part.split("(")[0]
                    offset = parse_offset(offset_str)

                    # Determine data size
                    if words[2] in ("stg", "stmg"):
                        data_size = 8  # 64-bit
                    else:
                        data_size = 4  # 32-bit

                    stackaddr_list = register_dict["%rsp"]
                    result_str = result_str + format_stack_data(stackaddr_list, offset, data_size)

                    if words[2] == "stmg":
                        result_str = result_str + " ..."  # Multiple registers
                    break

    # Handle load operations: lg r14, 112(r15) or lmg r6,r14,48(r15)
    elif words[2] in ("lg", "lmg", "l", "ly") and len(words) > 3:
        if "(r15)" in words[3]:
            # Extract offset from format: 112(r15)
            parts = words[3].split(",")
            for part in parts:
                if "(r15)" in part:
                    offset_str = part.split("(")[0]
                    offset = parse_offset(offset_str)

                    # Determine data size
                    if words[2] in ("lg", "lmg"):
                        data_size = 8  # 64-bit
                    else:
                        data_size = 4  # 32-bit

                    stackaddr_list = register_dict["%rsp"]
                    result_str = result_str + format_stack_data(stackaddr_list, offset, data_size)

                    if words[2] == "lmg":
                        result_str = result_str + " ..."  # Multiple registers
                    break

    # Handle frame pointer operations with r11 or r13
    elif len(words) > 3 and ("(r11)" in words[3] or "(r13)" in words[3]):
        # Similar to r15, but using frame pointer
        reg_name = "r11" if "(r11)" in words[3] else "r13"
        parts = words[3].split(",")
        for part in parts:
            if "(" + reg_name + ")" in part:
                offset_str = part.split("(")[0]
                offset = parse_offset(offset_str)

                # Use frame pointer if available
                if "%rbp" in register_dict:
                    result_str = result_str + format_stack_data(register_dict["%rbp"], offset, stack_unit)
                break

    return result_str


def riscv_stack_reg_op(words, result_str):
    """Enhanced RISC-V stack register operations handler"""

    # Ensure we have stack pointer initialized
    if "%rsp" not in register_dict:
        return result_str

    # Handle stack pointer adjustment: addi sp, sp, -32
    if words[2] == "addi" and len(words) >= 4 and words[3].startswith("sp,sp,"):
        # Extract offset: sp,sp,-32 -> -32
        offset_str = words[3].split(",")[-1]
        offset = parse_offset(offset_str)
        reg_list = []
        for stackaddr in register_dict["%rsp"]:
            actual_addr = stackaddr + offset
            reg_list.append(actual_addr)
        register_dict["%rsp"] = reg_list
        add_stack_debug("sp update: sp += %d => %s" %
                        (offset, ",".join(["0x%x" % a for a in register_dict["%rsp"]])))

    # Handle frame pointer setup: mv s0, sp or addi s0, sp, 0
    elif (words[2] == "mv" and len(words) >= 4 and
          (words[3] == "s0,sp" or words[3] == "fp,sp")):
        reg_list = []
        for stackaddr in register_dict["%rsp"]:
            reg_list.append(stackaddr)
        register_dict["%rbp"] = reg_list

    # Handle store operations: sd ra, 24(sp) or sw a0, 8(sp)
    elif words[2] in ("sd", "sw", "sh", "sb") and len(words) > 3:
        if "(sp)" in words[3]:
            # Extract offset from format: 24(sp)
            parts = words[3].split(",")
            for part in parts:
                if "(sp)" in part:
                    offset_str = part.split("(")[0]
                    offset = parse_offset(offset_str)

                    # Determine data size
                    if words[2] == "sd":
                        data_size = 8  # 64-bit
                    elif words[2] == "sw":
                        data_size = 4  # 32-bit
                    elif words[2] == "sh":
                        data_size = 2  # 16-bit
                    else:  # sb
                        data_size = 1  # 8-bit

                    stackaddr_list = register_dict["%rsp"]
                    result_str = result_str + format_stack_data(stackaddr_list, offset, data_size)
                    break

    # Handle load operations: ld ra, 24(sp) or lw a0, 8(sp)
    elif words[2] in ("ld", "lw", "lh", "lhu", "lb", "lbu") and len(words) > 3:
        if "(sp)" in words[3]:
            # Extract offset from format: 24(sp)
            parts = words[3].split(",")
            for part in parts:
                if "(sp)" in part:
                    offset_str = part.split("(")[0]
                    offset = parse_offset(offset_str)

                    # Determine data size
                    if words[2] == "ld":
                        data_size = 8  # 64-bit
                    elif words[2] == "lw":
                        data_size = 4  # 32-bit
                    elif words[2] in ("lh", "lhu"):
                        data_size = 2  # 16-bit
                    else:  # lb, lbu
                        data_size = 1  # 8-bit

                    stackaddr_list = register_dict["%rsp"]
                    result_str = result_str + format_stack_data(stackaddr_list, offset, data_size)
                    break

    # Handle operations with frame pointer: ld a0, 16(s0) or ld a0, 16(fp)
    elif len(words) > 3:
        stack_word = ""
        use_fp = False
        for word in words[3:]:
            if "(s0)" in word or "(fp)" in word or "(x8)" in word:
                stack_word = word
                use_fp = True
                break

        if stack_word != "" and use_fp:
            parts = stack_word.split(",")
            for part in parts:
                if "(s0)" in part or "(fp)" in part or "(x8)" in part:
                    offset_str = part.split("(")[0]
                    offset = parse_offset(offset_str)

                    if "%rbp" in register_dict:
                        result_str = result_str + format_stack_data(register_dict["%rbp"], offset, stack_unit)
                    break

    return result_str


def stack_reg_op(words, result_str):
    arch = sys_info.machine
    if (arch in ("x86_64", "i386", "i686", "athlon")):
        result_str = x86_stack_reg_op(words, result_str)
    elif (arch.startswith("arm") or (arch in ("aarch64"))):
        result_str = arm_stack_reg_op(words, result_str)
    elif (arch.startswith("ppc")):
        result_str = ppc_stack_reg_op(words, result_str)
    elif (arch.startswith("s390") or arch in ("s390x")):
        result_str = s390x_stack_reg_op(words, result_str)
    elif (arch.startswith("riscv") or arch in ("riscv64", "riscv32")):
        result_str = riscv_stack_reg_op(words, result_str)

    return result_str


def ppc_stack_reg_op(words, result_str):
    """Enhanced PPC/PPC64 stack register operations handler"""

    # Ensure we have stack pointer initialized
    if "%rsp" not in register_dict:
        return result_str

    # Handle stack pointer adjustment: addi r1, r1, offset
    if words[2] == "addi" and len(words) >= 4 and words[3].startswith("r1,r1,"):
        # Extract offset: r1,r1,-128 -> -128
        offset_str = words[3].split(",")[-1]
        offset = parse_offset(offset_str)
        reg_list = []
        for stackaddr in register_dict["%rsp"]:
            actual_addr = stackaddr + offset
            reg_list.append(actual_addr)
        register_dict["%rsp"] = reg_list
        add_stack_debug("sp update: r1 += %d => %s" %
                        (offset, ",".join(["0x%x" % a for a in register_dict["%rsp"]])))

    # Handle stack operations with (r1): std r17,-120(r1)
    elif len(words) > 3 and "(r1)" in words[3]:
        op_words = words[3].split(",")
        for op in op_words:
            if "(r1)" in op:
                # Extract offset from format: -120(r1)
                if len(op) > 4:
                    offset_str = op[:-4]
                    offset = parse_offset(offset_str)
                else:
                    offset = 0

                # Determine data size based on instruction
                data_size = stack_unit  # Default to 8 bytes (doubleword)
                if words[2] in ("stw", "lwz", "lwzu", "stwu"):
                    data_size = 4  # Word operations
                elif words[2] in ("sth", "lhz", "lha"):
                    data_size = 2  # Halfword operations
                elif words[2] in ("stb", "lbz"):
                    data_size = 1  # Byte operations

                stackaddr_list = register_dict["%rsp"]
                result_str = result_str + format_stack_data(stackaddr_list, offset, data_size)

                # Handle instructions that update the stack pointer
                # stdu: store doubleword with update (r1 = effective address)
                # stwu: store word with update
                if words[2] in ("stdu", "stwu") and op_words[0] == "r1":
                    result_stack_addr_list = []
                    for stackaddr in stackaddr_list:
                        actual_addr = stackaddr + offset
                        result_stack_addr_list.append(actual_addr)
                    register_dict["%rsp"] = result_stack_addr_list
                    add_stack_debug("sp update: %s updates r1 by %d => %s" %
                                    (words[2], offset, ",".join(["0x%x" % a for a in register_dict["%rsp"]])))

                break

    # Handle multiple register store/load: stmw, lmw
    elif words[2] in ("stmw", "lmw") and len(words) > 3:
        # stmw/lmw stores/loads multiple words starting from specified register
        # Format: stmw r27,-20(r1)
        if "(r1)" in words[3]:
            op_words = words[3].split(",")
            for op in op_words:
                if "(r1)" in op:
                    if len(op) > 4:
                        offset_str = op[:-4]
                        offset = parse_offset(offset_str)
                    else:
                        offset = 0

                    stackaddr_list = register_dict["%rsp"]
                    result_str = result_str + format_stack_data(stackaddr_list, offset, 4)
                    result_str = result_str + " ..."  # Multiple registers
                    break

    return result_str


def parse_offset(offset_str):
    """
    Parse an offset string that can be in various formats.
    Handles: decimal, hex (0x...), negative values, with/without # prefix

    Args:
        offset_str: String containing the offset (e.g., "16", "0x10", "-8", "#16")

    Returns:
        int: Parsed offset value
    """
    if not offset_str:
        return 0

    # Remove # prefix if present (ARM style)
    if offset_str.startswith("#"):
        offset_str = offset_str[1:]

    # Remove $ prefix if present (x86 style)
    if offset_str.startswith("$"):
        offset_str = offset_str[1:]

    try:
        # Handle hex
        if offset_str.startswith("0x") or offset_str.startswith("-0x"):
            return int(offset_str, 16)
        # Handle decimal (including negative)
        else:
            return int(offset_str, 10)
    except ValueError:
        # Return 0 for unparseable values
        return 0


def get_stack_offset(stack_word):
    """Legacy wrapper for parse_offset() to maintain compatibility"""
    op_words = stack_word.split(",")
    if len(op_words) > 1:
        return parse_offset(op_words[1])
    else:
        return 0


def format_stack_data(stackaddr_list, offset, unit, prefix="    ; ", reg=None):
    """
    Format stack data for display.

    Args:
        stackaddr_list: List of stack addresses to read from
        offset: Offset from stack address
        unit: Size of data to read (1, 2, 4, or 8 bytes)
        prefix: Prefix string for the comment
        reg: Optional register name (e.g., "x19")

    Returns:
        str: Formatted string with stack values, empty string if no data
    """
    if not stackaddr_list:
        return ""

    result = ""
    for idx, stackaddr in enumerate(stackaddr_list):
        try:
            actual_addr = stackaddr + offset
            data = read_stack_data(actual_addr, unit)
            add_stack_debug("read %s base=0x%x offset=%d addr=0x%x size=%d value=0x%x" %
                            (reg if reg else "stack", stackaddr, offset, actual_addr, unit, data))
            # Format with correct width based on unit size
            data_str = ("%x" % data).zfill(unit * 2)

            # Format with register name if provided
            if reg:
                if idx == 0:
                    result = "%s%s: 0x%s" % (prefix, reg, data_str)
                else:
                    result = "%s, %s: 0x%s" % (result, reg, data_str)
            else:
                if idx == 0:
                    result = "%s0x%s" % (prefix, data_str)
                else:
                    result = "%s, 0x%s" % (result, data_str)
        except Exception as e:
            # Skip this entry if there's an error
            continue

    return result


def format_stack_data_pair(stackaddr_list, offset, unit, prefix="    ; ", reg1=None, reg2=None):
    """
    Format pair of stack data values for display (used by ARM stp/ldp).

    Args:
        stackaddr_list: List of stack addresses to read from
        offset: Offset from stack address
        unit: Size of data to read (4 or 8 bytes)
        prefix: Prefix string for the comment
        reg1: Optional name of first register (e.g., "x21")
        reg2: Optional name of second register (e.g., "x22")

    Returns:
        str: Formatted string with pairs of stack values, empty string if no data
    """
    if not stackaddr_list:
        return ""

    result = ""
    for idx, stackaddr in enumerate(stackaddr_list):
        try:
            actual_addr = stackaddr + offset
            data1 = read_stack_data(actual_addr, unit)
            data2 = read_stack_data(actual_addr + unit, unit)
            add_stack_debug("read pair %s/%s base=0x%x offset=%d addrs=(0x%x,0x%x) size=%d values=(0x%x,0x%x)" %
                            (reg1 if reg1 else "stack", reg2 if reg2 else "stack",
                             stackaddr, offset, actual_addr, actual_addr + unit, unit, data1, data2))
            data1_str = ("%x" % data1).zfill(unit * 2)
            data2_str = ("%x" % data2).zfill(unit * 2)

            # Format with register names if provided
            if reg1 and reg2:
                if idx == 0:
                    result = "%s%s: 0x%s, %s: 0x%s" % (prefix, reg1, data1_str, reg2, data2_str)
                else:
                    result = "%s, %s: 0x%s, %s: 0x%s" % (result, reg1, data1_str, reg2, data2_str)
            else:
                if idx == 0:
                    result = "%s0x%s 0x%s" % (prefix, data1_str, data2_str)
                else:
                    result = "%s, 0x%s 0x%s" % (result, data1_str, data2_str)
        except Exception as e:
            # Skip this entry if there's an error
            continue

    return result


def parse_aarch64_mem_operand(operand_text):
    """
    Parse AArch64 memory operand forms used in prologue/epilogue.
    Examples:
      [sp, #96]
      [sp,#-64]!
      [sp],#16
    Returns:
      (base_reg, offset, writeback, post_index)
    """
    if operand_text is None:
        return None, 0, False, False

    text = operand_text.replace(" ", "")
    writeback = text.endswith("]!")
    post_index = "]," in text and not writeback

    if text.startswith("[") and "]" in text:
        inner = text[1:text.find("]")]
        parts = inner.split(",")
        base_reg = parts[0] if len(parts) > 0 else ""
        offset = 0
        if len(parts) > 1 and parts[1] != "":
            offset = parse_offset(parts[1])

        if post_index:
            # Form: [sp],#16 (post-index immediate after ']')
            post = text[text.find("],") + 2:]
            offset = parse_offset(post)

        return base_reg, offset, writeback, post_index

    return None, 0, False, False


def is_aarch64_immediate(token):
    tok = token.strip().rstrip(",")
    if tok == "":
        return False
    if tok.startswith("#"):
        return True
    if tok.startswith("0x") or tok.startswith("-0x"):
        return True
    return tok.lstrip("-").isdigit()


def estimate_aarch64_runtime_sp(frame_addr, disasm_str):
    """
    Estimate ENTRY SP (before prologue stack allocation) from bt frame address
    for AArch64. bt frame address usually matches x29 (frame pointer).

    We replay from function start in edis -r, so initial %rsp must be entry SP.
    """
    fp_from_sp_off = None
    sp_delta_before_fp = 0
    seen_insn = 0

    for one_line in disasm_str.splitlines():
        words = one_line.split()
        if len(words) < 3 or not words[0].startswith("0x"):
            continue

        seen_insn += 1
        if seen_insn > 80:
            break

        op = words[2]
        ops_text = "".join(words[3:]) if len(words) > 3 else ""

        # Track SP changes from function entry until FP is established.
        # sub sp, sp, #imm
        if op == "sub" and len(words) >= 5 and words[3] == "sp," and words[4].startswith("sp"):
            if "," in words[4] and len(words[4].split(",")[-1]) > 0:
                offset_part = words[4].split(",")[-1]
            elif len(words) > 5:
                offset_part = words[5]
            else:
                offset_part = "0"
            sp_delta_before_fp -= parse_offset(offset_part.rstrip(","))
            continue

        # add sp, sp, #imm
        if op == "add" and len(words) >= 5 and words[3] == "sp," and words[4].startswith("sp"):
            if "," in words[4] and len(words[4].split(",")[-1]) > 0:
                offset_part = words[4].split(",")[-1]
            elif len(words) > 5:
                offset_part = words[5]
            else:
                offset_part = "0"
            sp_delta_before_fp += parse_offset(offset_part.rstrip(","))
            continue

        # Track SP writeback forms before FP is established:
        #   stp/ldp ..., [sp, #imm]!
        #   stp/ldp ..., [sp], #imm
        #   str/ldr ..., [sp, #imm]!
        #   str/ldr ..., [sp], #imm
        if op in ("stp", "ldp", "str", "stur", "strb", "strh", "strw",
                  "ldr", "ldur", "ldrb", "ldrh", "ldrw", "ldrsw", "ldrsh", "ldrsb"):
            mem_pos = ops_text.find("[sp")
            if mem_pos >= 0:
                base_reg, wb_offset, writeback_pre, post_index = \
                    parse_aarch64_mem_operand(ops_text[mem_pos:])
                if base_reg == "sp" and (writeback_pre or post_index):
                    sp_delta_before_fp += wb_offset
                    continue

        # add x29, sp, #0x60
        if op == "add" and len(words) >= 6 and words[3].startswith("x29"):
            if words[4].startswith("sp"):
                fp_from_sp_off = parse_offset(words[5].rstrip(","))
                break

        # mov x29, sp
        if op == "mov" and len(words) >= 5 and words[3].startswith("x29"):
            if words[4].startswith("sp"):
                fp_from_sp_off = 0
                break

        # Stop after first call out of prologue region
        if op in ("bl", "blr"):
            break

    if fp_from_sp_off is not None:
        # frame_addr(x29) = (entry_sp + sp_delta_before_fp) + fp_from_sp_off
        # => entry_sp = frame_addr - fp_from_sp_off - sp_delta_before_fp
        return frame_addr - fp_from_sp_off - sp_delta_before_fp

    return frame_addr



def arm_stack_reg_op(words, result_str):
    """Enhanced ARM/AArch64 stack register operations handler"""

    # Ensure we have stack pointer initialized
    if "%rsp" not in register_dict:
        return result_str

    opcode = words[2]
    operands = "".join(words[3:]) if len(words) > 3 else ""

    # Handle frame pointer setup: mov x29, sp / add x29, sp, #imm
    if opcode == "mov" and len(words) >= 5 and words[3].startswith("x29") and words[4].startswith("sp"):
        reg_list = []
        for stackaddr in register_dict["%rsp"]:
            # On AArch64, x29 mirrors current SP at this point.
            reg_list.append(stackaddr)
        register_dict["%rbp"] = reg_list
        add_stack_debug("fp update: x29 <- sp, fp=%s" %
                        (",".join(["0x%x" % a for a in register_dict["%rbp"]])))
    elif opcode == "add" and len(words) >= 6 and words[3].startswith("x29") and words[4].startswith("sp"):
        fp_offset = parse_offset(words[5].rstrip(","))
        reg_list = []
        for stackaddr in register_dict["%rsp"]:
            reg_list.append(stackaddr + fp_offset)
        register_dict["%rbp"] = reg_list
        add_stack_debug("fp update: x29 <- sp + %d, fp=%s" %
                        (fp_offset, ",".join(["0x%x" % a for a in register_dict["%rbp"]])))

    # Handle mov sp, x29 / mov sp, xN
    elif opcode == "mov" and len(words) >= 5 and words[3].startswith("sp"):
        src_reg = words[4].rstrip(",")
        if src_reg.startswith("x29") or src_reg.startswith("fp"):
            if "%rbp" in register_dict:
                register_dict["%rsp"] = register_dict["%rbp"][:]
                add_stack_debug("sp update: sp <- fp, sp=%s" %
                                (",".join(["0x%x" % a for a in register_dict["%rsp"]])))
            else:
                result_str = result_str + "  ;CAUTION: missing frame pointer value"
        elif src_reg.startswith("sp"):
            pass
        else:
            result_str = result_str + "  ;CAUTION: skipped register sp move"

    # Handle stack pointer manipulation:
    #   sub/add sp, sp, #imm
    #   sub/add sp, sp, xN
    #   add/sub sp, x29, #imm
    elif opcode in ("sub", "add") and len(words) >= 5 and words[3] == "sp,":
        src_token = words[4].rstrip(",")
        rhs_token = words[5].rstrip(",") if len(words) > 5 else ""
        if "," in words[4]:
            # Handles compact style: sp,sp,#0x40
            parts = words[4].split(",")
            src_token = parts[0]
            if len(parts) > 1 and parts[1] != "":
                rhs_token = parts[1]

        sign = -1 if opcode == "sub" else 1

        if src_token == "sp":
            if is_aarch64_immediate(rhs_token):
                delta = sign * parse_offset(rhs_token)
                reg_list = []
                for stackaddr in register_dict["%rsp"]:
                    reg_list.append(stackaddr + delta)
                register_dict["%rsp"] = reg_list
                add_stack_debug("sp update: sp <- sp %s %s => %s" %
                                ("+" if delta >= 0 else "-", abs(delta),
                                 ",".join(["0x%x" % a for a in register_dict["%rsp"]])))
            else:
                result_str = result_str + "  ;CAUTION: skipped register sp adjust"
        elif src_token in ("x29", "fp"):
            if "%rbp" not in register_dict:
                result_str = result_str + "  ;CAUTION: missing frame pointer value"
            elif is_aarch64_immediate(rhs_token):
                delta = sign * parse_offset(rhs_token)
                reg_list = []
                for fpaddr in register_dict["%rbp"]:
                    reg_list.append(fpaddr + delta)
                register_dict["%rsp"] = reg_list
                add_stack_debug("sp update: sp <- fp %s %s => %s" %
                                ("+" if delta >= 0 else "-", abs(delta),
                                 ",".join(["0x%x" % a for a in register_dict["%rsp"]])))
            else:
                result_str = result_str + "  ;CAUTION: skipped register sp base adjust"
        else:
            result_str = result_str + "  ;CAUTION: unsupported sp base register"

    # Handle store pair: stp x29, x30, [sp,#-64]!
    elif words[2] == "stp" and len(words) >= 5:
        # Extract register names (e.g., x29, x30)
        reg1 = words[3].rstrip(",") if len(words) > 3 else None
        reg2 = words[4].rstrip(",") if len(words) > 4 else None

        # Check if [sp is in the instruction (could be words[len-2] or words[len-1])
        found_sp = False
        stack_word = ""

        # Format 1: stp x29, x30, [sp, #64] -> second-to-last word is [sp,
        if len(words) >= 6 and words[len(words)-2].find("[sp") >= 0:
            stack_word = words[len(words)-1]
            found_sp = True
        # Format 2: stp x29, x30, [sp,#64] -> last word is [sp,#64]
        elif words[len(words)-1].find("[sp") >= 0:
            stack_word = words[len(words)-1]
            found_sp = True

        if not found_sp:
            # Not an sp-relative stp, skip
            pass
        else:
            # Determine if it's pre-decrement or normal
            if stack_word.endswith("]!"):
                # Stack Push
                # Example:
                # 0xffff800010386560 <vfs_read+16>:	stp	x29, x30, [sp,#-64]!
                # sp = sp - 64
                # [sp] = x29
                # [sp + 8] = x30
                update_sp=True
            else:
                # Normal stack access
                # Example:
                # 0xffff800010386568 <vfs_read+24>:	stp	x19, x20, [sp,#16]
                # [sp + 16] = x19
                # [sp + 16 + 8] = x20
                update_sp=False

            # Extract offset from stack_word
            # Could be "#64]" or "[sp,#64]" or "[sp, #64]"
            if stack_word.startswith("[sp"):
                # Format: [sp,#64] or [sp, #64] -> find the offset part
                offset_start = stack_word.find("#")
                if offset_start > 0:
                    # Extract from # to ]
                    offset_end = stack_word.find("]")
                    offset_str = stack_word[offset_start:offset_end]
                else:
                    # No # found, extract from comma
                    offset_str = stack_word[stack_word.find(",")+1:stack_word.find("]")]
            else:
                # Format: #64] -> already just the offset
                offset_str = stack_word[1:stack_word.find("]")]

            offset = parse_offset(offset_str)

            if update_sp == True:
                stackaddr_list = register_dict["%rsp"]
                new_stackaddr_list = []
                for stackaddr in stackaddr_list:
                    stackaddr = stackaddr + offset
                    new_stackaddr_list.append(stackaddr)
                register_dict["%rsp"] = new_stackaddr_list
                offset = 0

            # Use helper function for formatting with register names
            result_str = result_str + format_stack_data_pair(register_dict["%rsp"], offset, stack_unit, reg1=reg1, reg2=reg2)
    # Handle load pair: ldp x29, x30, [sp],#16
    elif words[2] == "ldp" and len(words) >= 5:
        # Extract register names (e.g., x29, x30)
        reg1 = words[3].rstrip(",") if len(words) > 3 else None
        reg2 = words[4].rstrip(",") if len(words) > 4 else None

        # Check for [sp in the instruction
        found_sp = False
        stack_word = ""
        update_sp = False
        sp_offset = 0

        # Format 1: ldp x29, x30, [sp],#16 -> post-increment
        if len(words) >= 6 and words[len(words)-2].find("[sp") >= 0:
            stack_word = words[len(words)-2]
            stack_op = words[len(words) - 1]
            if stack_op.startswith("#"):
                stack_op = stack_op[1:]
            if stack_op.endswith("]"):
                stack_op = stack_op[:-1]
            sp_offset = parse_offset(stack_op)
            update_sp = True
            found_sp = True
        # Format 2: ldp x19, x20, [sp, #16] or [sp,#16] -> normal access
        elif words[len(words)-1].find("[sp") >= 0:
            stack_word = words[len(words)-1]
            update_sp = False
            sp_offset = 0
            found_sp = True
        elif len(words) >= 6 and words[len(words)-2].find("[sp") >= 0:
            stack_word = words[len(words)-1]
            update_sp = False
            sp_offset = 0
            found_sp = True

        if found_sp:
            # Extract offset from stack_word
            if stack_word.startswith("[sp"):
                # Format: [sp,#16] -> extract offset
                offset_start = stack_word.find("#")
                if offset_start > 0:
                    offset_end = stack_word.find("]")
                    offset_str = stack_word[offset_start:offset_end]
                else:
                    offset_str = stack_word[stack_word.find(",")+1:stack_word.find("]")]
            else:
                # Format: #16] or just numbers
                if stack_word.find("]") > 0:
                    offset_str = stack_word[1:stack_word.find("]")]
                else:
                    offset_str = stack_word

            offset = parse_offset(offset_str)

            # Use helper function for formatting with register names
            result_str = result_str + format_stack_data_pair(register_dict["%rsp"], offset, stack_unit, reg1=reg1, reg2=reg2)

            if update_sp == True:
                stackaddr_list = register_dict["%rsp"]
                new_stackaddr_list = []
                for stackaddr in stackaddr_list:
                    stackaddr = stackaddr + sp_offset
                    new_stackaddr_list.append(stackaddr)
                register_dict["%rsp"] = new_stackaddr_list

    # Handle single register store: str x19, [sp,#16] or str x19, [sp], #16
    elif opcode in ("str", "stur", "strb", "strh", "strw"):
        # Extract register name (e.g., x19)
        reg_name = words[3].rstrip(",") if len(words) > 3 else None

        mem_pos = operands.find("[sp")
        if mem_pos >= 0:
            mem_op = operands[mem_pos:]
            base_reg, offset, writeback_pre, post_index = parse_aarch64_mem_operand(mem_op)

            if base_reg == "sp":
                # Determine data size based on instruction
                if opcode == "strb":
                    data_size = 1
                elif opcode == "strh":
                    data_size = 2
                elif opcode == "strw":
                    data_size = 4
                else:
                    data_size = stack_unit

                if writeback_pre:
                    reg_list = []
                    for stackaddr in register_dict["%rsp"]:
                        reg_list.append(stackaddr + offset)
                    register_dict["%rsp"] = reg_list
                    access_offset = 0
                    add_stack_debug("sp writeback(pre): sp <- sp %+d => %s" %
                                    (offset, ",".join(["0x%x" % a for a in register_dict["%rsp"]])))
                else:
                    access_offset = offset

                result_str = result_str + format_stack_data(register_dict["%rsp"], access_offset, data_size, reg=reg_name)

                if post_index:
                    reg_list = []
                    for stackaddr in register_dict["%rsp"]:
                        reg_list.append(stackaddr + offset)
                    register_dict["%rsp"] = reg_list
                    add_stack_debug("sp writeback(post): sp <- sp %+d => %s" %
                                    (offset, ",".join(["0x%x" % a for a in register_dict["%rsp"]])))

    # Handle single register load: ldr x19, [sp,#16] / [sp],#16 / [sp,#-16]!
    elif opcode in ("ldr", "ldur", "ldrb", "ldrh", "ldrw", "ldrsw", "ldrsh", "ldrsb"):
        # Extract register name (e.g., x19)
        reg_name = words[3].rstrip(",") if len(words) > 3 else None

        mem_pos = operands.find("[sp")
        if mem_pos >= 0:
            mem_op = operands[mem_pos:]
            base_reg, offset, writeback_pre, post_index = parse_aarch64_mem_operand(mem_op)

            if base_reg == "sp":
                # Determine data size based on instruction
                if opcode in ("ldrb", "ldrsb"):
                    data_size = 1
                elif opcode in ("ldrh", "ldrsh"):
                    data_size = 2
                elif opcode in ("ldrw", "ldrsw"):
                    data_size = 4
                else:
                    data_size = stack_unit

                if writeback_pre:
                    reg_list = []
                    for stackaddr in register_dict["%rsp"]:
                        reg_list.append(stackaddr + offset)
                    register_dict["%rsp"] = reg_list
                    access_offset = 0
                    add_stack_debug("sp writeback(pre): sp <- sp %+d => %s" %
                                    (offset, ",".join(["0x%x" % a for a in register_dict["%rsp"]])))
                else:
                    access_offset = offset

                result_str = result_str + format_stack_data(register_dict["%rsp"], access_offset, data_size, reg=reg_name)

                if post_index:
                    reg_list = []
                    for stackaddr in register_dict["%rsp"]:
                        reg_list.append(stackaddr + offset)
                    register_dict["%rsp"] = reg_list
                    add_stack_debug("sp writeback(post): sp <- sp %+d => %s" %
                                    (offset, ",".join(["0x%x" % a for a in register_dict["%rsp"]])))

    # Handle operations with frame pointer (x29): ldr x0, [x29,#16]
    elif len(words) > 3:
        # Check for [x29] or [fp] addressing
        stack_word = ""
        use_fp = False
        for word in words[3:]:
            if word.startswith("[x29") or word.startswith("[fp"):
                stack_word = word
                use_fp = True
                break
            elif word.startswith("[sp"):
                stack_word = word
                break

        if stack_word != "":
            stack_word = stack_word[1:stack_word.find("]")]
            offset = parse_offset(stack_word)

            # Use frame pointer or stack pointer
            if use_fp and "%rbp" in register_dict:
                result_str = result_str + format_stack_data(register_dict["%rbp"], offset, stack_unit)
            elif "%rsp" in register_dict:
                result_str = result_str + format_stack_data(register_dict["%rsp"], offset, stack_unit)

    return result_str


def x86_stack_reg_op(words, result_str):
    """Enhanced x86/x86_64 stack register operations handler"""

    # Ensure we have stack pointer initialized
    if "%rsp" not in register_dict:
        return result_str

    # Handle frame pointer setup: mov %rsp,%rbp
    if words[2] == "mov" and words[3] == "%rsp,%rbp":
        reg_list = []
        for stackaddr in register_dict["%rsp"]:
            actual_addr = stackaddr - stack_offset - (cur_count * stack_unit)
            reg_list.append(actual_addr)
        register_dict["%rbp"] = reg_list

    # Handle stack allocation: sub $0x40,%rsp
    elif words[2] == "sub" and words[3].endswith(",%rsp"):
        op_words = words[3].split(",")
        if "%" in op_words[0]: # Cannot use other register values
            return result_str + "  ;CAUTION: skipped register sub"
        value_to_sub = parse_offset(op_words[0])
        reg_list = []
        for stackaddr in register_dict["%rsp"]:
            actual_addr = stackaddr - value_to_sub - (cur_count * stack_unit)
            reg_list.append(actual_addr)
        register_dict["%rsp"] = reg_list
        add_stack_debug("sp update: rsp -= %d => %s" %
                        (value_to_sub, ",".join(["0x%x" % a for a in register_dict["%rsp"]])))

    # Handle stack cleanup: add $0x40,%rsp
    elif words[2] == "add" and words[3].endswith(",%rsp"):
        op_words = words[3].split(",")
        if "%" in op_words[0]: # Cannot use other register values
            return result_str + "  ;CAUTION: skipped register add"
        value_to_add = parse_offset(op_words[0])
        reg_list = []
        for stackaddr in register_dict["%rsp"]:
            actual_addr = stackaddr + value_to_add
            reg_list.append(actual_addr)
        register_dict["%rsp"] = reg_list
        add_stack_debug("sp update: rsp += %d => %s" %
                        (value_to_add, ",".join(["0x%x" % a for a in register_dict["%rsp"]])))

    # Handle pop instruction: pop %rbx
    elif words[2] == "pop" or words[2] == "popq":
        # Display current stack value
        result_str = result_str + format_stack_data(register_dict["%rsp"], 0, stack_unit)
        # Update stack pointer (pop removes 8 bytes on x86_64, 4 on x86)
        reg_list = []
        for stackaddr in register_dict["%rsp"]:
            actual_addr = stackaddr + stack_unit
            reg_list.append(actual_addr)
        register_dict["%rsp"] = reg_list
        add_stack_debug("sp update: pop -> rsp += %d => %s" %
                        (stack_unit, ",".join(["0x%x" % a for a in register_dict["%rsp"]])))

    # Handle enter instruction: enter $0x10,$0x00
    elif words[2] == "enter":
        # enter creates a stack frame
        # First pushes %rbp, then mov %rsp,%rbp, then sub from %rsp
        op_words = words[3].split(",")
        frame_size = parse_offset(op_words[0]) if op_words else 0
        # Simulate push %rbp
        reg_list = []
        for stackaddr in register_dict["%rsp"]:
            actual_addr = stackaddr - stack_unit
            reg_list.append(actual_addr)
        register_dict["%rsp"] = reg_list
        register_dict["%rbp"] = reg_list[:]
        # Subtract frame size
        reg_list = []
        for stackaddr in register_dict["%rsp"]:
            actual_addr = stackaddr - frame_size
            reg_list.append(actual_addr)
        register_dict["%rsp"] = reg_list
        add_stack_debug("sp update: enter frame_size=%d => rsp=%s rbp=%s" %
                        (frame_size,
                         ",".join(["0x%x" % a for a in register_dict["%rsp"]]),
                         ",".join(["0x%x" % a for a in register_dict["%rbp"]])))

    # Handle leave instruction: leave
    elif words[2] == "leave":
        # leave restores the stack frame
        # mov %rbp,%rsp; pop %rbp
        if "%rbp" in register_dict:
            register_dict["%rsp"] = register_dict["%rbp"][:]
            reg_list = []
            for stackaddr in register_dict["%rsp"]:
                actual_addr = stackaddr + stack_unit
                reg_list.append(actual_addr)
            register_dict["%rsp"] = reg_list
            add_stack_debug("sp update: leave -> rsp from rbp then +%d => %s" %
                            (stack_unit, ",".join(["0x%x" % a for a in register_dict["%rsp"]])))

    # Handle operations with frame pointer: mov %rax,-0x30(%rbp)
    elif len(words) > 3 and "(%rbp)" in words[3]:
        op_words = words[3].split(",")
        for op in op_words:
            if "(%rbp)" in op and "%rbp" in register_dict:
                if op.startswith("*"):
                    op = op[1:]
                # Extract offset, handling negative values
                if len(op) > 6:
                    offset_str = op[:-6]
                    offset = parse_offset(offset_str)
                else:
                    offset = 0

                # Use the new helper function for formatting
                if words[2] != "lea": # lea doesn't dereference
                    result_str = result_str + format_stack_data(
                        register_dict["%rbp"], offset + stack_unit, stack_unit)
                else:
                    # For lea, show the address itself
                    for idx, stackaddr in enumerate(register_dict["%rbp"]):
                        actual_addr = stackaddr + offset + stack_unit
                        if idx == 0:
                            result_str = "%s    ; 0x%x" % (result_str, actual_addr)
                        else:
                            result_str = "%s, 0x%x" % (result_str, actual_addr)
                break

    # Handle operations with stack pointer: mov %rdx,0x18(%rsp)
    elif len(words) > 3 and "(%rsp)" in words[3]:
        op_words = words[3].split(",")
        for op in op_words:
            if "(%rsp)" in op:
                if op.startswith("*"):
                    op = op[1:]

                # Handle indexed addressing: 0x10(%rsp,%rbx,8)
                if "," in op:
                    # Complex addressing mode - just show base for now
                    base_part = op.split(",")[0]
                    if len(base_part) > 6:
                        offset = parse_offset(base_part[:-6])
                    else:
                        offset = 0
                    result_str = result_str + "  ;CAUTION: indexed addressing"
                else:
                    # Simple offset: 0x18(%rsp) or (%rsp)
                    if len(op) > 6:
                        offset = parse_offset(op[:-6])
                    else:
                        offset = 0

                # Use the new helper function for formatting
                if words[2] != "lea": # lea doesn't dereference
                    result_str = result_str + format_stack_data(
                        register_dict["%rsp"], offset, stack_unit)
                else:
                    # For lea, show the address itself
                    for idx, stackaddr in enumerate(register_dict["%rsp"]):
                        actual_addr = stackaddr + offset
                        if idx == 0:
                            result_str = "%s    ; 0x%x" % (result_str, actual_addr)
                        else:
                            result_str = "%s, 0x%x" % (result_str, actual_addr)
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

    elif (arch.startswith("arm") or (arch in ("aarch64"))):
        stack_op_dict = {
        }
        stack_unit = 8
        stack_offset = 0

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
                # Exception frame hand-off: the following frame holds the stack pointer.
                stackaddr_list.append(int(words[1][1:-1], 16))
                add_stack_debug("set_stack_data: exception hand-off sp=0x%x" % stackaddr_list[-1])
                stackfound = 0
                continue

            if words[0].startswith("#") and words[2] == funcname and words[4] == disaddr_str:
                # For AArch64, bt frame address is often x29. Convert to runtime SP.
                frame_addr = int(words[1][1:-1], 16)
                runtime_sp = estimate_aarch64_runtime_sp(frame_addr, disasm_str)
                stackaddr_list.append(runtime_sp)
                add_stack_debug("set_stack_data: frame=0x%x estimated_entry_sp=0x%x" %
                                (frame_addr, runtime_sp))

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

    elif (arch.startswith("s390") or arch in ("s390x")):
        stack_op_dict = {}
        stack_unit = 8
        stack_offset = 0

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

    elif (arch.startswith("riscv") or arch in ("riscv64", "riscv32")):
        stack_op_dict = {}
        if arch in ("riscv64"):
            stack_unit = 8
        else:
            stack_unit = 4
        stack_offset = 0

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
    elif (arch.startswith("arm") or (arch in ("aarch64"))):
        asm_color_dict = {
            "bl" : crashcolor.LIGHTRED | crashcolor.BOLD,
            "b" : crashcolor.BLUE | crashcolor.BOLD,
            "stp" : crashcolor.RED | crashcolor.UNDERLINE,
            "ldp" : crashcolor.YELLOW | crashcolor.UNDERLINE,
            "ret" : crashcolor.MAGENTA | crashcolor.BOLD,
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
    elif (arch.startswith("s390") or arch in ("s390x")):
        asm_color_dict = {
            "brasl" : crashcolor.LIGHTRED | crashcolor.BOLD,
            "bras" : crashcolor.LIGHTRED | crashcolor.BOLD,
            "jg" : crashcolor.BLUE | crashcolor.BOLD,
            "j" : crashcolor.BLUE | crashcolor.BOLD,
            "brc" : crashcolor.BLUE | crashcolor.BOLD,
            "stg" : crashcolor.RED | crashcolor.UNDERLINE,
            "stmg" : crashcolor.RED | crashcolor.UNDERLINE,
            "lg" : crashcolor.YELLOW | crashcolor.UNDERLINE,
            "lmg" : crashcolor.YELLOW | crashcolor.UNDERLINE,
            "br" : crashcolor.MAGENTA | crashcolor.BOLD,
        }
        arg_color_dict = {
            "r2" : crashcolor.UNDERLINE | crashcolor.CYAN,
            "r3" : crashcolor.UNDERLINE | crashcolor.CYAN,
            "r4" : crashcolor.UNDERLINE | crashcolor.CYAN,
            "r5" : crashcolor.UNDERLINE | crashcolor.CYAN,
            "r6" : crashcolor.UNDERLINE | crashcolor.CYAN,
        }
    elif (arch.startswith("riscv") or arch in ("riscv64", "riscv32")):
        asm_color_dict = {
            "jal" : crashcolor.LIGHTRED | crashcolor.BOLD,
            "jalr" : crashcolor.LIGHTRED | crashcolor.BOLD,
            "j" : crashcolor.BLUE | crashcolor.BOLD,
            "beq" : crashcolor.BLUE | crashcolor.BOLD,
            "bne" : crashcolor.BLUE | crashcolor.BOLD,
            "sd" : crashcolor.RED | crashcolor.UNDERLINE,
            "sw" : crashcolor.RED | crashcolor.UNDERLINE,
            "ld" : crashcolor.YELLOW | crashcolor.UNDERLINE,
            "lw" : crashcolor.YELLOW | crashcolor.UNDERLINE,
            "ret" : crashcolor.MAGENTA | crashcolor.BOLD,
        }
        arg_color_dict = {
            "a0" : crashcolor.UNDERLINE | crashcolor.CYAN,
            "a1" : crashcolor.UNDERLINE | crashcolor.CYAN,
            "a2" : crashcolor.UNDERLINE | crashcolor.CYAN,
            "a3" : crashcolor.UNDERLINE | crashcolor.CYAN,
            "a4" : crashcolor.UNDERLINE | crashcolor.CYAN,
            "a5" : crashcolor.UNDERLINE | crashcolor.CYAN,
            "a6" : crashcolor.UNDERLINE | crashcolor.CYAN,
            "a7" : crashcolor.UNDERLINE | crashcolor.CYAN,
        }

    return


def is_address(str):
    str = str.strip()
    if (str.startswith("0x") and len(str) == ((sys_info.pointersize + 1) * 2)):
        return True

    return False


def find_symbol(str):
    try:
        sym = exec_crash_command("kmem %s" % str).splitlines()[0].strip()
        words = sym.split()
        if len(words) > 2 and words[1].startswith("("):
            return " <" + " ".join(sym.split()[2:]) + ">"
    except:
        pass

    return ""


def disasm(ins_addr, o, args, cmd_path_list):
    global asm_color_dict

    global funcname
    global stackaddr_list
    global stack_op_dict
    global stack_debug_enabled

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

    if (o.fullsource):
        print(result_str)
        return

    if (o.graph):
        result_str = draw_branches(result_str, o.jump_op_list)

    stack_debug_enabled = o.debug
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
            debug_lines = get_stack_debug()
            if o.symbol:
                words = line.split()
                if words[-2] == '#':
                    line = line + " " + find_symbol(words[-1])
        else:
            debug_lines = []

        words = line.split()
        if len(words) > 2:
            if (o.symbol and is_address(words[-1]) == True): # Translate address into symbol
                line = ("%s%s" % (words[-1], find_symbol(words[-1]))).join(line.rsplit(words[-1], 1))
            color_str = get_colored_asm(words[2].strip())
            constsym = ""
            if len(words) > 3:
                if  words[3].startswith("$0x"):
                    constaddr = words[3].split(',')[0][1:]
                    #constsym = find_symbol(constaddr)
                elif words[2].startswith("call") and len(words) == 4:
                    #constsym = find_symbol(words[3])
                    pass

                if len(constsym) > 0:
                    constsym = '  ;' + constsym

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
                print(constsym, end='')

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

        if o.debug and is_disasm_line and len(debug_lines) > 0:
            crashcolor.set_color(crashcolor.LIGHTCYAN)
            for dbg in debug_lines:
                print("    [D] %s" % dbg)
            crashcolor.set_color(crashcolor.RESET)


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
    elif (arch.startswith("arm") or (arch in ("aarch64"))):
        call_op_set = [ "bl", "bic", "bics", "blx" ]
    elif (arch.startswith("s390") or arch in ("s390x")):
        call_op_set = [ "brasl", "bras" ]
    elif (arch.startswith("riscv") or arch in ("riscv64", "riscv32")):
        call_op_set = [ "jal", "jalr" ]
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

    op.add_option("-D", "--debug",
                  action="store_true",
                  dest="debug",
                  default=False,
                  help="Show stack calculation debug lines after each disassembly line")


    try:
        encode_url = os.environ['CRASHEXT_SERVER'] + '/api/disasm'
    except:
        encode_url = ""

    if encode_url != None and encode_url != "":
        noaction_default=False
    else:
        noaction_default=True

    op.add_option("-n", "--noaction",
                  action="store_true",
                  dest="noaction",
                  default=noaction_default,
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
