"""
'edis' command: enhanced disassembly with source lines, jump graphs and call graphs.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from pykdump.API import *

from LinuxDump import Tasks

import sys
import operator
import os
from os.path import expanduser
import time
import re
import shlex

import crashcolor
import crashhelper


# Register name constants (normalized keys for register_dict)
REG_STACK_POINTER = "%rsp"   # Stack pointer (all architectures)
REG_FRAME_POINTER = "%rbp"   # Frame pointer (all architectures)
REG_RETURN_ADDR = "%rra"      # Return address register

# Data size constants (in bytes)
DATA_SIZE_BYTE = 1
DATA_SIZE_WORD = 2
DATA_SIZE_DWORD = 4

# Compiled regex patterns for register detection (avoids recompilation on hot path)
_RE_PAREN_CONTENT = re.compile(r'\([^)]*\)')
_RE_REGISTER = re.compile(r'%[a-z0-9]+')
DATA_SIZE_QWORD = 8

# Instruction to data size mappings per architecture
INSTRUCTION_SIZES = {
    "s390x": {
        "stg": 8, "lg": 8, "stmg": 8, "lmg": 8,
        "st": 4, "l": 4, "sty": 4, "ly": 4,
        "sth": 2, "lh": 2, "lhy": 2,
        "stc": 1, "lc": 1,
    },
    "riscv": {
        "sd": 8, "ld": 8,
        "sw": 4, "lw": 4,
        "sh": 2, "lh": 2, "lhu": 2,
        "sb": 1, "lb": 1, "lbu": 1,
    },
    "ppc": {
        "std": 8, "ld": 8, "stdu": 8,
        "stw": 4, "lwz": 4, "lwzu": 4, "stwu": 4,
        "sth": 2, "lhz": 2, "lha": 2,
        "stb": 1, "lbz": 1,
    },
    "arm": {
        "stp": 8, "ldp": 8,
        "str": 8, "ldr": 8, "stur": 8, "ldur": 8,
        "strw": 4, "ldrw": 4, "ldrsw": 4,
        "strh": 2, "ldrh": 2, "ldrsh": 2,
        "strb": 1, "ldrb": 1, "ldrsb": 1,
    },
}


# ============================================================================
# Stack Handler Base Class Architecture
# ============================================================================

class StackHandler(object):
    """
    Abstract base class for architecture-specific stack analysis handlers.

    This class defines the standard interface that all architecture handlers
    must implement. It provides common utilities and ensures consistent
    behavior across different architectures.

    To add a new architecture:
    1. Create a subclass (e.g., MipsStackHandler)
    2. Implement handle_instruction() method
    3. Register in get_stack_handler() factory function
    4. Add instruction size mappings to INSTRUCTION_SIZES if needed

    Example:
        class MyArchHandler(StackHandler):
            def handle_instruction(self, words, result_str):
                opcode = words[2] if len(words) > 2 else ""
                if opcode == "addi":
                    return self._handle_sp_adjust(words, result_str)
                return result_str
    """

    def __init__(self, arch_name):
        """
        Initialize handler for specific architecture.

        Args:
            arch_name: Architecture identifier (e.g., "riscv", "x86_64")
        """
        self.arch_name = arch_name
        self.arch_family = get_arch_family(arch_name)

    def handle_instruction(self, words, result_str):
        """
        Process a single disassembled instruction for stack operations.

        This is the main entry point called by the analysis engine.
        Subclasses must override this method to implement architecture-
        specific instruction handling.

        Args:
            words: List of instruction tokens [address, ":", opcode, operands]
                   Example: ["0xffffffff81234567", ":", "mov", "%rsp,%rbp"]
            result_str: Current analysis result string (may have annotations)

        Returns:
            str: Updated result_str with stack annotations appended
        """
        raise NotImplementedError("Subclasses must implement handle_instruction()")

    # ========================================================================
    # Common utility methods - available to all subclasses
    # ========================================================================

    def has_stack_pointer(self):
        """Check if stack pointer is initialized in register tracking."""
        return REG_STACK_POINTER in register_dict

    def has_frame_pointer(self):
        """Check if frame pointer is initialized in register tracking."""
        return REG_FRAME_POINTER in register_dict

    def get_sp_addresses(self):
        """Get current stack pointer address list."""
        return register_dict.get(REG_STACK_POINTER, [])

    def get_fp_addresses(self):
        """Get current frame pointer address list."""
        return register_dict.get(REG_FRAME_POINTER, [])

    def update_sp(self, offset, debug_msg=None):
        """
        Update stack pointer by applying offset to all tracked addresses.

        Args:
            offset: Integer offset to add to each stack address
            debug_msg: Optional debug message to log

        Returns:
            list: Updated stack address list
        """
        return update_register_tracking(REG_STACK_POINTER, offset, debug_msg)

    def update_fp(self, offset, debug_msg=None):
        """Update frame pointer by applying offset."""
        return update_register_tracking(REG_FRAME_POINTER, offset, debug_msg)

    def set_sp(self, address_list):
        """Set stack pointer to specific address list (creates independent copy)."""
        register_dict[REG_STACK_POINTER] = list(address_list)

    def set_fp(self, address_list):
        """Set frame pointer to specific address list (creates independent copy)."""
        register_dict[REG_FRAME_POINTER] = list(address_list)

    def copy_sp_to_fp(self):
        """Snapshot stack pointer to frame pointer (frame setup).
        Creates a TRUE INDEPENDENT COPY - FP value is frozen and does NOT
        change when SP is later modified via sub/add/push/pop.
        SP contains entry_rsp from set_stack_data; FP = entry_rsp - (cur_count * stack_unit)."""
        if self.has_stack_pointer():
            sp_addrs = list(register_dict[REG_STACK_POINTER])
            register_dict[REG_FRAME_POINTER] = [
                addr - (cur_count * stack_unit)
                for addr in sp_addrs
            ]
            if stack_debug_enabled:
                add_stack_debug("copy_sp_to_fp: entry_rsp=%s cur_count=%d => fp=%s" % (
                    ",".join("0x%x" % a for a in sp_addrs),
                    cur_count,
                    ",".join("0x%x" % a for a in register_dict[REG_FRAME_POINTER])))

    def copy_fp_to_sp(self):
        """Copy frame pointer addresses to stack pointer (frame teardown).
        Creates independent copy so FP snapshot is not affected."""
        if self.has_frame_pointer():
            register_dict[REG_STACK_POINTER] = [
                addr for addr in register_dict[REG_FRAME_POINTER]
            ]

    def format_sp_data(self, offset, data_size, prefix="    ; "):
        """
        Format stack data at SP + offset.

        Args:
            offset: Byte offset from stack pointer
            data_size: Size of data to read (1, 2, 4, or 8 bytes)
            prefix: String prefix for output

        Returns:
            str: Formatted stack data string or empty string if no SP
        """
        if not self.has_stack_pointer():
            return ""
        return format_stack_data(self.get_sp_addresses(), offset, data_size, prefix)

    def format_fp_data(self, offset, data_size, prefix="    ; "):
        """Format stack data at FP + offset."""
        if not self.has_frame_pointer():
            return ""
        fp_addrs = self.get_fp_addresses()
        if stack_debug_enabled and fp_addrs:
            for a in fp_addrs:
                read_addr = a + offset
                add_stack_debug("format_fp_data: FP=0x%x offset=%d read_addr=0x%x size=%d" %
                                (a, offset, read_addr, data_size))
        return format_stack_data(fp_addrs, offset, data_size, prefix)

    def get_instruction_size(self, opcode, default_size=None):
        """
        Get data size for an instruction opcode.

        Args:
            opcode: Instruction opcode (e.g., "sd", "lw")
            default_size: Default size if opcode not found

        Returns:
            int: Data size in bytes, or default_size if not found
        """
        return get_instruction_data_size(opcode, self.arch_name, default_size)

    def add_debug(self, msg):
        """Add debug message if debugging enabled."""
        if stack_debug_enabled:
            add_stack_debug(msg)

    # ========================================================================
    # Register alias tracking - for mov %rsp,%reg patterns
    # ========================================================================

    def set_register_alias(self, reg_name, source_addresses):
        """Create register snapshot: register holds a frozen copy of current SP value.
        The snapshot is an independent copy that does NOT change when SP changes.
        Adjusts for pushes tracked via cur_count."""
        register_aliases[reg_name] = True
        register_dict[reg_name] = [
            addr - (cur_count * stack_unit)
            for addr in list(source_addresses)
        ]

    def invalidate_register_alias(self, reg_name):
        """Remove alias when register gets a new value."""
        if reg_name in register_aliases:
            del register_aliases[reg_name]
        if reg_name in register_dict and reg_name not in (REG_STACK_POINTER, REG_FRAME_POINTER):
            del register_dict[reg_name]

    def is_aliased_register(self, reg_name):
        """Check if a register is currently aliased to SP."""
        return reg_name in register_aliases

    def get_aliased_addresses(self, reg_name):
        """Get tracked addresses for an aliased register."""
        return register_dict.get(reg_name, [])


# ============================================================================
# Concrete Handler Implementations
# ============================================================================

class RiscVStackHandler(StackHandler):
    """
    RISC-V architecture stack handler.

    Handles RISC-V stack operations including:
    - Stack pointer adjustments: addi sp, sp, -32
    - Frame pointer setup: mv s0, sp
    - Store operations: sd/sw/sh/sb reg, offset(sp)
    - Load operations: ld/lw/lh/lb reg, offset(sp)
    - Frame-based access: ld reg, offset(s0)

    Register naming conventions:
    - sp: Stack pointer
    - s0/fp/x8: Frame pointer (all aliases for same register)
    - ra: Return address
    """

    def __init__(self):
        super(RiscVStackHandler, self).__init__("riscv")

        # RISC-V specific register patterns
        self.sp_patterns = ("sp",)
        self.fp_patterns = ("s0", "fp", "x8")

    def handle_instruction(self, words, result_str):
        """Process RISC-V instruction for stack operations."""

        if not self.has_stack_pointer():
            return result_str

        if len(words) < 3:
            return result_str

        opcode = words[2]
        operands = words[3] if len(words) > 3 else ""

        # Dispatch to specific handlers based on opcode
        if opcode == "addi":
            return self._handle_sp_adjust(words, operands, result_str)
        elif opcode == "mv":
            return self._handle_move(words, operands, result_str)
        elif opcode in ("sd", "sw", "sh", "sb"):
            return self._handle_store(words, opcode, operands, result_str)
        elif opcode in ("ld", "lw", "lh", "lhu", "lb", "lbu"):
            return self._handle_load(words, opcode, operands, result_str)
        else:
            # Check for frame pointer based operations
            return self._handle_frame_access(words, operands, result_str)

    def _handle_sp_adjust(self, words, operands, result_str):
        """Handle stack pointer adjustment: addi sp, sp, -32"""
        if not operands.startswith("sp,sp,"):
            return result_str

        # Extract offset: sp,sp,-32 -> -32
        offset_str = operands.split(",")[-1]
        offset = parse_offset(offset_str)

        self.update_sp(offset, "sp update: sp += %d => %s" %
                       (offset, ",".join(["0x%x" % a for a in self.get_sp_addresses()])))

        return result_str

    def _handle_move(self, words, operands, result_str):
        """Handle register moves: mv s0, sp"""
        if operands in ("s0,sp", "fp,sp"):
            # Frame pointer setup - copy SP to FP
            self.copy_sp_to_fp()
            self.add_debug("FP setup: s0 = sp")

        return result_str

    def _handle_store(self, words, opcode, operands, result_str):
        """Handle store operations: sd ra, 24(sp)"""
        if "(sp)" not in operands:
            return result_str

        # Extract offset from format: reg, 24(sp)
        offset, found = extract_mem_offset(operands, "sp")
        if not found:
            return result_str

        # Get data size from opcode
        data_size = self.get_instruction_size(opcode)
        if data_size is None:
            return result_str

        return result_str + self.format_sp_data(offset, data_size)

    def _handle_load(self, words, opcode, operands, result_str):
        """Handle load operations: ld ra, 24(sp)"""
        if "(sp)" not in operands:
            return result_str

        # Extract offset from format: reg, 24(sp)
        offset, found = extract_mem_offset(operands, "sp")
        if not found:
            return result_str

        # Get data size from opcode
        data_size = self.get_instruction_size(opcode)
        if data_size is None:
            return result_str

        return result_str + self.format_sp_data(offset, data_size)

    def _handle_frame_access(self, words, operands, result_str):
        """Handle frame pointer based access: ld a0, 16(s0)"""
        if not self.has_frame_pointer():
            return result_str

        # Check for any frame pointer pattern
        for fp_reg in self.fp_patterns:
            pattern = "(%s)" % fp_reg
            if pattern in operands:
                offset, found = extract_mem_offset(operands, fp_reg)
                if found:
                    # Use stack_unit as data size for frame access
                    return result_str + self.format_fp_data(offset, stack_unit)

        return result_str


class X86StackHandler(StackHandler):
    """
    x86/x86_64 architecture stack handler.

    Handles x86 stack operations including:
    - Frame pointer setup: mov %rsp,%rbp
    - Stack allocation: sub $N,%rsp
    - Stack cleanup: add $N,%rsp
    - Push/pop operations: push/pop %reg
    - Enter/leave instructions
    - Memory access: mov offset(%rsp), mov offset(%rbp)

    Register naming conventions:
    - %rsp: Stack pointer
    - %rbp: Frame pointer (base pointer)
    """

    def __init__(self):
        super(X86StackHandler, self).__init__("x86")

        # x86 specific register patterns
        self.sp_patterns = ("%rsp", "%esp")
        self.fp_patterns = ("%rbp", "%ebp")

    def handle_instruction(self, words, result_str):
        """Process x86 instruction for stack operations."""

        if not self.has_stack_pointer():
            return result_str

        if len(words) < 3:
            return result_str

        opcode = words[2]
        operands = words[3] if len(words) > 3 else ""

        # Debug: capture FP state BEFORE any processing
        fp_before = list(register_dict.get(REG_FRAME_POINTER, []))
        has_fp_before = REG_FRAME_POINTER in register_dict

        # Pre-dispatch: invalidate aliases when register gets a new value
        self._check_alias_invalidation(words)

        # Debug: check if alias invalidation changed FP
        if stack_debug_enabled and has_fp_before and REG_FRAME_POINTER not in register_dict:
            self.add_debug("BUG TRACE at %s (%s %s): FP CLEARED by _check_alias_invalidation! was=%s" % (
                words[0], opcode, operands,
                ",".join("0x%x" % a for a in fp_before)))

        # Dispatch to specific handlers
        handler_names = [
            ("_handle_frame_setup", lambda: self._handle_frame_setup(words, result_str)),
            ("_handle_stack_alloc", lambda: self._handle_stack_alloc(words, result_str)),
            ("_handle_stack_cleanup", lambda: self._handle_stack_cleanup(words, result_str)),
            ("_handle_pop", lambda: self._handle_pop(words, result_str)),
            ("_handle_enter", lambda: self._handle_enter(words, result_str)),
            ("_handle_leave", lambda: self._handle_leave(words, result_str)),
            ("_handle_frame_access", lambda: self._handle_frame_access(words, result_str)),
            ("_handle_sp_access", lambda: self._handle_sp_access(words, result_str)),
            ("_handle_alias_access", lambda: self._handle_alias_access(words, result_str)),
        ]

        for handler_name, handler in handler_names:
            result_str, handled = handler()
            if handled:
                # Debug: check if this handler changed FP
                if stack_debug_enabled and has_fp_before and REG_FRAME_POINTER not in register_dict:
                    self.add_debug("BUG TRACE at %s (%s %s): FP CLEARED by %s! was=%s" % (
                        words[0], opcode, operands, handler_name,
                        ",".join("0x%x" % a for a in fp_before)))
                return result_str

        # If not handled by specific handlers, show generic equation for mov with memory
        self._show_generic_mov_equation(words, opcode, operands)

        # Debug: check if unhandled instruction cleared FP
        if stack_debug_enabled and has_fp_before and REG_FRAME_POINTER not in register_dict:
            self.add_debug("BUG TRACE at %s (%s %s): FP CLEARED by unhandled path! was=%s" % (
                words[0], opcode, operands,
                ",".join("0x%x" % a for a in fp_before)))

        return result_str

    def _check_alias_invalidation(self, words):
        """Invalidate register aliases when the register gets a new non-SP value."""
        if not register_aliases or len(words) < 4:
            return

        opcode = words[2]
        operands = words[3]

        if opcode in ("mov", "movq", "movl", "movabs"):
            parts = operands.split(",")
            if len(parts) == 2:
                src = parts[0].strip()
                dst = parts[1].strip()
                if src not in self.sp_patterns and dst in register_aliases:
                    self.invalidate_register_alias(dst)
                    self.add_debug("Alias invalidated: %s (overwritten by %s)" % (dst, src))

        elif opcode == "xor":
            parts = operands.split(",")
            if len(parts) == 2 and parts[0].strip() == parts[1].strip():
                dst = parts[1].strip()
                if dst in register_aliases:
                    self.invalidate_register_alias(dst)
                    self.add_debug("Alias invalidated: %s (xor zeroed)" % dst)

        elif opcode in ("pop", "popq"):
            reg = operands.strip()
            if reg in register_aliases:
                self.invalidate_register_alias(reg)
                self.add_debug("Alias invalidated: %s (pop)" % reg)

        elif opcode == "lea":
            parts = operands.split(",")
            if len(parts) == 2:
                dst = parts[1].strip()
                if dst in register_aliases:
                    self.invalidate_register_alias(dst)
                    self.add_debug("Alias invalidated: %s (lea)" % dst)

        elif opcode in ("add", "sub", "addq", "subq"):
            parts = operands.split(",")
            if len(parts) == 2:
                dst = parts[1].strip()
                if dst in register_aliases:
                    self.invalidate_register_alias(dst)
                    self.add_debug("Alias invalidated: %s (arithmetic)" % dst)

    def _handle_frame_setup(self, words, result_str):
        """Handle SP snapshot: mov %rsp,%rbp or mov %rsp,%r13 etc.
        Creates an independent snapshot - destination register value is frozen
        at the time of the mov and does NOT change when %rsp changes later."""
        if words[2] not in ("mov", "movq"):
            return result_str, False

        parts = words[3].split(",")
        if len(parts) != 2:
            return result_str, False

        src = parts[0].strip()
        dst = parts[1].strip()

        if src not in self.sp_patterns:
            return result_str, False

        if dst in self.fp_patterns:
            # Frame pointer: use dedicated FP snapshot mechanism.
            # Do NOT add to register_aliases - FP is handled independently
            # by _handle_frame_access and must remain a frozen snapshot.
            self.copy_sp_to_fp()
            self.add_debug("FP snapshot: rbp = rsp (frozen, independent)")
        elif self.has_stack_pointer():
            # Non-FP register (e.g., %r13): create independent register snapshot
            self.set_register_alias(dst, self.get_sp_addresses())
            self.add_debug("Register snapshot: %s = rsp (frozen)" % dst)

        return result_str, True

    def _handle_alias_access(self, words, result_str):
        """Handle memory access via aliased register: mov -0x38(%r13),%rax"""
        if len(words) < 4 or not register_aliases:
            return result_str, False

        operands = words[3]
        for reg_name in list(register_aliases.keys()):
            pattern = "(%s)" % reg_name
            if pattern in operands:
                parts = operands.split(",")
                for part in parts:
                    if pattern in part:
                        offset_str = part.split("(")[0]
                        offset = parse_offset(offset_str)
                        addr_list = register_dict.get(reg_name, [])
                        if addr_list:
                            if words[2] != "lea":
                                data_size = get_x86_operand_data_size(words, stack_unit)
                                result_str += format_stack_data(addr_list, offset, data_size)
                            else:
                                result_str += format_lea_addresses(addr_list, offset)
                        return result_str, True
        return result_str, False

    def _handle_stack_alloc(self, words, result_str):
        """Handle stack allocation: sub $128,%rsp"""
        if words[2] == "sub" and len(words) >= 4:
            parts = words[3].split(",")
            if len(parts) == 2 and parts[1] in ("%rsp", "%esp"):
                offset_str = parts[0]
                offset = -parse_offset(offset_str)  # sub means negative
                self.update_sp(offset, "Stack alloc: rsp -= %d" % abs(offset))
                return result_str, True
        return result_str, False

    def _handle_stack_cleanup(self, words, result_str):
        """Handle stack cleanup: add $128,%rsp"""
        if words[2] == "add" and len(words) >= 4:
            parts = words[3].split(",")
            if len(parts) == 2 and parts[1] in ("%rsp", "%esp"):
                offset_str = parts[0]
                offset = parse_offset(offset_str)  # add means positive
                self.update_sp(offset, "Stack cleanup: rsp += %d" % offset)
                return result_str, True
        return result_str, False

    def _handle_pop(self, words, result_str):
        """Handle pop instruction: pop %rbx"""
        if words[2] == "pop":
            self.update_sp(stack_unit, "Pop: rsp += %d" % stack_unit)
            if stack_debug_enabled and len(words) > 3:
                popped_reg = words[3].strip()
                if popped_reg in ("%rbp", "%ebp"):
                    self.add_debug("Pop %s at %s: has_fp=%s (pop does NOT clear FP tracking)" % (
                        popped_reg, words[0], self.has_frame_pointer()))
            return result_str, True
        return result_str, False

    def _handle_enter(self, words, result_str):
        """Handle enter instruction: enter $0x20,$0x0"""
        if words[2] == "enter" and len(words) >= 4:
            parts = words[3].split(",")
            if len(parts) >= 1:
                alloc_str = parts[0]
                alloc_size = parse_offset(alloc_str)

                # enter pushes rbp and allocates space
                # Simulated as: push rbp; mov rsp, rbp; sub alloc_size, rsp
                self.update_sp(-stack_unit)  # push rbp
                self.copy_sp_to_fp()          # mov rsp, rbp
                self.update_sp(-alloc_size)   # sub alloc_size, rsp

                self.add_debug("Enter: alloc %d bytes" % alloc_size)
                return result_str, True
        return result_str, False

    def _handle_leave(self, words, result_str):
        """Handle leave instruction: leave"""
        if words[2] == "leave":
            # leave = mov rbp, rsp; pop rbp
            old_sp = list(self.get_sp_addresses()) if self.has_stack_pointer() else []
            self.copy_fp_to_sp()
            self.update_sp(stack_unit)
            new_sp = list(self.get_sp_addresses()) if self.has_stack_pointer() else []
            self.add_debug("Leave at %s: rsp %s => %s (fp unchanged: %s)" % (
                words[0],
                ",".join("0x%x" % a for a in old_sp) if old_sp else "NONE",
                ",".join("0x%x" % a for a in new_sp) if new_sp else "NONE",
                ",".join("0x%x" % a for a in self.get_fp_addresses()) if self.has_frame_pointer() else "NONE"))
            return result_str, True
        return result_str, False

    def _handle_frame_access(self, words, result_str):
        """Handle frame pointer access: mov -0x10(%rbp),%rax"""
        if len(words) >= 4 and ("(%rbp)" in words[3] or "(%ebp)" in words[3]):
            parts = words[3].split(",")
            for part in parts:
                if "(%rbp)" in part or "(%ebp)" in part:
                    offset_str = part.split("(")[0]
                    offset = parse_offset(offset_str)
                    fp_addrs = self.get_fp_addresses()
                    self.add_debug("frame_access at %s: offset=%d fp_addrs=%s has_fp=%s read_addr=%s" % (
                        words[0], offset,
                        ",".join("0x%x" % a for a in fp_addrs) if fp_addrs else "EMPTY",
                        self.has_frame_pointer(),
                        ",".join("0x%x" % (a + offset) for a in fp_addrs) if fp_addrs else "N/A"))

                    if words[2] != "lea":
                        data_size = get_x86_operand_data_size(words, stack_unit)
                        fp_result = self.format_fp_data(offset, data_size)
                        if not fp_result and stack_debug_enabled:
                            self.add_debug("frame_access: NO VALUE - fp_data returned empty")
                        result_str = result_str + fp_result
                    else:
                        result_str += format_lea_addresses(fp_addrs, offset)
                    return result_str, True
        return result_str, False

    def _handle_sp_access(self, words, result_str):
        """Handle stack pointer access: mov 0x8(%rsp),%rax"""
        if len(words) >= 4 and ("(%rsp)" in words[3] or "(%esp)" in words[3]):
            parts = words[3].split(",")
            for part in parts:
                if "(%rsp)" in part or "(%esp)" in part:
                    offset_str = part.split("(")[0]
                    offset = parse_offset(offset_str)

                    if words[2] != "lea":
                        data_size = get_x86_operand_data_size(words, stack_unit)
                        result_str = result_str + self.format_sp_data(offset, data_size)
                    else:
                        result_str += format_lea_addresses(self.get_sp_addresses(), offset)
                    return result_str, True
        return result_str, False

    def _show_generic_mov_equation(self, words, opcode, operands):
        """
        Show detailed equation for any mov instruction with memory operands.
        This shows the data size, operation, and addressing mode.
        """
        # Only show for mov instructions with memory operands
        if not opcode.startswith("mov"):
            return

        if len(words) < 4:
            return

        # Parse operands
        ops = [o.strip() for o in operands.split(",") if o.strip()]
        if len(ops) < 2:
            return

        src = ops[0]
        dst = ops[1]

        # Check if this involves memory (has parentheses for addressing)
        has_memory = "(" in src or ")" in src or "(" in dst or ")" in dst
        if not has_memory:
            return

        # Determine data size and operation type from opcode
        size_info = ""
        operation = ""
        data_bytes = 0

        if opcode == "movzwl":
            size_info = "16-bit word (2 bytes)"
            operation = "zero-extend to 32-bit"
            data_bytes = 2
        elif opcode == "movzbl":
            size_info = "8-bit byte (1 byte)"
            operation = "zero-extend to 32-bit"
            data_bytes = 1
        elif opcode == "movzbq":
            size_info = "8-bit byte (1 byte)"
            operation = "zero-extend to 64-bit"
            data_bytes = 1
        elif opcode == "movzwq":
            size_info = "16-bit word (2 bytes)"
            operation = "zero-extend to 64-bit"
            data_bytes = 2
        elif opcode == "movsbl":
            size_info = "8-bit byte (1 byte)"
            operation = "sign-extend to 32-bit"
            data_bytes = 1
        elif opcode == "movswl":
            size_info = "16-bit word (2 bytes)"
            operation = "sign-extend to 32-bit"
            data_bytes = 2
        elif opcode == "movsbq":
            size_info = "8-bit byte (1 byte)"
            operation = "sign-extend to 64-bit"
            data_bytes = 1
        elif opcode == "movswq":
            size_info = "16-bit word (2 bytes)"
            operation = "sign-extend to 64-bit"
            data_bytes = 2
        elif opcode == "movslq" or opcode == "movsx":
            size_info = "32-bit long (4 bytes)"
            operation = "sign-extend to 64-bit"
            data_bytes = 4
        elif opcode == "movq":
            size_info = "64-bit quadword (8 bytes)"
            operation = "direct move"
            data_bytes = 8
        elif opcode == "movl":
            size_info = "32-bit long (4 bytes)"
            operation = "direct move"
            data_bytes = 4
        elif opcode == "movw":
            size_info = "16-bit word (2 bytes)"
            operation = "direct move"
            data_bytes = 2
        elif opcode == "movb":
            size_info = "8-bit byte (1 byte)"
            operation = "direct move"
            data_bytes = 1
        else:
            # Generic mov
            size_info = "word size"
            operation = "direct move"
            data_bytes = stack_unit

        # Parse memory addressing
        if "(" in src:
            # Memory read: mov (%rdx),%eax or mov 0x10(%rdx),%eax
            self.add_debug("x86 %s: Memory read" % opcode)
            self.add_debug("  Operation: %s" % operation)
            self.add_debug("  Data size: %s" % size_info)

            # Extract base register and offset
            import re
            match = re.match(r'([-0-9a-fx]*)\(([%a-z0-9]+)\)', src)
            if match:
                offset_str = match.group(1)
                base_reg = match.group(2)
                offset = parse_offset(offset_str) if offset_str else 0

                if offset == 0:
                    equation = "%s = memory[%s]" % (dst, base_reg)
                    self.add_debug("  Equation: %s" % equation)
                    self.add_debug("  Read from: [%s] -> %s" % (base_reg, dst))
                else:
                    equation = "%s = memory[%s %+d]" % (dst, base_reg, offset)
                    self.add_debug("  Equation: %s" % equation)
                    self.add_debug("  Read from: [%s %+d] -> %s" % (base_reg, offset, dst))
            else:
                self.add_debug("  Source: %s -> %s" % (src, dst))

        elif "(" in dst:
            # Memory write: mov %eax,(%rdx) or mov %eax,0x10(%rdx)
            self.add_debug("x86 %s: Memory write" % opcode)
            self.add_debug("  Operation: %s" % operation)
            self.add_debug("  Data size: %s" % size_info)

            # Extract base register and offset
            import re
            match = re.match(r'([-0-9a-fx]*)\(([%a-z0-9]+)\)', dst)
            if match:
                offset_str = match.group(1)
                base_reg = match.group(2)
                offset = parse_offset(offset_str) if offset_str else 0

                if offset == 0:
                    equation = "memory[%s] = %s" % (base_reg, src)
                    self.add_debug("  Equation: %s" % equation)
                    self.add_debug("  Write to: %s -> [%s]" % (src, base_reg))
                else:
                    equation = "memory[%s %+d] = %s" % (base_reg, offset, src)
                    self.add_debug("  Equation: %s" % equation)
                    self.add_debug("  Write to: %s -> [%s %+d]" % (src, base_reg, offset))
            else:
                self.add_debug("  Destination: %s -> %s" % (src, dst))


class ArmStackHandler(StackHandler):
    """
    ARM/AArch64 architecture stack handler.

    Handles ARM stack operations including:
    - Frame pointer setup: stp x29, x30, [sp,#-N]! or mov x29, sp
    - Stack pointer adjustments: sub sp, sp, #N
    - Pair operations: stp/ldp x29, x30, [sp,#N]
    - Single operations: str/ldr xN, [sp,#N]
    - Frame access: ldr x0, [x29,#N]

    Register naming conventions:
    - sp: Stack pointer
    - x29/fp: Frame pointer
    - x30/lr: Link register (return address)
    """

    def __init__(self):
        super(ArmStackHandler, self).__init__("arm")

        # ARM specific register patterns
        self.sp_patterns = ("sp",)
        self.fp_patterns = ("x29", "fp")

    def handle_instruction(self, words, result_str):
        """Process ARM instruction for stack operations."""

        if not self.has_stack_pointer():
            return result_str

        if len(words) < 3:
            return result_str

        opcode = words[2]
        operands = "".join(words[3:]) if len(words) > 3 else ""

        # Dispatch to specific handlers
        handlers = [
            lambda: self._handle_frame_pointer_setup(words, result_str),
            lambda: self._handle_sp_from_fp(words, result_str),
            lambda: self._handle_sp_adjustment(words, result_str),
            lambda: self._handle_store_pair(words, result_str),
            lambda: self._handle_load_pair(words, result_str),
            lambda: self._handle_store_single(words, opcode, operands, result_str),
            lambda: self._handle_load_single(words, opcode, operands, result_str),
            lambda: self._handle_frame_access(words, result_str),
        ]

        for handler in handlers:
            result_str, handled = handler()
            if handled:
                return result_str

        # If not handled by specific handlers, show generic equation for ldr/str
        self._show_generic_load_store_equation(words, opcode, operands)

        return result_str

    def _handle_frame_pointer_setup(self, words, result_str):
        """Handle frame pointer setup: stp x29, x30, [sp,#-64]! or mov x29, sp"""
        opcode = words[2]

        # Method 1: stp x29, x30, [sp,#-N]! (push FP and LR, update SP)
        if opcode == "stp" and len(words) >= 5:
            if words[3].startswith("x29,") and words[4].startswith("x30,"):
                operands = "".join(words[5:])
                if "[sp" in operands and operands.endswith("]!"):
                    # Pre-decrement store pair - use parse_aarch64_mem_operand
                    mem_pos = operands.find("[sp")
                    mem_op = operands[mem_pos:]
                    base_reg, offset, writeback_pre, post_index = parse_aarch64_mem_operand(mem_op)

                    if base_reg == "sp":
                        self.update_sp(offset)
                        self.copy_sp_to_fp()
                        result_str = result_str + self.format_sp_data(0, stack_unit)
                        self.add_debug("FP setup: stp x29,x30 with sp update")
                        return result_str, True

        # Method 2: mov x29, sp (simple frame pointer setup)
        elif opcode in ("mov", "add") and len(words) >= 4:
            if words[3] == "x29,sp" or words[3].startswith("x29,sp,"):
                self.copy_sp_to_fp()
                self.add_debug("FP setup: x29 = sp")
                return result_str, True

        return result_str, False

    def _handle_sp_from_fp(self, words, result_str):
        """Handle SP restoration from FP: mov sp, x29"""
        if words[2] in ("mov", "add") and len(words) >= 4:
            if words[3] == "sp,x29" or words[3].startswith("sp,x29,"):
                self.copy_fp_to_sp()
                self.add_debug("SP restore: sp = x29")
                return result_str, True
        return result_str, False

    def _handle_sp_adjustment(self, words, result_str):
        """Handle stack pointer adjustment: sub sp, sp, #128 or add sp, sp, #128"""
        opcode = words[2]

        if opcode in ("sub", "add") and len(words) >= 4:
            if words[3].startswith("sp,sp,"):
                offset_str = words[3].split(",")[-1]
                offset = parse_offset(offset_str)

                # sub decreases SP (negative), add increases SP (positive)
                if opcode == "sub":
                    self.add_debug("ARM sub: Stack allocation sp,sp,#%d" % abs(offset))
                    self.add_debug("  Allocate %d bytes: sp = sp - %d" % (abs(offset), abs(offset)))
                    offset = -offset
                else:
                    self.add_debug("ARM add: Stack deallocation sp,sp,#%d" % offset)
                    self.add_debug("  Free %d bytes: sp = sp + %d" % (offset, offset))

                self.update_sp(offset, "SP adjust: sp %s %d => %s" % (
                    "+=" if offset >= 0 else "-=", abs(offset),
                    ",".join(["0x%x" % a for a in self.get_sp_addresses()])))
                return result_str, True

        return result_str, False

    def _handle_store_pair(self, words, result_str):
        """Handle store pair: stp x19, x20, [sp,#16]"""
        if words[2] != "stp" or len(words) < 5:
            return result_str, False

        # Extract register names
        reg1 = words[3].rstrip(",") if len(words) > 3 else None
        reg2 = words[4].rstrip(",") if len(words) > 4 else None

        # Look for [sp in remaining words
        operands = "".join(words[5:])
        if "[sp" not in operands:
            return result_str, False

        mem_pos = operands.find("[sp")
        mem_op = operands[mem_pos:]
        base_reg, offset, writeback_pre, post_index = parse_aarch64_mem_operand(mem_op)

        if base_reg != "sp":
            return result_str, False

        # Add detailed debug output for -D flag
        if writeback_pre:
            # Pre-index: [sp,#-N]! - update SP first, then store to new SP
            self.add_debug("ARM stp: Pre-index writeback [sp,#%d]!" % offset)
            self.add_debug("  Step 1: Update SP: sp = sp + %d" % offset)
            self.update_sp(offset, "sp writeback(pre): sp <- sp %+d => %s" %
                          (offset, ",".join(["0x%x" % a for a in self.get_sp_addresses()])))
            self.add_debug("  Step 2: Store pair %s,%s to new SP+0 and SP+%d" %
                          (reg1 if reg1 else "?", reg2 if reg2 else "?", stack_unit))
            access_offset = 0
        else:
            # Normal offset: [sp,#N] - store to SP+offset, no SP update
            self.add_debug("ARM stp: Normal offset [sp,#%d]" % offset)
            self.add_debug("  Store pair %s,%s to SP+%d and SP+%d" %
                          (reg1 if reg1 else "?", reg2 if reg2 else "?",
                           offset, offset + stack_unit))
            access_offset = offset

        result_str = result_str + format_stack_data_pair(
            self.get_sp_addresses(), access_offset, stack_unit, reg1=reg1, reg2=reg2)

        if post_index:
            # Post-index: [sp],#N - store to current SP, then update SP
            self.add_debug("ARM stp: Post-index writeback [sp],#%d" % offset)
            self.add_debug("  Step 1: Store pair completed to SP+0 and SP+%d" % stack_unit)
            self.add_debug("  Step 2: Update SP: sp = sp + %d" % offset)
            self.update_sp(offset, "sp writeback(post): sp <- sp %+d => %s" %
                          (offset, ",".join(["0x%x" % a for a in self.get_sp_addresses()])))

        return result_str, True

    def _handle_load_pair(self, words, result_str):
        """Handle load pair: ldp x19, x20, [sp,#16]"""
        if words[2] != "ldp" or len(words) < 5:
            return result_str, False

        # Extract register names
        reg1 = words[3].rstrip(",") if len(words) > 3 else None
        reg2 = words[4].rstrip(",") if len(words) > 4 else None

        # Look for [sp in remaining words
        operands = "".join(words[5:])
        if "[sp" not in operands:
            return result_str, False

        mem_pos = operands.find("[sp")
        mem_op = operands[mem_pos:]
        base_reg, offset, writeback_pre, post_index = parse_aarch64_mem_operand(mem_op)

        if base_reg != "sp":
            return result_str, False

        # Add detailed debug output for -D flag
        if writeback_pre:
            self.add_debug("ARM ldp: Pre-index writeback [sp,#%d]!" % offset)
            self.add_debug("  Step 1: Update SP: sp = sp + %d" % offset)
            self.update_sp(offset, "sp writeback(pre): sp <- sp %+d => %s" %
                          (offset, ",".join(["0x%x" % a for a in self.get_sp_addresses()])))
            self.add_debug("  Step 2: Load pair from new SP+0 into %s,%s" %
                          (reg1 if reg1 else "?", reg2 if reg2 else "?"))
            access_offset = 0
        else:
            self.add_debug("ARM ldp: Normal offset [sp,#%d]" % offset)
            self.add_debug("  Load pair from SP+%d and SP+%d into %s,%s" %
                          (offset, offset + stack_unit,
                           reg1 if reg1 else "?", reg2 if reg2 else "?"))
            access_offset = offset

        result_str = result_str + format_stack_data_pair(
            self.get_sp_addresses(), access_offset, stack_unit, reg1=reg1, reg2=reg2)

        if post_index:
            self.add_debug("ARM ldp: Post-index writeback [sp],#%d" % offset)
            self.add_debug("  Step 1: Load pair completed from SP+0 and SP+%d" % stack_unit)
            self.add_debug("  Step 2: Update SP: sp = sp + %d" % offset)
            self.update_sp(offset, "sp writeback(post): sp <- sp %+d => %s" %
                          (offset, ",".join(["0x%x" % a for a in self.get_sp_addresses()])))

        return result_str, True

    def _handle_store_single(self, words, opcode, operands, result_str):
        """Handle single register store: str x19, [sp,#16]"""
        if opcode not in ("str", "stur", "strb", "strh", "strw"):
            return result_str, False

        reg_name = words[3].rstrip(",") if len(words) > 3 else None

        if "[sp" not in operands:
            return result_str, False

        mem_pos = operands.find("[sp")
        mem_op = operands[mem_pos:]
        base_reg, offset, writeback_pre, post_index = parse_aarch64_mem_operand(mem_op)

        if base_reg != "sp":
            return result_str, False

        # Determine data size
        data_size = self.get_instruction_size(opcode, stack_unit)

        # Add detailed debug output for -D flag
        if writeback_pre:
            # Pre-index: [sp,#offset]! - update SP first, then store to new SP
            self.add_debug("ARM %s: Pre-index writeback [sp,#%d]!" % (opcode, offset))
            self.add_debug("  Step 1: Update SP: sp = sp + %d" % offset)
            self.update_sp(offset, "sp writeback(pre): sp <- sp %+d => %s" %
                          (offset, ",".join(["0x%x" % a for a in self.get_sp_addresses()])))
            self.add_debug("  Step 2: Store %s to new SP+0" % (reg_name if reg_name else "register"))
            access_offset = 0
        else:
            # Normal offset: [sp,#offset] - store to SP+offset, no SP update
            self.add_debug("ARM %s: Normal offset [sp,#%d]" % (opcode, offset))
            self.add_debug("  Store %s to SP+%d (%s)" %
                          (reg_name if reg_name else "register",
                           offset,
                           "%+d" % offset if offset != 0 else "no offset"))
            access_offset = offset

        # Format and display the data (format_stack_data adds its own debug output)
        result_str = result_str + format_stack_data(
            self.get_sp_addresses(), access_offset, data_size, reg=reg_name)

        if post_index:
            # Post-index: [sp],#offset - store to current SP, then update SP
            self.add_debug("ARM %s: Post-index writeback [sp],#%d" % (opcode, offset))
            self.add_debug("  Step 1: Store completed to SP+0")
            self.add_debug("  Step 2: Update SP: sp = sp + %d" % offset)
            self.update_sp(offset, "sp writeback(post): sp <- sp %+d => %s" %
                          (offset, ",".join(["0x%x" % a for a in self.get_sp_addresses()])))

        return result_str, True

    def _handle_load_single(self, words, opcode, operands, result_str):
        """Handle single register load: ldr x19, [sp,#16]"""
        if opcode not in ("ldr", "ldur", "ldrb", "ldrh", "ldrw", "ldrsw", "ldrsh", "ldrsb"):
            return result_str, False

        reg_name = words[3].rstrip(",") if len(words) > 3 else None

        if "[sp" not in operands:
            return result_str, False

        mem_pos = operands.find("[sp")
        mem_op = operands[mem_pos:]
        base_reg, offset, writeback_pre, post_index = parse_aarch64_mem_operand(mem_op)

        if base_reg != "sp":
            return result_str, False

        # Determine data size
        data_size = self.get_instruction_size(opcode, stack_unit)

        # Add detailed debug output for -D flag
        if writeback_pre:
            # Pre-index: [sp,#offset]! - update SP first, then load from new SP
            self.add_debug("ARM %s: Pre-index writeback [sp,#%d]!" % (opcode, offset))
            self.add_debug("  Step 1: Update SP: sp = sp + %d" % offset)
            self.update_sp(offset, "sp writeback(pre): sp <- sp %+d => %s" %
                          (offset, ",".join(["0x%x" % a for a in self.get_sp_addresses()])))
            self.add_debug("  Step 2: Load from new SP+0 into %s" % (reg_name if reg_name else "register"))
            access_offset = 0
        else:
            # Normal offset: [sp,#offset] - load from SP+offset, no SP update
            self.add_debug("ARM %s: Normal offset [sp,#%d]" % (opcode, offset))
            self.add_debug("  Load from SP+%d (%s) into %s" %
                          (offset,
                           "%+d" % offset if offset != 0 else "no offset",
                           reg_name if reg_name else "register"))
            access_offset = offset

        # Format and read the data (format_stack_data adds its own debug output)
        result_str = result_str + format_stack_data(
            self.get_sp_addresses(), access_offset, data_size, reg=reg_name)

        if post_index:
            # Post-index: [sp],#offset - load from current SP, then update SP
            self.add_debug("ARM %s: Post-index writeback [sp],#%d" % (opcode, offset))
            self.add_debug("  Step 1: Load completed from SP+0")
            self.add_debug("  Step 2: Update SP: sp = sp + %d" % offset)
            self.update_sp(offset, "sp writeback(post): sp <- sp %+d => %s" %
                          (offset, ",".join(["0x%x" % a for a in self.get_sp_addresses()])))

        return result_str, True

    def _handle_frame_access(self, words, result_str):
        """Handle frame pointer access: ldr x0, [x29,#16]"""
        if len(words) < 4:
            return result_str, False

        opcode = words[2]
        reg_name = words[3].rstrip(",") if len(words) > 3 else None
        operands = "".join(words[3:])

        # Check for x29 or fp addressing
        if "[x29" in operands or "[fp" in operands:
            fp_reg = "x29" if "[x29" in operands else "fp"
            mem_pos = operands.find("[" + fp_reg)
            mem_op = operands[mem_pos:]
            base_reg, offset, writeback_pre, post_index = parse_aarch64_mem_operand(mem_op)

            if base_reg in ("x29", "fp"):
                self.add_debug("ARM %s: Frame pointer access [%s,#%d]" % (opcode, fp_reg, offset))
                self.add_debug("  Access via FP: x29+%d (%s) -> %s" %
                              (offset,
                               "%+d" % offset if offset != 0 else "no offset",
                               reg_name if reg_name else "register"))
                result_str = result_str + self.format_fp_data(offset, stack_unit)
                return result_str, True

        return result_str, False

    def _show_generic_load_store_equation(self, words, opcode, operands):
        """
        Show equation for any ldr/str instruction with any base register.
        This is called for instructions not handled by specific handlers.
        Only shows the mathematical expression, doesn't calculate values.
        """
        # Only show for load/store instructions
        if opcode not in ("ldr", "ldur", "ldrb", "ldrh", "ldrw", "ldrsw", "ldrsh", "ldrsb",
                          "str", "stur", "strb", "strh", "strw",
                          "ldp", "stp"):
            return

        if len(words) < 4:
            return

        # Get target/source register
        target_reg = words[3].rstrip(",") if len(words) > 3 else "?"

        # Parse memory operand to extract base register and offset
        # Look for [register pattern
        if "[" not in operands:
            return

        mem_start = operands.find("[")
        mem_end = operands.find("]")
        if mem_end == -1:
            mem_end = len(operands)

        mem_expr = operands[mem_start:mem_end+1]

        # Try to parse using parse_aarch64_mem_operand
        try:
            base_reg, offset, writeback_pre, post_index = parse_aarch64_mem_operand(mem_expr)
        except:
            # If parsing fails, try simple extraction
            import re
            match = re.search(r'\[([a-z0-9]+)', mem_expr)
            if match:
                base_reg = match.group(1)
                offset = 0
                writeback_pre = False
                post_index = False
            else:
                return

        # Determine data size
        data_size = self.get_instruction_size(opcode, stack_unit)
        if data_size is None:
            data_size = stack_unit

        # Determine if it's a pair operation
        is_pair = opcode in ("ldp", "stp")
        if is_pair and len(words) > 4:
            second_reg = words[4].rstrip(",")
        else:
            second_reg = None

        # Build the equation string
        if opcode.startswith("ldr") or opcode == "ldur":
            # Load operation
            operation = "Load"
            if is_pair:
                equation = "%s, %s = memory[%s + %d], memory[%s + %d]" % (
                    target_reg, second_reg if second_reg else "?",
                    base_reg, offset,
                    base_reg, offset + data_size)
            else:
                if offset == 0:
                    equation = "%s = memory[%s]" % (target_reg, base_reg)
                else:
                    equation = "%s = memory[%s %+d]" % (target_reg, base_reg, offset)
        else:
            # Store operation
            operation = "Store"
            if is_pair:
                equation = "memory[%s + %d], memory[%s + %d] = %s, %s" % (
                    base_reg, offset,
                    base_reg, offset + data_size,
                    target_reg, second_reg if second_reg else "?")
            else:
                if offset == 0:
                    equation = "memory[%s] = %s" % (base_reg, target_reg)
                else:
                    equation = "memory[%s %+d] = %s" % (base_reg, offset, target_reg)

        # Add debug output with the equation
        self.add_debug("ARM %s: Generic register [%s,#%d]" % (opcode, base_reg, offset))
        self.add_debug("  Equation: %s" % equation)
        self.add_debug("  Base register: %s (value not tracked)" % base_reg)
        self.add_debug("  Offset: %+d bytes" % offset)
        self.add_debug("  Data size: %d bytes" % data_size)

        if writeback_pre:
            self.add_debug("  Note: Pre-index writeback - %s updated before access" % base_reg)
        elif post_index:
            self.add_debug("  Note: Post-index writeback - %s updated after access" % base_reg)


class PpcStackHandler(StackHandler):
    """
    PPC/PPC64 architecture stack handler.

    Handles PowerPC stack operations including:
    - Stack pointer adjustments: addi r1, r1, -128
    - Store operations: std/stw/sth/stb rN, offset(r1)
    - Load operations: ld/lwz/lhz/lbz rN, offset(r1)
    - Store with update: stdu/stwu (updates r1)
    - Multiple register operations: stmw/lmw

    Register naming conventions:
    - r1: Stack pointer
    - r31: Frame pointer (by convention, not enforced)
    """

    def __init__(self):
        super(PpcStackHandler, self).__init__("ppc")

        # PPC specific register patterns
        self.sp_patterns = ("r1",)
        self.fp_patterns = ("r31",)

    def handle_instruction(self, words, result_str):
        """Process PPC instruction for stack operations."""

        if not self.has_stack_pointer():
            return result_str

        if len(words) < 3:
            return result_str

        opcode = words[2]
        operands = words[3] if len(words) > 3 else ""

        # Dispatch to specific handlers
        if opcode == "addi":
            return self._handle_sp_adjust(words, operands, result_str)
        elif opcode in ("std", "stw", "sth", "stb", "stdu", "stwu"):
            return self._handle_store(words, opcode, operands, result_str)
        elif opcode in ("ld", "lwz", "lwzu", "lhz", "lha", "lbz"):
            return self._handle_load(words, opcode, operands, result_str)
        elif opcode in ("stmw", "lmw"):
            return self._handle_multiple(words, opcode, operands, result_str)

        return result_str

    def _handle_sp_adjust(self, words, operands, result_str):
        """Handle stack pointer adjustment: addi r1, r1, -128"""
        if not operands.startswith("r1,r1,"):
            return result_str

        offset_str = operands.split(",")[-1]
        offset = parse_offset(offset_str)
        self.update_sp(offset, "sp update: r1 += %d" % offset)
        return result_str

    def _handle_store(self, words, opcode, operands, result_str):
        """Handle store operations: std r17, -120(r1)"""
        if "(r1)" not in operands:
            return result_str

        offset, found = extract_mem_offset(operands, "r1")
        if not found:
            return result_str

        # Determine data size
        data_size = self.get_instruction_size(opcode, stack_unit)
        if data_size is None:
            data_size = stack_unit

        result_str = result_str + self.format_sp_data(offset, data_size)

        # Handle update instructions (stdu, stwu)
        if opcode in ("stdu", "stwu"):
            # These instructions update r1 to the effective address
            op_words = operands.split(",")
            if op_words[0] == "r1":
                self.update_sp(offset, "sp update: %s updates r1 by %d" % (opcode, offset))

        return result_str

    def _handle_load(self, words, opcode, operands, result_str):
        """Handle load operations: ld r17, -120(r1)"""
        if "(r1)" not in operands:
            return result_str

        offset, found = extract_mem_offset(operands, "r1")
        if not found:
            return result_str

        # Determine data size
        data_size = self.get_instruction_size(opcode, stack_unit)
        if data_size is None:
            data_size = stack_unit

        result_str = result_str + self.format_sp_data(offset, data_size)
        return result_str

    def _handle_multiple(self, words, opcode, operands, result_str):
        """Handle multiple register operations: stmw r27, -20(r1)"""
        if "(r1)" not in operands:
            return result_str

        offset, found = extract_mem_offset(operands, "r1")
        if not found:
            return result_str

        # Multiple word operations (4 bytes each)
        result_str = result_str + self.format_sp_data(offset, 4)
        result_str = result_str + " ..."  # Indicate multiple registers
        return result_str


class S390xStackHandler(StackHandler):
    """
    s390x (IBM Z) architecture stack handler.

    Handles s390x stack operations including:
    - Stack pointer adjustments: aghi r15, -160 or lay r15, -160(r15)
    - Store operations: stg/st rN, offset(r15)
    - Load operations: lg/l rN, offset(r15)
    - Multiple register operations: stmg/lmg
    - Frame pointer operations: using r11 or r13

    Register naming conventions:
    - r15: Stack pointer
    - r11/r13: Frame pointer (by convention)
    """

    def __init__(self):
        super(S390xStackHandler, self).__init__("s390x")

        # s390x specific register patterns
        self.sp_patterns = ("r15",)
        self.fp_patterns = ("r11", "r13")

    def handle_instruction(self, words, result_str):
        """Process s390x instruction for stack operations."""

        if not self.has_stack_pointer():
            return result_str

        if len(words) < 3:
            return result_str

        opcode = words[2]
        operands = words[3] if len(words) > 3 else ""

        # Dispatch to specific handlers
        if opcode in ("aghi", "lay"):
            return self._handle_sp_adjust(words, opcode, operands, result_str)
        elif opcode in ("stg", "stmg", "st", "sty"):
            return self._handle_store(words, opcode, operands, result_str)
        elif opcode in ("lg", "lmg", "l", "ly"):
            return self._handle_load(words, opcode, operands, result_str)
        else:
            # Check for frame pointer operations
            return self._handle_frame_access(words, operands, result_str)

    def _handle_sp_adjust(self, words, opcode, operands, result_str):
        """Handle stack pointer adjustment: aghi r15, -160 or lay r15, -160(r15)"""
        if opcode == "aghi" and operands.startswith("r15,"):
            offset_str = operands.split(",")[-1]
            offset = parse_offset(offset_str)
            self.update_sp(offset, "sp update: r15 += %d" % offset)
            return result_str

        elif opcode == "lay" and operands.startswith("r15,") and "(r15)" in operands:
            # lay r15, -160(r15)
            offset_str = operands.split(",")[1].split("(")[0]
            offset = parse_offset(offset_str)
            self.update_sp(offset, "sp update: lay r15,%d(r15)" % offset)
            return result_str

        return result_str

    def _handle_store(self, words, opcode, operands, result_str):
        """Handle store operations: stg r14, 112(r15)"""
        if "(r15)" not in operands:
            return result_str

        offset, found = extract_mem_offset(operands, "r15")
        if not found:
            return result_str

        # Determine data size
        data_size = self.get_instruction_size(opcode)
        if data_size is None:
            data_size = stack_unit

        result_str = result_str + self.format_sp_data(offset, data_size)

        if opcode == "stmg":
            result_str = result_str + " ..."  # Multiple registers

        return result_str

    def _handle_load(self, words, opcode, operands, result_str):
        """Handle load operations: lg r14, 112(r15)"""
        if "(r15)" not in operands:
            return result_str

        offset, found = extract_mem_offset(operands, "r15")
        if not found:
            return result_str

        # Determine data size
        data_size = self.get_instruction_size(opcode)
        if data_size is None:
            data_size = stack_unit

        result_str = result_str + self.format_sp_data(offset, data_size)

        if opcode == "lmg":
            result_str = result_str + " ..."  # Multiple registers

        return result_str

    def _handle_frame_access(self, words, operands, result_str):
        """Handle frame pointer operations with r11 or r13"""
        if "(r11)" in operands or "(r13)" in operands:
            reg_name = "r11" if "(r11)" in operands else "r13"
            offset, found = extract_mem_offset(operands, reg_name)

            if found and self.has_frame_pointer():
                result_str = result_str + self.format_fp_data(offset, stack_unit)

        return result_str


# ============================================================================
# Handler Factory
# ============================================================================

def get_stack_handler(arch):
    """
    Factory function to get appropriate stack handler for architecture.

    All supported architectures now use the StackHandler class architecture
    for consistent, reusable, and extensible stack analysis.

    Args:
        arch: Architecture string from sys_info.machine

    Returns:
        StackHandler: Appropriate handler instance, or None if unsupported

    Example:
        handler = get_stack_handler("x86_64")
        if handler:
            result = handler.handle_instruction(words, result_str)
    """
    # x86 family
    if get_arch_family(arch) == "x86":
        return X86StackHandler()

    # ARM family
    elif get_arch_family(arch) == "arm":
        return ArmStackHandler()

    # PowerPC family
    elif get_arch_family(arch) == "ppc":
        return PpcStackHandler()

    # s390x (IBM Z)
    elif get_arch_family(arch) == "s390x":
        return S390xStackHandler()

    # RISC-V family
    elif get_arch_family(arch) == "riscv":
        return RiscVStackHandler()

    # Unsupported architecture
    return None


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


def set_jump_op_list(arch=None):
    global jump_op_set
    global exclude_set

    if arch is None:
        arch = sys_info.machine
    family = get_arch_family(arch)

    exclude_set = []
    if family == "x86":
        jump_op_set = [ "j" ]
    elif family == "ppc":
        jump_op_set = [ "b" ]
        exclude_set = [ "bl", "bla", "bctrl" ]
    elif family == "arm":
        # cbz/cbnz/tbz/tbnz branch too. Everything else starting with 'b'
        # that is not a branch (bit operations) or is a call is excluded.
        jump_op_set = [ "b", "cbz", "cbnz", "tbz", "tbnz" ]
        exclude_set = [ "bl", "blr", "blx", "blraa", "blrab",
                        "bic", "bics", "bfi", "bfc", "bfm", "bfxil",
                        "bif", "bit", "bsl" ]
    elif family == "s390x":
        jump_op_set = [ "j", "brc", "brct" ]
        exclude_set = [ "brasl", "bras" ]
    elif family == "riscv":
        jump_op_set = [ "j", "b" ]
        exclude_set = [ "jal", "jalr" ]
    else:
        jump_op_set = [ "j" ]


_RE_HEX_ADDR = re.compile(r'^0x[0-9a-fA-F]+$')

def get_branch_target(words):
    """
    Return the target address of a branch line split into words, or "".

    The target is the last bare hex address among the operands, which covers
    'jne 0x...', 'bne cr7,0x...', 'cbz x0, 0x...' and 'tbz w0, #3, 0x...'.
    Indirect branches ('jmp *0x10(%rax)', 'br x1') have none.
    """
    target = ""
    for word in words[3:]:
        if word.startswith("<"):
            break
        for part in word.split(","):
            if _RE_HEX_ADDR.match(part):
                target = part
    return target


def assign_jump_lanes(jumps):
    """
    Give each jump a lane so jumps whose line ranges don't overlap share one.

    jumps: list of (start_row, end_row). Shorter jumps are placed first and
    get the lanes nearest the code, like 'objdump --visualize-jumps', so
    nested jumps read inside-out.
    Returns (lane per jump in input order, number of lanes); lane 0 is the
    one next to the code.
    """
    order = sorted(range(len(jumps)),
                   key=lambda i: (jumps[i][1] - jumps[i][0], jumps[i][0]))
    lanes = []          # lanes[n] = list of (start, end) placed in lane n
    result = [0] * len(jumps)
    for i in order:
        start, end = jumps[i]
        for n, spans in enumerate(lanes):
            if all(end < s or start > e for s, e in spans):
                spans.append((start, end))
                result[i] = n
                break
        else:
            lanes.append([(start, end)])
            result[i] = len(lanes) - 1
    return result, len(lanes)


def draw_branches(disasm_str, jump_op_list):
    """
    Prefix each line with a jump graph. A jump leaves its line with '+--*'
    and arrives with '+==>'; '|' carries it between. A jump out of the
    function runs to the last line with no arrow.
    """
    lines = disasm_str.splitlines()
    total_num = len(lines)
    asm_addr_dict = {}
    for loc, line in enumerate(lines):
        if line.startswith("0x"):
            asm_addr_dict[line.split()[0]] = loc

    set_jump_op_list()
    jumps = []          # (origin_row, target_row or None)
    for loc, line in enumerate(lines):
        if not line.startswith("0x"):
            continue
        words = line.split()
        if len(words) < 3:
            continue
        if jump_op_list == "":
            is_jump_op = check_jump_op(words[2])
        else:
            is_jump_op = words[2] in jump_op_list
        if is_jump_op:
            jumps.append((loc, asm_addr_dict.get(get_branch_target(words))))

    spans = []
    for origin, target in jumps:
        end = target if target is not None else total_num - 1
        spans.append((min(origin, end), max(origin, end)))
    lane_of, num_lanes = assign_jump_lanes(spans)

    # cells[row][column]: column 0 is the leftmost (outermost lane).
    cells = [[" "] * num_lanes for _ in range(total_num)]
    horizontal = [None] * total_num   # (column, char) of the line leaving a lane
    for (origin, target), (start, end), lane in zip(jumps, spans, lane_of):
        col = num_lanes - 1 - lane
        for row in range(start, end + 1):
            if cells[row][col] == " ":
                cells[row][col] = "|"
        ends = [(origin, "-")]
        if target is not None:
            ends.append((target, "="))
        for row, char in ends:
            cells[row][col] = "+"
            # Arrivals win over departures on a line that is both, and the
            # outermost lane's line is drawn so it crosses the inner ones.
            prev = horizontal[row]
            if prev is None or (char == "=" and prev[1] == "-") or \
               (char == prev[1] and col < prev[0]):
                horizontal[row] = (col, char)

    result = ""
    for row, line in enumerate(lines):
        row_cells = cells[row]
        marker = " "
        if horizontal[row] is not None:
            col, char = horizontal[row]
            for c in range(col + 1, num_lanes):
                if row_cells[c] != "+":
                    row_cells[c] = char
            marker = ">" if char == "=" else "*"
        result = result + "".join(row_cells) + marker + line + "\n"

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
register_dict = {}  # Fixed: was [], should be dict
register_aliases = {}  # Tracks registers that hold SP snapshots (e.g., mov %rsp,%r13)
stack_debug_enabled = False
stack_debug_lines = []


def reset_stack_debug():
    global stack_debug_lines
    stack_debug_lines = []


def update_register_tracking(reg_name, offset, debug_msg=None):
    """
    Update register tracking by applying offset to all tracked addresses.

    Args:
        reg_name: Register name (REG_STACK_POINTER, REG_FRAME_POINTER, etc.)
        offset: Offset to add to each address
        debug_msg: Optional debug message (auto-generated if None)

    Returns:
        list: Updated address list, or empty list if register not in dict
    """
    global register_dict

    if reg_name not in register_dict:
        return []

    # Use list comprehension for better performance
    updated_list = [addr + offset for addr in register_dict[reg_name]]
    register_dict[reg_name] = updated_list

    if debug_msg is None and stack_debug_enabled:
        debug_msg = "register %s += %d => %s" % (
            reg_name, offset, ",".join("0x%x" % a for a in updated_list))

    if debug_msg and stack_debug_enabled:
        add_stack_debug(debug_msg)

    return updated_list


def extract_mem_offset(operand_str, base_reg):
    """
    Extract memory offset from operand like "112(r15)" or "24(sp)".

    Args:
        operand_str: Full operand string (may contain commas)
        base_reg: Base register to look for (e.g., "r15", "sp")

    Returns:
        tuple: (offset_value, found_flag)
    """
    parts = operand_str.split(",")
    for part in parts:
        if f"({base_reg})" in part:
            offset_str = part.split("(")[0]
            return parse_offset(offset_str), True
    return 0, False


def get_arch_family(arch):
    """
    Map specific architecture to family name.

    Args:
        arch: Architecture string from sys_info.machine

    Returns:
        str: Architecture family name
    """
    if arch in ("x86_64", "i386", "i686", "athlon"):
        return "x86"
    elif arch.startswith("arm") or arch in ("aarch64",):
        return "arm"
    elif arch.startswith("ppc"):
        return "ppc"
    elif arch.startswith("s390") or arch in ("s390x",):
        return "s390x"
    elif arch.startswith("riscv") or arch in ("riscv64", "riscv32"):
        return "riscv"
    return arch


def get_instruction_data_size(opcode, arch=None, default_size=None):
    """
    Get data size for an instruction opcode.

    Args:
        opcode: Instruction opcode (e.g., "str", "ld", "stg")
        arch: Architecture string (defaults to sys_info.machine)
        default_size: Default size if not found (defaults to stack_unit)

    Returns:
        int: Data size in bytes
    """
    global stack_unit

    if arch is None:
        arch = sys_info.machine

    if default_size is None:
        default_size = stack_unit if stack_unit > 0 else 8

    arch_family = get_arch_family(arch)

    if arch_family in INSTRUCTION_SIZES:
        return INSTRUCTION_SIZES[arch_family].get(opcode, default_size)

    return default_size


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

    if get_arch_family(arch) == "x86":
        if opcode.startswith("mov") and len(ops) == 2:
            # Provide detailed explanation for mov variants
            src = ops[0]
            dst = ops[1]

            # Detect specific mov variants with size information
            if opcode == "movzwl":
                return "move zero-extend: read 16-bit word from %s, zero-extend to 32-bit, store in %s" % (src, dst)
            elif opcode == "movzbl":
                return "move zero-extend: read 8-bit byte from %s, zero-extend to 32-bit, store in %s" % (src, dst)
            elif opcode == "movzbq":
                return "move zero-extend: read 8-bit byte from %s, zero-extend to 64-bit, store in %s" % (src, dst)
            elif opcode == "movzwq":
                return "move zero-extend: read 16-bit word from %s, zero-extend to 64-bit, store in %s" % (src, dst)
            elif opcode == "movsbl":
                return "move sign-extend: read 8-bit byte from %s, sign-extend to 32-bit, store in %s" % (src, dst)
            elif opcode == "movswl":
                return "move sign-extend: read 16-bit word from %s, sign-extend to 32-bit, store in %s" % (src, dst)
            elif opcode == "movsbq":
                return "move sign-extend: read 8-bit byte from %s, sign-extend to 64-bit, store in %s" % (src, dst)
            elif opcode == "movswq":
                return "move sign-extend: read 16-bit word from %s, sign-extend to 64-bit, store in %s" % (src, dst)
            elif opcode == "movslq" or opcode == "movsx":
                return "move sign-extend: read 32-bit long from %s, sign-extend to 64-bit, store in %s" % (src, dst)
            elif opcode == "movq":
                return "move 64-bit quadword from %s to %s" % (src, dst)
            elif opcode == "movl":
                return "move 32-bit long from %s to %s" % (src, dst)
            elif opcode == "movw":
                return "move 16-bit word from %s to %s" % (src, dst)
            elif opcode == "movb":
                return "move 8-bit byte from %s to %s" % (src, dst)
            else:
                # Generic mov
                return "move value from %s to %s" % (src, dst)
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

    if get_arch_family(arch) == "arm":
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

    if get_arch_family(arch) == "ppc":
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

    if get_arch_family(arch) == "s390x":
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

    if get_arch_family(arch) == "riscv":
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
        if stack_debug_enabled:
            add_stack_debug("INIT: register_dict[rsp] = stackaddr_list = %s" %
                          (",".join("0x%x" % a for a in stackaddr_list) if stackaddr_list else "EMPTY"))
    elif stack_debug_enabled and "%rsp" not in register_dict:
        add_stack_debug("WARN: register_dict non-empty but missing %%rsp — stale state? keys=%s" % list(register_dict.keys()))

    result_str = one_line
    words = one_line.split()
    if len(words) < 3 or one_line.startswith("/") or one_line.startswith(" "):
        return result_str

    arch = sys_info.machine
    explain = get_operand_explanation(one_line)
    if explain != "":
        add_stack_debug("hint=%s" % explain)

    # Debug: capture FP state at entry to interpret_one_line
    fp_at_entry = list(register_dict.get("%rbp", []))
    had_fp_at_entry = "%rbp" in register_dict

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
            if stack_debug_enabled and "%rsp" in register_dict and get_arch_family(arch) == "x86":
                vsp = []
                for a in register_dict["%rsp"]:
                    vsp.append(a - stack_offset - (cur_count * stack_unit))
                add_stack_debug("sp update: push -> virtual rsp=%s" %
                                (",".join(["0x%x" % a for a in vsp])))
            # Debug: check if stack_op_dict loop cleared FP
            if stack_debug_enabled and had_fp_at_entry and "%rbp" not in register_dict:
                add_stack_debug("BUG TRACE at %s: FP CLEARED by stack_op_dict loop (push handler)! was=%s" % (
                    words[0], ",".join("0x%x" % a for a in fp_at_entry)))
            break

    if result_str == one_line and len(words) > 3: # Nothing happened in the above loop
        result_str = stack_reg_op(words, result_str)
        # Debug: check if stack_reg_op cleared FP
        if stack_debug_enabled and had_fp_at_entry and "%rbp" not in register_dict:
            add_stack_debug("BUG TRACE at %s (%s): FP CLEARED by stack_reg_op! was=%s" % (
                words[0], words[2], ",".join("0x%x" % a for a in fp_at_entry)))

    # Debug: trace ret/leave instructions that may affect register tracking
    if stack_debug_enabled and len(words) >= 3 and words[2] in ("ret", "retq"):
        fp_state = ",".join("0x%x" % a for a in register_dict.get("%rbp", [])) if "%rbp" in register_dict else "NONE"
        sp_state = ",".join("0x%x" % a for a in register_dict.get("%rsp", [])) if "%rsp" in register_dict else "NONE"
        add_stack_debug("RET at %s: rbp=%s rsp=%s cur_count=%d" % (words[0], fp_state, sp_state, cur_count))

    return result_str


def stack_reg_op(words, result_str):
    """
    Main dispatcher for architecture-specific stack analysis.

    Routes instructions to the appropriate StackHandler based on system
    architecture. All supported architectures now use the unified handler
    architecture for consistency and maintainability.

    Supported architectures:
    - x86/x86_64: X86StackHandler
    - ARM/AArch64: ArmStackHandler
    - PPC/PPC64: PpcStackHandler
    - s390x: S390xStackHandler
    - RISC-V: RiscVStackHandler

    Args:
        words: List of instruction tokens [address, ":", opcode, operands]
        result_str: Current analysis result string

    Returns:
        str: Updated result_str with stack annotations appended
    """
    arch = sys_info.machine

    # Get appropriate handler for this architecture
    handler = get_stack_handler(arch)
    if handler:
        return handler.handle_instruction(words, result_str)

    # No handler available for this architecture
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


def format_lea_addresses(addr_list, offset, prefix="    ; "):
    """Format address list for lea instruction display (shows addresses, not values)"""
    return prefix + ", ".join("0x%x" % (addr + offset) for addr in addr_list)


def _get_register_size(reg):
    """Determine size of a single x86 register"""
    reg_lower = reg.lower()

    # 64-bit registers (8 bytes)
    if (reg_lower.startswith('%r') and len(reg_lower) >= 3 and
        reg_lower[2] in '0123456789' and not reg_lower.endswith('d') and
        not reg_lower.endswith('w') and not reg_lower.endswith('b')):
        return 8  # %r8, %r9, ... %r15
    elif reg_lower in ('%rax', '%rbx', '%rcx', '%rdx', '%rsi', '%rdi',
                       '%rsp', '%rbp', '%rip'):
        return 8

    # 32-bit registers (4 bytes)
    elif (reg_lower.startswith('%r') and reg_lower.endswith('d')):
        return 4  # %r8d, %r9d, ... %r15d
    elif reg_lower in ('%eax', '%ebx', '%ecx', '%edx', '%esi', '%edi',
                       '%esp', '%ebp', '%eip'):
        return 4

    # 16-bit registers (2 bytes)
    elif (reg_lower.startswith('%r') and reg_lower.endswith('w')):
        return 2  # %r8w, %r9w, ... %r15w
    elif reg_lower in ('%ax', '%bx', '%cx', '%dx', '%si', '%di',
                       '%sp', '%bp', '%ip'):
        return 2

    # 8-bit registers (1 byte)
    elif (reg_lower.startswith('%r') and reg_lower.endswith('b')):
        return 1  # %r8b, %r9b, ... %r15b
    elif reg_lower in ('%al', '%bl', '%cl', '%dl', '%ah', '%bh', '%ch', '%dh',
                       '%sil', '%dil', '%spl', '%bpl'):
        return 1

    return None


def _extract_data_registers(operand_str):
    """Extract data registers (not addressing registers in parentheses)"""
    # Remove addressing registers: anything inside parentheses
    # e.g., "-0x60(%rbp)" -> "-0x60()"
    cleaned = _RE_PAREN_CONTENT.sub('()', operand_str)

    # Now extract registers from the cleaned string
    return _RE_REGISTER.findall(cleaned)


def get_x86_operand_data_size(words, default_size=None):
    """
    Detect data size from x86 instruction operands by examining register names.
    Prioritizes destination register (second operand in AT&T syntax) and filters
    out addressing registers (those inside parentheses).

    Args:
        words: Instruction words list (e.g., ['0xaddr', '<func+off>:', 'mov', '%eax,%ebx'])
        default_size: Default size to return if detection fails (uses stack_unit if None)

    Returns:
        int: Data size in bytes (1, 2, 4, or 8)
    """
    if default_size is None:
        default_size = stack_unit

    if len(words) < 3:
        return default_size

    opcode = words[2]
    operands = words[3] if len(words) > 3 else ""

    # Split operands into source and destination (AT&T syntax: source, destination)
    operand_parts = operands.split(',')

    # Check destination operand first (second operand in AT&T syntax)
    if len(operand_parts) >= 2:
        dest_operand = operand_parts[1].strip()
        dest_regs = _extract_data_registers(dest_operand)
        for reg in dest_regs:
            size = _get_register_size(reg)
            if size is not None:
                return size

    # Fall back to source operand (first operand)
    if len(operand_parts) >= 1:
        src_operand = operand_parts[0].strip()
        src_regs = _extract_data_registers(src_operand)
        for reg in src_regs:
            size = _get_register_size(reg)
            if size is not None:
                return size

    # Fall back to opcode suffix if no register size detected
    if opcode.endswith('q'):
        return 8  # movq, addq, etc.
    elif opcode.endswith('l'):
        return 4  # movl, addl, etc.
    elif opcode.endswith('w'):
        return 2  # movw, addw, etc.
    elif opcode.endswith('b'):
        return 1  # movb, addb, etc.

    # Final fallback
    return default_size


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

    # Use list accumulation for better performance (30-50% faster)
    parts = []
    for stackaddr in stackaddr_list:
        try:
            actual_addr = stackaddr + offset
            data = read_stack_data(actual_addr, unit)
            if stack_debug_enabled:
                add_stack_debug("read %s base=0x%x offset=%d addr=0x%x size=%d value=0x%x" %
                                (reg if reg else "stack", stackaddr, offset, actual_addr, unit, data))
            # Format with correct width based on unit size
            data_str = ("%x" % data).zfill(unit * 2)

            # Format with register name if provided
            if reg:
                parts.append("%s: 0x%s" % (reg, data_str))
            else:
                parts.append("0x%s" % data_str)
        except Exception as e:
            if stack_debug_enabled:
                add_stack_debug("read FAILED base=0x%x offset=%d addr=0x%x size=%d err=%s" %
                                (stackaddr, offset, stackaddr + offset, unit, str(e)))
            continue

    if not parts:
        return ""

    return prefix + ", ".join(parts)


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

    # Use list accumulation for better performance (30-50% faster)
    parts = []
    for stackaddr in stackaddr_list:
        try:
            actual_addr = stackaddr + offset
            data1 = read_stack_data(actual_addr, unit)
            data2 = read_stack_data(actual_addr + unit, unit)
            if stack_debug_enabled:
                add_stack_debug("read pair %s/%s base=0x%x offset=%d addrs=(0x%x,0x%x) size=%d values=(0x%x,0x%x)" %
                                (reg1 if reg1 else "stack", reg2 if reg2 else "stack",
                                 stackaddr, offset, actual_addr, actual_addr + unit, unit, data1, data2))
            data1_str = ("%x" % data1).zfill(unit * 2)
            data2_str = ("%x" % data2).zfill(unit * 2)

            # Format with register names if provided
            if reg1 and reg2:
                parts.append("%s: 0x%s, %s: 0x%s" % (reg1, data1_str, reg2, data2_str))
            else:
                parts.append("0x%s 0x%s" % (data1_str, data2_str))
        except Exception as e:
            # Skip this entry if there's an error
            continue

    if not parts:
        return ""

    return prefix + ", ".join(parts)


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


def normalize_address(addr_str):
    """'0xFFFF8...', 'ffff8...' and '0x0ffff8...' all become 'ffff8...'.
    Anything that is not hex (a symbol) is returned unchanged."""
    s = addr_str.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if s == "" or any(c not in "0123456789abcdef" for c in s):
        return addr_str
    return s.lstrip("0") or "0"


def bt_frame_matches(words, funcname, disaddr_str):
    """
    True when a split 'bt' frame line ('#3 [sp] func at addr') is the frame
    edis was asked about. 'bt' prints addresses without '0x', so compare
    them normalized: 'edis -r 0xffffffff8f7b9c5d' must match too.
    """
    if len(words) < 5 or words[2] != funcname:
        return False
    if disaddr_str == funcname:
        return True
    return normalize_address(words[4]) == normalize_address(disaddr_str)


def set_stack_data(disasm_str, disaddr_str, task=""):
    global funcname
    global stackaddr_list
    global stack_op_dict
    global cur_count
    global stack_unit
    global stack_offset
    global stack_debug_enabled
    global register_dict
    global register_aliases

    if stack_debug_enabled and (register_dict or register_aliases):
        add_stack_debug("set_stack_data: STALE STATE detected register_dict keys=%s register_aliases keys=%s — resetting" % (
            list(register_dict.keys()), list(register_aliases.keys())))

    stackaddr_list = []
    cur_count = 0
    register_dict = {}
    register_aliases = {}

    try:
        # 'bt' of the current context unless a pid or task was given.
        bt_str = exec_crash_command(("bt %s" % task).strip())
    except:
        if stack_debug_enabled:
            add_stack_debug("set_stack_data: bt command failed")
        return # In case stack has corrupted

    funcname = ""
    for one_line in disasm_str.splitlines():
        if one_line.startswith("/") or one_line.startswith(" "):
            continue
        words = one_line.split()
        funcname = words[1][1:-2]
        break

    if stack_debug_enabled:
        add_stack_debug("set_stack_data: funcname='%s' disaddr_str='%s'" % (funcname, disaddr_str))

    if funcname == "":  # Not matching with any
        if stack_debug_enabled:
            add_stack_debug("set_stack_data: funcname is empty, returning")
        return

    arch = sys_info.machine
    if get_arch_family(arch) == "x86":
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
                if stack_debug_enabled:
                    add_stack_debug("set_stack_data: caller_sp=0x%x" % int(words[1][1:-1], 16))
                break

            if bt_frame_matches(words, funcname, disaddr_str):
                # Mark that we found the target frame - extract SP from NEXT frame (caller)
                stackfound = 1
                if stack_debug_enabled:
                    add_stack_debug("set_stack_data: matched funcname='%s' at %s, will extract from caller frame" % (funcname, disaddr_str))
                continue

    elif get_arch_family(arch) == "arm":
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

            if words[0].startswith("#") and bt_frame_matches(words, funcname, disaddr_str):
                # For AArch64, bt frame address is often x29. Convert to runtime SP.
                frame_addr = int(words[1][1:-1], 16)
                runtime_sp = estimate_aarch64_runtime_sp(frame_addr, disasm_str)
                stackaddr_list.append(runtime_sp)
                add_stack_debug("set_stack_data: frame=0x%x estimated_entry_sp=0x%x" %
                                (frame_addr, runtime_sp))

    elif get_arch_family(arch) == "ppc":
        stack_op_dict = {}
        stack_unit = 8
        stack_offset = 0

        stackfound = 0
        for one_line in bt_str.splitlines():
            words = one_line.split()
            if not words or not words[0].startswith("#"):
                continue
            if stackfound == 1:
                stackaddr_list.append(int(words[1][1:-1], 16))
                stackfound = 0

            if bt_frame_matches(words, funcname, disaddr_str):
                stackfound = 1

    elif get_arch_family(arch) == "s390x":
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

            if bt_frame_matches(words, funcname, disaddr_str):
                stackfound = 1

    elif get_arch_family(arch) == "riscv":
        stack_op_dict = {}
        if arch == "riscv64":
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

            if bt_frame_matches(words, funcname, disaddr_str):
                stackfound = 1


def set_asm_colors():
    global asm_color_dict
    global arg_color_dict

    arch = sys_info.machine
    if get_arch_family(arch) == "x86":
        asm_color_dict = {
            # Prefix match: covers 'callq' and the plain 'call' newer
            # binutils prints.
            "call" : crashcolor.LIGHTRED | crashcolor.BOLD,
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
    elif get_arch_family(arch) == "arm":
        asm_color_dict = {
            "bl" : crashcolor.LIGHTRED | crashcolor.BOLD,
            "b" : crashcolor.BLUE | crashcolor.BOLD,
            "stp" : crashcolor.RED | crashcolor.UNDERLINE,
            "ldp" : crashcolor.YELLOW | crashcolor.UNDERLINE,
            "ret" : crashcolor.MAGENTA | crashcolor.BOLD,
        }
    elif get_arch_family(arch) == "ppc":
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
    elif get_arch_family(arch) == "s390x":
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
    elif get_arch_family(arch) == "riscv":
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


# Lazily-initialized pygments highlighter used to pretty-print the C source
# lines that are interleaved with disassembly, matching the theme (and its
# background) used by 'edis -f'. Stored as
# (highlight_fn, lexer, formatter, bg_ansi) or None if pygments is missing.
_source_highlighter = None
_source_highlighter_ready = False


def _hex_to_bg_ansi(hex_color):
    """Convert a '#rrggbb' style background color into a truecolor background
    ANSI escape, or "" if it can't be parsed."""
    if not hex_color:
        return ""
    h = hex_color.lstrip('#')
    if len(h) != 6:
        return ""
    try:
        r = int(h[0:2], 16)
        g = int(h[2:4], 16)
        b = int(h[4:6], 16)
    except Exception:
        return ""
    return "\x1b[48;2;%d;%d;%dm" % (r, g, b)


def get_source_highlighter():
    global _source_highlighter, _source_highlighter_ready

    if _source_highlighter_ready:
        return _source_highlighter

    _source_highlighter_ready = True
    # Piped or saved output ('edis ... | grep', evidence files) gets plain
    # text, like the rest of edis output through crashcolor.
    if not sys.stdout.isatty():
        _source_highlighter = None
        return None
    try:
        from pygments import highlight
        from pygments.lexers import CLexer
        from pygments.formatters import TerminalTrueColorFormatter
        from pygments.styles import get_style_by_name

        code_theme = os.environ.get('CODE_THEME', 'tango')
        try:
            formatter = TerminalTrueColorFormatter(style=code_theme)
            style = get_style_by_name(code_theme)
        except Exception:
            # Fall back to the same default 'edis -f' uses if the theme is
            # unknown to this pygments version.
            formatter = TerminalTrueColorFormatter(style='tango')
            style = get_style_by_name('tango')

        bg_ansi = _hex_to_bg_ansi(getattr(style, 'background_color', None))

        # ensurenl=False keeps us from adding stray newlines; we print them.
        lexer = CLexer(stripnl=False, ensurenl=False)
        _source_highlighter = (highlight, lexer, formatter, bg_ansi)
    except Exception:
        _source_highlighter = None

    return _source_highlighter


def is_source_path_header(text):
    """
    True when `text` is the "<path>: <lineno>" header the server prints before
    each source region (e.g. '/usr/src/debug/.../swap_state.c: 333').

    Such a header is not C code and must not be run through the C lexer, which
    would otherwise colorize the version numbers in the path as numeric
    literals. Real source lines are prefixed with a right-justified line number,
    so they start with a digit rather than '/'.
    """
    s = text.strip()
    if s.startswith("/") and re.search(r":\s*\d+$", s):
        return True
    return False


def highlight_source_code(text, width=0, highlight_syntax=True):
    """
    Return the source line `text` with the theme's background applied, matching
    the look of 'edis -f'. When `highlight_syntax` is True the text is run
    through the C lexer; when False (used for path headers) only the background
    band is applied so non-code text is not mis-colorized.

    The theme background is kept alive across pygments' full-reset sequences
    and, when `width` is given, the line is padded so the background band
    spans the full width like a code block. Falls back to the original text
    unchanged if pygments is not available or highlighting fails.
    """
    hl = get_source_highlighter()
    if hl is None:
        return text

    # Expand tabs so len(text) matches the number of terminal columns; kernel
    # source is tab-indented and a raw '\t' would otherwise under-count the
    # width and make the padded background band wrap onto the next line.
    text = text.expandtabs()

    highlight, lexer, formatter, bg_ansi = hl
    if highlight_syntax:
        try:
            body = highlight(text, lexer, formatter)
        except Exception:
            return text

        # pygments may append a trailing newline; drop it so the caller's
        # print() controls line breaks.
        if body.endswith("\n") and not text.endswith("\n"):
            body = body[:-1]
    else:
        body = text

    if not bg_ansi:
        return body

    # pygments emits a full reset ("\x1b[39;00m") after bold tokens, which also
    # clears the background. Turn bold off (22) and restore the default
    # foreground (39) without clearing the background, then re-assert it.
    body = body.replace("\x1b[39;00m", "\x1b[22;39m" + bg_ansi)

    pad = width - len(text)
    if pad < 0:
        pad = 0

    return bg_ansi + body + (" " * pad) + "\x1b[0m"


_GRAPH_CHARS = frozenset(" +|-=*>")

def asm_start(one_line):
    """
    Index where the instruction starts in an output line ('0x...' after an
    optional jump-graph prefix), or -1 for a source or header line. A source
    line containing '0x' ('   333   if (x & 0x10)') is not an instruction:
    its prefix holds a line number, not just graph characters.
    """
    idx = one_line.find("0x")
    if idx < 0:
        return -1
    if any(c not in _GRAPH_CHARS for c in one_line[:idx]):
        return -1
    return idx


def join_around_target(before, after):
    """
    Join 'dis -r <addr>' (function start up to addr) and 'dis -f <addr>'
    (addr to function end) into the whole function. Both contain the
    instruction at addr, so 'after' is used from the line following it.
    """
    lines = after.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("0x"):
            rest = lines[i + 1:]
            if not rest:
                return before
            return before.rstrip("\n") + "\n" + "\n".join(rest) + "\n"
    return before


def context_rows(lines, target, count):
    """
    Rows of `lines` to print for 'edis -C count': `count` instructions each
    side of the target, the source lines between them, and the source block
    the first one belongs to. None when the target is not found, meaning
    print everything.
    """
    asm_rows = [row for row, line in enumerate(lines) if asm_start(line) >= 0]
    target_pos = None
    for pos, row in enumerate(asm_rows):
        line = lines[row]
        if is_target_line(line[asm_start(line):].split(), target):
            target_pos = pos
            break
    if target_pos is None:
        return None

    kept = asm_rows[max(0, target_pos - count):target_pos + count + 1]
    shown = set(kept)
    for i, row in enumerate(kept):
        r = row - 1
        if i == 0:
            # Walk back over skipped instructions to the source block
            # that the first shown instruction belongs to.
            while r >= 0 and asm_start(lines[r]) >= 0:
                r = r - 1
        while r >= 0 and asm_start(lines[r]) < 0:
            shown.add(r)
            r = r - 1
    return shown


def jump_sources(lines, limit=4):
    """
    For each instruction row that jumps land on, a note naming where they
    come from: {row: "from f+4, f+30"}, listing up to `limit` of them.
    crash prints '<f+N>' offsets in decimal and so does this.
    """
    set_jump_op_list()
    rows = {}
    origins = {}
    for row, line in enumerate(lines):
        idx = asm_start(line)
        if idx < 0:
            continue
        words = line[idx:].split()
        if len(words) < 2:
            continue
        rows[words[0]] = row
        if len(words) > 2 and check_jump_op(words[2]):
            target = get_branch_target(words)
            if target != "":
                origins.setdefault(target, []).append(words[1].rstrip(":").strip("<>"))

    notes = {}
    for target, names in origins.items():
        if target not in rows:
            continue
        note = "from " + ", ".join(names[:limit])
        if len(names) > limit:
            note = note + ", +%d more" % (len(names) - limit)
        notes[rows[target]] = note
    return notes


# ============================================================================
# Operand helpers shared by the annotations below
# ============================================================================

def _x86_register_names():
    names = {}
    for r in ("a", "b", "c", "d"):
        for alias in ("r%sx" % r, "e%sx" % r, "%sx" % r, "%sl" % r, "%sh" % r):
            names[alias] = "r%sx" % r
    for r in ("si", "di", "bp", "sp"):
        for alias in ("r" + r, "e" + r, r, r + "l"):
            names[alias] = "r" + r
    for n in range(8, 16):
        for suffix in ("", "d", "w", "b"):
            names["r%d%s" % (n, suffix)] = "r%d" % n
    return names

_X86_REGISTERS = _x86_register_names()

# Registers that carry the first arguments of a call, per architecture family.
ARG_REGS = {
    "x86": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
    "arm": ["x%d" % n for n in range(8)],
    "ppc": ["r%d" % n for n in range(3, 11)],
    "s390x": ["r%d" % n for n in range(2, 7)],
    "riscv": ["a%d" % n for n in range(8)],
}

# x86_64 registers a call may change (the rest survive it).
_X86_CALL_CLOBBERED = ("rax", "rcx", "rdx", "rsi", "rdi",
                       "r8", "r9", "r10", "r11")


def canonical_register(name, family):
    """'%edi' -> 'rdi' and 'w1' -> 'x1': the full register a name is part of.
    None when `name` is not a register."""
    reg = name.strip().lstrip("*").lstrip("%").lower()
    if family == "x86":
        return _X86_REGISTERS.get(reg)
    if family == "arm" and re.match(r'^w\d+$', reg):
        return "x" + reg[1:]
    if re.match(r'^[a-z]+\d*$', reg):
        return reg
    return None


def split_operands(text):
    """Split 'a,b' operands on the commas outside () and [], so
    '0x8(%rax,%rbx,8),%rcx' and '[sp, #16]' stay whole."""
    ops = []
    depth = 0
    cur = ""
    for c in text:
        if c in "([":
            depth = depth + 1
        elif c in ")]":
            depth = depth - 1
        if c == "," and depth == 0:
            ops.append(cur.strip())
            cur = ""
        else:
            cur = cur + c
    if cur.strip() != "":
        ops.append(cur.strip())
    return ops


def instruction_operands(words):
    """The operands of a split 'dis' line, without the '<sym>' or '# ...'
    comment crash adds after them."""
    parts = []
    for word in words[3:]:
        if word == "#" or word.startswith("<") or word.startswith(";"):
            break
        parts.append(word)
    return split_operands(" ".join(parts))


_NO_DEST_PREFIX = {
    "x86": ("cmp", "test", "bt", "j", "call", "ret", "push", "nop", "ud"),
    "arm": ("st", "cmp", "cmn", "tst", "b.", "cb", "tb", "ret", "prfm"),
    "ppc": ("st", "cmp", "b", "tw", "td", "mt"),
    "s390x": ("st", "c", "b", "j", "tm"),
    "riscv": ("b", "j", "ret"),
}
_ARM_BRANCHES = ("b", "bl", "blr", "br", "blx")
_RISCV_STORES = ("sd", "sw", "sh", "sb")


def dest_register(words, family):
    """The register a split 'dis' line writes, or None (stores, compares,
    branches, memory destinations)."""
    if len(words) < 4:
        return None
    op = words[2]
    if op.startswith(_NO_DEST_PREFIX.get(family, ())):
        return None
    if family == "arm" and op in _ARM_BRANCHES:
        return None
    if family == "riscv" and op in _RISCV_STORES:
        return None
    ops = instruction_operands(words)
    if not ops:
        return None
    dest = ops[-1] if family == "x86" else ops[0]
    if "(" in dest or "[" in dest:
        return None
    return canonical_register(dest, family)


def parse_prototype(text):
    """Parameter types from crash 'whatis <func>' output, such as
    'int foo(struct page *, unsigned int);'. [] for '(void)', None when the
    output is not a function prototype."""
    for line in text.splitlines():
        start = line.find("(")
        if start < 0:
            continue
        depth = 0
        for end in range(start, len(line)):
            if line[end] == "(":
                depth = depth + 1
            elif line[end] == ")":
                depth = depth - 1
                if depth == 0:
                    break
        else:
            return None
        inner = line[start + 1:end].strip()
        if inner in ("", "void"):
            return []
        return split_operands(inner)
    return None


_prototype_cache = {}

def get_prototype(func):
    if func not in _prototype_cache:
        try:
            _prototype_cache[func] = parse_prototype(
                exec_crash_command("whatis %s" % func))
        except Exception:
            _prototype_cache[func] = None
    return _prototype_cache[func]


def _asm_rows(lines):
    rows = []
    for row, line in enumerate(lines):
        idx = asm_start(line)
        if idx >= 0:
            words = line[idx:].split()
            if len(words) >= 3:
                rows.append((row, words))
    return rows


# ============================================================================
# -a: name the registers that carry a call's arguments
# ============================================================================

def call_arg_notes(lines, get_proto=None, lookback=16):
    """
    {row: "arg1 of foo (struct page *)"} for the instructions that set up
    the argument registers of the calls in `lines`. Walks back from each
    call to the previous call or jump target, taking the last write to each
    register. With a prototype only its parameters are named.
    """
    family = get_arch_family(sys_info.machine)
    regs = ARG_REGS.get(family)
    if regs is None or (family == "x86" and sys_info.machine != "x86_64"):
        return {}
    set_call_op_list()
    targets = set(jump_sources(lines).keys())
    asm = _asm_rows(lines)

    notes = {}
    for pos, (row, words) in enumerate(asm):
        if words[2] not in call_op_set:
            continue
        callee = None
        if len(words) > 4 and words[4].startswith("<"):
            callee = words[4][1:-1].split("+")[0]
        params = get_proto(callee) if (callee and get_proto) else None
        count = min(len(params), len(regs)) if params is not None else len(regs)
        seen = set()
        for prow, pwords in reversed(asm[max(0, pos - lookback):pos]):
            if pwords[2] in call_op_set:
                break
            dest = dest_register(pwords, family)
            if dest in regs[:count] and dest not in seen:
                seen.add(dest)
                i = regs.index(dest)
                label = "arg%d of %s" % (i + 1, callee or "indirect call")
                if params is not None:
                    label = label + " (%s)" % params[i]
                notes.setdefault(prow, label)
            if prow in targets:     # Reached from elsewhere too: stop here
                break
    return notes


# ============================================================================
# -T: name the struct field a memory access reads or writes (x86_64)
# ============================================================================

def parse_struct_offsets(text):
    """
    crash 'struct -o <name>' output -> (members, size). members is a list
    of (offset, name, type) in order; type is 'function pointer' or ends
    with '[]' for those. size is None when no 'SIZE:' line is found.
    """
    members = []
    size = None
    for line in text.splitlines():
        m = re.match(r'^\s*SIZE:\s*(0x[0-9a-fA-F]+|\d+)', line)
        if m:
            size = int(m.group(1), 0)
            continue
        m = re.match(r'^\s*\[(0x[0-9a-fA-F]+|\d+)\]\s+(.*)$', line)
        if m is None:
            continue
        offset = int(m.group(1), 0)
        decl = m.group(2).strip().rstrip(";").strip()
        fp = re.search(r'\(\s*\*\s*(\w+)\s*\)', decl)
        if fp:
            members.append((offset, fp.group(1), "function pointer"))
            continue
        decl = decl.split(":")[0].strip()       # bitfield width
        is_array = decl.endswith("]")
        decl = re.sub(r'(\s*\[[^\]]*\])+$', '', decl).strip()
        mm = re.search(r'(\w+)$', decl)
        if mm is None:
            continue
        ftype = decl[:mm.start()].strip()
        if is_array:
            ftype = ftype + "[]"
        members.append((offset, mm.group(1), ftype))
    return members, size


_struct_cache = {}

def struct_layout(kind, name):
    key = (kind, name)
    if key not in _struct_cache:
        try:
            _struct_cache[key] = parse_struct_offsets(
                exec_crash_command("%s -o %s" % (kind, name)))
        except Exception:
            _struct_cache[key] = ([], None)
    return _struct_cache[key]


def pointer_target(ftype):
    """('struct', 'page') for 'struct page *', else None."""
    m = re.match(r'^(?:const\s+)?(struct|union)\s+(\w+)\s*\*$', ftype or "")
    return (m.group(1), m.group(2)) if m else None


def embedded_type(ftype):
    """('struct', 'list_head') for an embedded 'struct list_head', else None."""
    m = re.match(r'^(?:const\s+)?(struct|union)\s+(\w+)$', ftype or "")
    return (m.group(1), m.group(2)) if m else None


def resolve_field(kind, name, offset, layout=None, depth=0):
    """
    'mapping', 'lru.prev' or 'flags+0x4' for `offset` bytes into the
    struct, with the field's type (None when it falls inside a field).
    None when the layout is unknown or the offset is outside the struct.
    """
    layout = layout or struct_layout
    members, size = layout(kind, name)
    if not members or offset < 0 or (size is not None and offset >= size):
        return None
    best = None
    for member in members:
        if member[0] <= offset and (best is None or member[0] > best[0]):
            best = member
    if best is None:
        return None
    moff, mname, mtype = best
    rel = offset - moff
    if rel == 0:
        return (mname, mtype)
    inner = embedded_type(mtype)
    if inner and depth < 3:
        sub = resolve_field(inner[0], inner[1], rel, layout, depth + 1)
        if sub:
            return (mname + "." + sub[0], sub[1])
    return ("%s+0x%x" % (mname, rel), None)


_RE_X86_MEM = re.compile(r'^(-?0x[0-9a-fA-F]+|-?\d+)?\(%(\w+)\)$')

def struct_field_notes(lines, get_proto=None, layout=None):
    """
    {row: "page->mapping"} for x86_64 memory accesses through a register
    known to point to a struct. Pointer types start from the function's
    prototype and follow 'mov' of a struct pointer field, 'lea' of an
    embedded struct and register copies. Calls drop the registers they
    clobber; a jump target drops everything, as another path may arrive
    with other values.
    """
    if sys_info.machine != "x86_64":
        return {}
    layout = layout or struct_layout
    asm = _asm_rows(lines)
    if not asm:
        return {}
    set_call_op_list()
    targets = set(jump_sources(lines).keys())

    state = {}
    first = asm[0][1][1].rstrip(":")
    if get_proto and first.startswith("<") and "+" not in first:
        params = get_proto(first[1:-1]) or []
        for reg, ptype in zip(ARG_REGS["x86"], params):
            t = pointer_target(ptype)
            if t:
                state[reg] = t

    notes = {}
    for row, words in asm:
        if row in targets and row != asm[0][0]:
            state = {}
        op = words[2]
        ops = instruction_operands(words)
        field = None
        for operand in ops:
            m = _RE_X86_MEM.match(operand)
            if m is None:
                continue
            base = canonical_register(m.group(2), "x86")
            if base not in state:
                continue
            offset = int(m.group(1), 0) if m.group(1) else 0
            field = resolve_field(state[base][0], state[base][1], offset, layout)
            if field:
                notes[row] = "%s%s->%s" % ("&" if op.startswith("lea") else "",
                                           state[base][1], field[0])
            break

        if op in call_op_set:
            for reg in _X86_CALL_CLOBBERED:
                state.pop(reg, None)
            continue
        dest = dest_register(words, "x86")
        if dest is None:
            continue
        new = None
        full_width = ops and ops[-1].lstrip("%") == dest
        if full_width and op in ("mov", "movq") and len(ops) == 2:
            if ops[0].startswith("%"):
                src = canonical_register(ops[0], "x86")
                if ops[0].lstrip("%") == src:
                    new = state.get(src)
            elif field:
                new = pointer_target(field[1])
        elif full_width and op.startswith("lea") and field:
            new = embedded_type(field[1])
        if new:
            state[dest] = new
        else:
            state.pop(dest, None)
    return notes


# ============================================================================
# -F: find call paths from a function to another
# ============================================================================

def find_call_paths(root, target, max_depth, get_calls, limit=50):
    """
    Call chains from `root` that reach `target` within `max_depth` calls,
    as lists of names. Indirect calls are skipped and no function appears
    twice in a chain.
    """
    paths = []

    def walk(name, path):
        if len(path) - 1 >= max_depth or len(paths) >= limit:
            return
        for callee in get_calls(name):
            if callee.startswith("*"):
                continue
            base = callee.split("+")[0]
            if base == target:
                if len(paths) < limit:
                    paths.append(path + [base])
                continue
            if base in path:
                continue
            walk(base, path + [base])

    walk(root, [root])
    return paths


# ============================================================================
# Source lines without the remoteapi server
# ============================================================================

def is_statement_end(line):
    s = re.sub(r"/\*.*?\*/", "", line)
    s = re.sub(r"//.*$", "", s).strip()
    return s.endswith((";", ":", "{", "}")) or s.startswith("#")


def statement_range(file_lines, idx, back=5, forward=8):
    """First and last 0-based line of the C statement around line idx."""
    start = idx
    while start > 0 and idx - start < back:
        prev = file_lines[start - 1]
        if prev.strip() == "" or is_statement_end(prev):
            break
        start = start - 1
    end = idx
    while not is_statement_end(file_lines[end]) and end + 1 < len(file_lines) \
          and end - idx < forward:
        end = end + 1
    return start, end


def local_source_path(path):
    """The readable local file for a 'dis -l' source path: the path itself
    (kernel-debuginfo-common installs it) or the same file under
    $EDIS_SOURCE_DIR, a kernel source tree. None when neither exists."""
    if os.path.isfile(path):
        return path
    src_dir = os.environ.get("EDIS_SOURCE_DIR", "")
    m = re.search(r'/linux-[^/]+/(.+)$', path)
    if src_dir and m:
        candidate = os.path.join(src_dir, m.group(1))
        if os.path.isfile(candidate):
            return candidate
    return None


_source_file_cache = {}

def read_source_file(path):
    if path not in _source_file_cache:
        local = local_source_path(path)
        try:
            with open(local) as f:
                _source_file_cache[path] = f.read().splitlines()
        except Exception:
            _source_file_cache[path] = None
    return _source_file_cache[path]


def split_source_header(line):
    """('/path/file.c', 123) for a 'dis -l' header line, else None."""
    if not is_source_path_header(line):
        return None
    path, _, number = line.strip().rpartition(":")
    try:
        return path.strip(), int(number)
    except ValueError:
        return None


def add_local_source(disasm_str, read_lines=None):
    """
    'dis -l' output with the source statement printed under each header,
    in the server's '%8d <code>' format. Returns (text, found); found is
    False when no source file could be read, and the text is then the
    output with the headers dropped, as plain 'dis' shows it.
    """
    read_lines = read_lines or read_source_file
    out = []
    plain = []
    found = False
    last = None
    for line in disasm_str.splitlines():
        out.append(line)
        header = split_source_header(line)
        if header is None:
            plain.append(line)
            continue
        file_lines = read_lines(header[0])
        if not file_lines or not (0 < header[1] <= len(file_lines)):
            continue
        found = True
        if header == last:
            continue
        last = header
        start, end = statement_range(file_lines, header[1] - 1)
        for i in range(start, end + 1):
            out.append("%8d %s" % (i + 1, file_lines[i]))
    if not found:
        return "\n".join(plain) + "\n", False
    return "\n".join(out) + "\n", True


def local_function_source(disasm_str, read_lines=None):
    """
    The whole function's source for 'edis -f' without the server: the
    lines from the first to the last one 'dis -l' maps to in the file of
    the first header. None when that file can't be read.
    """
    read_lines = read_lines or read_source_file
    path = None
    numbers = []
    for line in disasm_str.splitlines():
        header = split_source_header(line)
        if header is None:
            continue
        if path is None:
            path = header[0]
        if header[0] == path:
            numbers.append(header[1])
    if path is None:
        return None
    file_lines = read_lines(path)
    if not file_lines:
        return None
    start = max(1, min(numbers))
    end = min(len(file_lines), max(numbers))
    # Widen to the whole definition in kernel style: back to the '{' in
    # column 0 and the signature above it, forward to the '}' in column 0.
    for n in range(start, max(0, start - 60), -1):
        if file_lines[n - 1].startswith("{"):
            start = n
            while start > 1 and file_lines[start - 2].strip() != "" and \
                  not is_statement_end(file_lines[start - 2]):
                start = start - 1
            break
    for n in range(end, min(len(file_lines), end + 200) + 1):
        if file_lines[n - 1].startswith("}"):
            end = n
            break
    out = ["%s: %d" % (path, start)]
    for n in range(start, end + 1):
        out.append("%8d %s" % (n, file_lines[n - 1]))
    return "\n".join(out) + "\n"


# ============================================================================
# --save / --diff: compare a function across kernels
# ============================================================================

_RE_ADDR_SYM = re.compile(r'0x[0-9a-fA-F]{9,}\s+(<[^>]+>)')
_RE_LONG_ADDR = re.compile(r'0x[0-9a-fA-F]{12,}')

def normalize_disasm(text):
    """
    'dis' output as '<f+N> op operands' lines with kernel addresses
    removed, so the same function from two kernels can be diffed: an
    address with a symbol becomes the symbol, any other becomes ADDR.
    """
    result = []
    for line in text.splitlines():
        idx = asm_start(line)
        if idx < 0:
            continue
        words = line[idx:].split(None, 2)
        if len(words) < 3:
            continue
        body = _RE_ADDR_SYM.sub(r'\1', words[2].strip())
        body = _RE_LONG_ADDR.sub("ADDR", body)
        body = re.sub(r'\s+', ' ', body)
        result.append("%s %s" % (words[1].rstrip(":"), body))
    return result


def diff_disasm(saved_lines, current_lines, saved_name, current_name):
    import difflib
    return list(difflib.unified_diff(saved_lines, current_lines,
                                     fromfile=saved_name, tofile=current_name,
                                     lineterm=""))


TARGET_MARKER = "  <=="

def parse_target(ins_addr):
    """
    What 'edis' was pointed at, to mark that instruction: ('addr', hex digits)
    for an address, ('sym', name, offset) for 'func+0x12', or None for a bare
    function name, which names no single instruction.
    """
    s = ins_addr.strip()
    if "+" in s:
        name, off = s.split("+", 1)
        try:
            return ("sym", name, int(off, 0))
        except ValueError:
            return None
    if s.lower().startswith("0x") or \
       (len(s) >= 8 and all(c in "0123456789abcdefABCDEF" for c in s)):
        return ("addr", normalize_address(s))
    return None


def is_target_line(words, target):
    """True when the split 'dis' line '0x... <func+N>: op ...' is `target`.
    crash prints the offset in '<func+N>' in decimal."""
    if target is None or len(words) < 2:
        return False
    if target[0] == "addr":
        return normalize_address(words[0]) == target[1]
    sym = words[1].rstrip(":")
    if not (sym.startswith("<") and sym.endswith(">")):
        return False
    sym = sym[1:-1]
    name, _, off = sym.partition("+")
    try:
        offset = int(off) if off else 0
    except ValueError:
        return False
    return name == target[1] and offset == target[2]


def save_or_diff(disasm_str, ins_addr, o):
    """'edis --save FILE func' writes the function's normalized disassembly;
    'edis --diff FILE func', run on another kernel, shows what changed."""
    current = normalize_disasm(disasm_str)
    kernel_ver, release_ver = get_kernel_version()
    label = "%s %s" % (ins_addr, release_ver)
    if o.save:
        try:
            with open(o.save, "w") as f:
                f.write("# edis %s\n" % label)
                for line in current:
                    f.write(line + "\n")
        except Exception as e:
            print("Cannot write %s: %s" % (o.save, e))
            return
        print("Saved %d instructions of %s to %s" % (len(current), label, o.save))
        return

    try:
        with open(o.diff) as f:
            saved = f.read().splitlines()
    except Exception as e:
        print("Cannot read %s: %s" % (o.diff, e))
        return
    saved_label = o.diff
    if saved and saved[0].startswith("# edis "):
        saved_label = saved[0][len("# edis "):]
        saved = saved[1:]
    diff = diff_disasm(saved, current, saved_label, label)
    if not diff:
        print("No difference between %s and %s" % (saved_label, label))
        return
    for line in diff:
        if line.startswith("+") and not line.startswith("+++"):
            crashcolor.set_color(crashcolor.LIGHTGREEN)
        elif line.startswith("-") and not line.startswith("---"):
            crashcolor.set_color(crashcolor.LIGHTRED)
        elif line.startswith("@@"):
            crashcolor.set_color(crashcolor.LIGHTCYAN)
        print(line)
        crashcolor.set_color(crashcolor.RESET)


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
    target = parse_target(ins_addr)

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
    elif o.context > 0 and target is not None and not o.fullsource:
        # Whole function, so stack tracking sees the prologue; only the
        # window around the address is printed.
        base = "" if o.noaction else "-l"
        before = exec_crash_command("dis %s -r %s" % (base, ins_addr))
        after = exec_crash_command("dis %s -f %s" % (base, ins_addr))
        disasm_str = join_around_target(before, after)
    else:
        command_str = "dis %s %s" % (options, ins_addr)
        disasm_str = exec_crash_command(command_str)
    if (disasm_str.startswith("symbol not found")):
        print (disasm_str)
        return


    if o.save or o.diff:
        save_or_diff(disasm_str, ins_addr, o)
        return

    result_str = ""
    server = os.environ.get("CRASHEXT_SERVER", "")
    if (o.noaction or not disasm_str.startswith("/")):
        result_str = disasm_str
    elif server == "":
        # No server: read the source from this machine if it is here.
        if o.fullsource:
            full = local_function_source(disasm_str)
            if full is None:
                # No source here: show the disassembly, as before
                # local source reading existed.
                print("Source is not readable here (set CRASHEXT_SERVER,"
                      " or EDIS_SOURCE_DIR to a kernel source tree)")
                print(add_local_source(disasm_str)[0], end="")
                return
            for line in full.splitlines():
                print(highlight_source_code(
                    line, 0, highlight_syntax=not is_source_path_header(line)))
            crashcolor.set_color(crashcolor.RESET)
            return
        result_str, found = add_local_source(disasm_str)
        if o.sourceonly and found:
            result_str = "\n".join(l for l in result_str.splitlines()
                                   if asm_start(l) < 0) + "\n"
    else:
        # Ordered: a set would pick an arbitrary one, possibly python2.
        python_list = ( "python3", "python", "python2" )
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
                # Feed the text on stdin from a file: an "echo '...'" breaks
                # on a quote in it and on the shell's command line limit.
                result_str = crashhelper.run_gdb_command_with_file(
                    "!%s %s %s" % (python_cmd, shlex.quote(disasm_path),
                                   cmd_options),
                    disasm_str + "\n")
                break

    if (o.fullsource):
        print(result_str)
        return

    if (o.graph):
        result_str = draw_branches(result_str, o.jump_op_list)

    stack_debug_enabled = o.debug
    set_stack_data(disasm_str, ins_addr, o.task) # To retreive stack data
    if o.stackaddr != "":
        stackaddr_list = [int(o.stackaddr, 16)]

    set_asm_colors()
    crashcolor.set_color(crashcolor.RESET)

    # Terminal width, used to pad the highlighted source background band so it
    # spans the line like the code block rendered by 'edis -f'.
    try:
        term_width = os.get_terminal_size(1).columns
    except Exception:
        term_width = 0
    if term_width <= 0:
        try:
            term_width = int(os.environ.get("COLUMNS", "0"))
        except Exception:
            term_width = 0
    if term_width <= 0:
        term_width = 80

    result_lines = result_str.splitlines()
    shown = None
    if o.context > 0 and target is not None:
        shown = context_rows(result_lines, target, o.context)
    skipped = False
    # The graph already draws where jumps come from.
    jump_notes = {} if o.graph else jump_sources(result_lines)
    arg_notes = call_arg_notes(result_lines, get_prototype) if o.args else {}
    field_notes = struct_field_notes(result_lines, get_prototype) \
                  if o.fields else {}

    for row, one_line in enumerate(result_lines):
        idx = asm_start(one_line)
        if shown is not None and row not in shown:
            if idx >= 0:
                interpret_one_line(one_line[idx:]) # Keep stack tracking going
            skipped = True
            continue
        if skipped:
            crashcolor.set_color(crashcolor.DARKGRAY)
            print("  ...")
            crashcolor.set_color(crashcolor.RESET)
            skipped = False

        if idx >= 0:
            line = one_line[idx:]
            graph = one_line[:idx]
            is_disasm_line = True
        elif is_source_path_header(one_line):
            # "<path>: <lineno>" header. The path itself often embeds digits
            # (e.g. a kernel version like ".../kernel-3.10.0-1160.../..."),
            # so the line-number search below would latch onto the first
            # digit inside the path instead of the real line number at the
            # end, splitting most of the path into an uncolored 'graph'
            # prefix and C-highlighting the leftover fragment. Treat the
            # header as a single unit so it always takes the column-0
            # background band below, with syntax highlighting skipped.
            line = one_line
            graph = ""
            is_disasm_line = False
        else: # source line
            prog = re.compile(r"(?P<line_number>[0-9]+)")
            m = prog.search(one_line)
            line = None
            if m is not None:
                line = m.group("line_number")
            if line == None:
                m = re.search(r"/[a-zA-Z]", one_line)
                if m is not None:
                    line = one_line[m.start():]

            if line == None:
                line = one_line
            idx = one_line.find(line)
            line = one_line[idx:]
            graph = one_line[:idx]
            is_disasm_line = False

        # Source lines with no jump-graph prefix (the common case, e.g.
        # 'edis -lr'): render the whole line (indent + line number + code) as
        # one syntax-highlighted band so the theme background spans from
        # column 0, matching 'edis -f'.
        if is_disasm_line == False and graph.strip() == "":
            crashcolor.set_color(crashcolor.RESET)
            print(highlight_source_code(
                one_line, term_width,
                highlight_syntax=not is_source_path_header(one_line)))
            crashcolor.set_color(crashcolor.RESET)
            continue

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

        # Source lines that carry a jump-graph prefix: keep the prefix
        # coloring above, then highlight the code portion with the theme
        # background spanning the remaining width.
        if is_disasm_line == False:
            crashcolor.set_color(crashcolor.RESET)
            print(highlight_source_code(
                line, term_width - len(graph),
                highlight_syntax=not is_source_path_header(line)))
            crashcolor.set_color(crashcolor.RESET)
            continue

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
        is_target = is_disasm_line and is_target_line(words, target)
        if len(words) > 2:
            if (o.symbol and is_address(words[-1]) == True): # Translate address into symbol
                line = ("%s%s" % (words[-1], find_symbol(words[-1]))).join(line.rsplit(words[-1], 1))
            notes = []
            if row in field_notes:
                notes.append(field_notes[row])
            if row in arg_notes:
                notes.append(arg_notes[row])
            if o.explain and is_disasm_line:
                explain = get_operand_explanation(one_line[asm_start(one_line):])
                if explain != "":
                    notes.append(explain)
            if row in jump_notes:
                notes.append(jump_notes[row])
            if notes:
                line = line + "  ; " + "; ".join(notes)
            if is_target:
                line = line + TARGET_MARKER
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
            if is_target:
                crashcolor.set_color(crashcolor.LIGHTRED | crashcolor.BOLD)
            print(line[:idx], end='')
            if is_target:
                crashcolor.set_color(crashcolor.RESET)
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

    if skipped:
        crashcolor.set_color(crashcolor.DARKGRAY)
        print("  ...")
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

def set_call_op_list(arch=None):
    global call_op_set
    global call_exclude_set

    if arch is None:
        arch = sys_info.machine
    family = get_arch_family(arch)

    if family == "x86":
        call_op_set = [ "call", "callq" ]
    elif family == "ppc":
        call_op_set = [ "bl", "bla", "bctrl" ]
    elif family == "arm":
        call_op_set = [ "bl", "blr", "blx" ]
    elif family == "s390x":
        call_op_set = [ "brasl", "bras", "basr" ]
    elif family == "riscv":
        call_op_set = [ "jal", "jalr", "call" ]
    else:
        call_op_set = [ "call", "callq" ]


# Calls that are not part of a function's logic: tracing and return hooks.
_CALL_NOISE = ("__fentry__", "mcount", "_mcount", "__x86_return_thunk",
               "__sanitizer_cov_trace_pc")
# Thunks that make an indirect call through the register in their name.
_INDIRECT_THUNKS = ("__x86_indirect_thunk_", "__x86_indirect_call_thunk_")

# Start address of each callee seen by get_call_list(), so it can be
# disassembled by address: 'dis <name>' fails for a name that more than
# one function has ("duplicate text symbols found").
callee_address = {}


def get_call_list(disasm_str):
    """
    Return the callees of a 'dis' output, in order.

    Direct calls give the symbol ('<func>') or the bare address. A jump to
    the start of another function is a tail call and counts as a call.
    Calls through a register or memory ('call *%rax', 'blr x1', a retpoline
    thunk) can't be followed and are returned with a leading '*' so they
    are shown but not walked.
    """
    set_jump_op_list()
    call_list = []
    this_func = None
    for line in disasm_str.splitlines():
        if line == "":
            break
        words = line.split()
        if len(words) <= 3:
            continue
        if this_func is None and words[1].startswith("<"):
            this_func = words[1].rstrip(":")[1:-1].split("+")[0]
        is_call = words[2] in call_op_set
        if not is_call:
            # Tail call: 'jmp 0x... <other_func>' to another function's start.
            if not check_jump_op(words[2]) or len(words) <= 4 or \
               not words[4].startswith("<"):
                continue
            name = words[4][1:-1]
            if "+" in name or name == this_func:
                continue
        if len(words) > 4:
            if words[4].startswith("<"):
                name = words[4][1:-1]
                if name in _CALL_NOISE:
                    continue
                if name.startswith(_INDIRECT_THUNKS):
                    call_list.append("*%" + name.split("_")[-1])
                    continue
                target = get_branch_target(words)
                if target != "" and "+" not in name:
                    callee_address[name] = target
                call_list.append(name)
                continue
            if words[4].startswith("#") and len(words) > 5:
                # 'call *0x...(%rip)  # 0x...': read the pointer.
                try:
                    call_list.append("0x%x" % readULong(int(words[5], 16)))
                except Exception:
                    call_list.append("*" + words[3])
                continue
        if _RE_HEX_ADDR.match(words[3]):
            call_list.append(words[3])
        else:
            call_list.append(words[3] if words[3].startswith("*")
                             else "*" + words[3])
    return call_list


# 'dis' output parsed into callees, per function, for one 'edis -c' run.
callgraph_cache = {}
# Functions on the chain from the root to the function being expanded.
callgraph_path = []

def show_callgraph(func_name, depth, options):
    global branch_bar
    global call_op_set

    if func_name.startswith("*"):  # Indirect call: target unknown
        return

    if func_name in callgraph_path:
        crashcolor.set_color(crashcolor.LIGHTYELLOW)
        print("(recursive)", end="")
        crashcolor.set_color(crashcolor.RESET)
        return

    if depth >= options.max_depth:
        print("...", end="")
        return

    depth = depth + 1
    while (len(branch_bar) <= depth):
        branch_bar.append(LineType.LINE_SPACE)

    first = True
    call_list = callees_of(func_name)

    callgraph_path.append(func_name)
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
    callgraph_path.pop()


def callees_of(func_name):
    """Callees of a function, from its 'dis' output, cached for the run."""
    if func_name not in callgraph_cache:
        disasm_str = ""
        addr = callee_address.get(func_name)
        if addr:
            # 'dis -f <start>' is the whole function, even when another
            # function has the same name.
            try:
                disasm_str = exec_crash_command("dis -f %s" % addr)
            except Exception:
                disasm_str = ""
        if asm_start(disasm_str) != 0:
            try:
                disasm_str = exec_crash_command("dis %s" % (func_name))
            except Exception:
                disasm_str = ""
        callgraph_cache[func_name] = get_call_list(disasm_str)
    return callgraph_cache[func_name]


def show_call_paths(root, target, max_depth):
    paths = find_call_paths(root, target, max_depth, callees_of)
    if not paths:
        print("No call path from %s to %s within %d calls (raise it with -m)" %
              (root, target, max_depth))
        return
    for path in paths:
        print(" -> ".join(path[:-1]) + " -> ", end="")
        crashcolor.set_color(crashcolor.LIGHTRED | crashcolor.BOLD)
        print(path[-1])
        crashcolor.set_color(crashcolor.RESET)
    if len(paths) >= 50:
        print("(first 50 paths shown)")


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

    op.add_option("-p", "--task",
                  action="store",
                  type="string",
                  default="",
                  dest="task",
                  help="Read stack values from this pid or task's backtrace" \
                    + " instead of the current context's")

    op.add_option("-C", "--context",
                  action="store",
                  type="int",
                  default=0,
                  dest="context",
                  help="With an address or func+offset, show only N" \
                    + " instructions before and after it")

    op.add_option("-e", "--explain",
                  action="store_true",
                  dest="explain",
                  default=False,
                  help="Explain each instruction in plain English")

    op.add_option("-a", "--args",
                  action="store_true",
                  dest="args",
                  default=False,
                  help="Name the registers that carry each call's arguments")

    op.add_option("-T", "--fields",
                  action="store_true",
                  dest="fields",
                  default=False,
                  help="Name the struct field each memory access uses" \
                    + " (x86_64)")

    op.add_option("-F", "--find",
                  action="store",
                  type="string",
                  default="",
                  dest="find",
                  help="With -c, show only the call paths that reach" \
                    + " this function")

    op.add_option("--save",
                  action="store",
                  type="string",
                  default="",
                  dest="save",
                  help="Save the function's disassembly, without" \
                    + " addresses, to FILE")

    op.add_option("--diff",
                  action="store",
                  type="string",
                  default="",
                  dest="diff",
                  help="Compare the function with one saved by --save")

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


    # Without CRASHEXT_SERVER, source lines are read from this machine when
    # the files are here (see add_local_source), so -n is off by default.
    op.add_option("-n", "--noaction",
                  action="store_true",
                  dest="noaction",
                  default=False,
                  help="Plain disassembly: no source lines, no server")

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
        if len(args) == 0:
            print("ERROR> edis -c needs a function name\n",
                  "\ti.e) edis -c do_page_fault")
            return
        set_call_op_list()
        callgraph_cache.clear()
        callee_address.clear()
        del callgraph_path[:]
        if o.find:
            show_call_paths(args[0], o.find, o.max_depth)
            return
        show_callgraph_func(args[0], 0, True, o)
        show_callgraph(args[0], 0, o)
        sys.exit(0)

    if len(args) != 0:
        pykdump_path = os.environ.get("PYKDUMPPATH",
                                      os.path.dirname(os.path.abspath(__file__)))
        disasm(args[0], o, args, pykdump_path)
    else:
        print("ERROR> edis needs an address or a symbol\n",
              "\ti.e) edis 0xffffffff81c76fca or edis hugetlb_init")


if ( __name__ == '__main__'):
    edis()
