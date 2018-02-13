"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function

from pykdump.API import *

import sys
from optparse import OptionParser

def revs_x86():
    print ("""
** function parameters for x86_64 **
%rdi - 1st argument (%rdi:64, %edi:32, %di:16, %dl:8)
%rsi - 2nd argument (%rsi:64, %esi:32, %si:16, %sl:8)
%rdx - 3rd argument (%rdx:64, %edx:32, %dx:16, %dl:8)
%rcx - 4th argument (%rcx:64, %ecx:32, %cx:16, %cl:8)
%r8 - 5th argument (%r8:64, %r8d:32, %r8w:16, %r8b:8)
%r9 - 6th argument (%r9:64, %r9d:32, %r9w:16, %r9b:8)
%rsp - Stack pointer
%rax - Return value""")


inst_list = [
    ["lea",
"""
lea - Load effective address
     The lea instruction places the address specified by its
     first operandinto the register specified by its second
     operand.Note, the contents of the memory location are
     notloaded, only the effective address is computed and
     placed into the register.This is useful for obtaining
     a pointer into a memory region or to perform simple
     arithmetic operations.

     Syntax
     lea <mem>, <reg32>

     Examples
     lea (%ebx,%esi,8), %edi - the quantity EBX+8*ESI is placed in EDI.
     lea val(,1), %eax - the value val is placed in EAX.

"""
     ],
     ["je jne jz jg jge jl jle",
"""
j<condition> - Conditional jump

        These instructions are conditional jumps that are based on
        the status ofa set of condition codes that are stored in a
        special register calledthe machine status word. The contents
        of the machine statusword include information about the last
        arithmetic operationperformed. For example, one bit of this
        word indicates if the lastresult was zero. Another indicates
        if the last result wasnegative. Based on these condition codes,
        a number of conditional jumpscan be performed. For example,
        the jzinstruction performs a jump to the specified operand label
        if the resultof the last arithmetic operation was zero.
        Otherwise, control proceedsto the next instruction in sequence.

        A number of the conditional branches are given names that
        areintuitively based on the last operation performed being
        a specialcompare instruction, cmp (see below). For example,
        conditional branchessuch as jle and jne are based on first
        performing a cmp operationon the desired operands.


        Syntax
            je <label> (jump when equal)
            jne <label> (jump when not equal)
            jz <label> (jump when last result was zero)
            jg <label> (jump when greater than)
            jge <label> (jump when greater than or equal to)
            jl <label> (jump when less than)
            jle <label> (jump when less than or equal to)

        Example
            cmp %ebx, %eax
            jle done

            If the contents of EAX are less than or equal to the contents
            of EBX,jump to the label done.  Otherwise, continue to the
            nextinstruction.
"""
      ]
]


def show_asm_details( asm_inst ):
    for (inst, inst_man) in inst_list:
        if (asm_inst in inst):
            print ("%s" % (inst_man))
            return

    return

def revs_arm():
    # ARM register details
    print ("""
** function parameters for ARM **
X0 - X29: General Purpose Registers
    X0 - X7     : Arguments & Result
    X8          : Indirect result (struct) location
    X9 - X15    : Spare temp registers
    X16 - X17   : Intra-call registers (PLT, linker)
    X18         : Platform specific (TLS)
    X19 - X28   : Callee-saved registers
    X29         : Frame pointer
X30: This is the Link Register (LR)""")


def show_registers():
    if (sys_info.machine in ("x86_64", "i386", "i686", "athlon")):
        revs_x86()
    if (sys_info.machine.startswith("arm")):
        revs_arm()

def revs():
    op = OptionParser()
    op.add_option("--regs", dest="Regs", default=0,
                  action="store_true",
                  help="Registers used for argument passing")

    op.add_option('--asm', dest='Asm', default="",
                action="store",
                help="Simple manual for GNU assembly")

    (o, args) = op.parse_args()

    if (o.Asm != ""):
        show_asm_details(o.Asm)

    if (o.Regs):
        show_registers()


    return

if ( __name__ == '__main__'):
    revs()
