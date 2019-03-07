"""
Helper tool for reverse engineering steps

 Written by Daniel Sungju Kwon
"""

from __future__ import print_function

from pykdump.API import *

import sys
import os
from optparse import OptionParser


arch_register_list = {}
instruction_list = {}

def show_register_details(arch):
    for arch_list_str in arch_register_list:
        arch_list = arch_list_str.split()
        if (arch in arch_list):
            register_details = arch_register_list[arch_list_str]
            print("%s" % (register_details))


def show_asm_details( asm_inst ):
    for inst_list_str in instruction_list:
        inst_list = inst_list_str.split()
        if (asm_inst in inst_list):
            inst_man = instruction_list[inst_list_str]
            print ("%s" % (inst_man))
            return

    return


def show_asm_list():
    for inst_list_str in instruction_list:
        print("%s" % (inst_list_str.strip()))

def show_registers():
    arch = sys_info.machine
    if (arch in ("x86_64", "i386", "i686", "athlon")):
        show_register_details(arch)
    if (sys_info.machine.startswith("arm")):
        show_register_details("arm")
    if (sys_info.machine.startswith("ppc")):
        show_register_details("ppc")


def is_arch_match(arch, arch_list_str):
    arch_list = arch_list_str.split()
    for arch_entry in arch_list:
        if arch.startswith(arch_entry):
            return True
    return False


def read_database():
    file_lines = []
    try:
        cmd_path_list = os.environ["PYKDUMPPATH"]
        path_list = cmd_path_list.split(':')
        source_file = ""
        for path in path_list:
            if os.path.exists(path + "/revs.data"):
                source_file = path + "/revs.data"
                break

        arch = sys_info.machine
        arch_total_msg = ""
        with open(source_file, 'r') as f:
            for line in f:
                words = line.split(":")
                if words[0] == "ARCHITECTURE":
                    arch_list = words[1]
                    if is_arch_match(arch, arch_list) == False:
                        continue

                    for detail_line in f:
                        if detail_line == "END_" + line:
                            break
                        arch_total_msg = arch_total_msg + detail_line


        inst_set = ["REGISTERS", "INSTRUCTION"]
        cur_mode = 0
        cur_data_line = ""
        arch_list = ""
        total_line = ""

        for line in arch_total_msg.splitlines():
            words = line.split(":")
            if words[0] in inst_set:
                cur_data_line = line
                if words[0] == "REGISTERS":
                    arch_list = words[1] # don't split yet
                    total_line = ""
                    cur_mode = 1
                elif words[0] == "INSTRUCTION":
                    inst_list = words[1] # don't split yet
                    total_line = ""
                    cur_mode = 2
            elif line == "END_" + cur_data_line:
                if cur_mode == 1: # register
                    arch_register_list[arch_list] = total_line
                elif cur_mode == 2: # instruction
                    instruction_list[inst_list] =  total_line

                cur_data_line = ""
                arch_list = ""
                inst_list = ""
                total_line = ""
                cur_mode = 0
            else:
                total_line = total_line + line + "\n"

    except Exception as e:
        print(e)
        print("Failed to read file %s" % (source_file))
        return


def revs():
    op = OptionParser()
    op.add_option("--regs", dest="Regs", default=0,
                  action="store_true",
                  help="Registers used for argument passing")

    op.add_option('--asm', dest='Asm', default="",
                action="store",
                help="Simple manual for GNU assembly")

    op.add_option('--list', dest='List', default=0,
                action="store_true",
                help="Shows the list of instructions you can check details")

    (o, args) = op.parse_args()


    read_database()

    if (o.Asm != ""):
        show_asm_details(o.Asm)
        sys.exit(0)

    if (o.Regs):
        show_registers()
        sys.exit(0)


    if (o.List):
        show_asm_list()
        sys.exit(0)

    show_registers()


    return

if ( __name__ == '__main__'):
    revs()
