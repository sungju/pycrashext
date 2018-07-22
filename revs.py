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

def show_registers():
    arch = sys_info.machine
    if (arch in ("x86_64", "i386", "i686", "athlon")):
        show_register_details(arch)
    if (sys_info.machine.startswith("arm")):
        show_register_details("arm")
    if (sys_info.machine.startswith("ppc")):
        show_register_details("ppc")


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
        inst_set = ["REGISTERS", "INSTRUCTION"]
        idx = 0
        with open(source_file, 'r') as f:
            for line in f:
                words = line.split(":")
                if words[0] in inst_set:
                    if words[0] == "REGISTERS":
                        arch_list = words[1] # don't split yet
                        register_details = ""
                        idx = idx + 1
                        for detail_line in f:
                            idx = idx + 1
                            if detail_line == "END_" + line:
                                arch_register_list[arch_list] = register_details
                                break
                            register_details = register_details + detail_line
                    elif words[0] == "INSTRUCTION":
                        inst_list = words[1] # don't split yet
                        inst_details = ""
                        idx = idx + 1
                        for detail_line in f:
                            idx = idx + 1
                            if detail_line == "END_" + line:
                                instruction_list[inst_list] = inst_details
                                break
                            inst_details = inst_details + detail_line
                        idx = idx + 1
                else:
                    idx = idx + 1

    except:
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

    (o, args) = op.parse_args()


    read_database()

    if (o.Asm != ""):
        show_asm_details(o.Asm)
        sys.exit(0)

    if (o.Regs):
        show_registers()
        sys.exit(0)

    show_registers()


    return

if ( __name__ == '__main__'):
    revs()
