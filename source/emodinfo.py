#!/usr/bin/env/python
# --------------------------------------------------------------------
# (C) Copyright 2018-2019 Red Hat, Inc.
#
# Author: Daniel Sungju Kwon <dkwon@redhat.com>
#
# This command 'modinfo' shows module list or individual module details
# It can be very handy to disassemble all the function in a module.
#
#
# Contributors:
# --------------------------------------------------------------------
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
from pykdump.API import *
from LinuxDump import Tasks
import sys
from datetime import datetime
import crashcolor
import crashhelper

module_list = []
def load_module_details():
    global module_list

    module_list = []
    try:
        # On older kernels, we have module_list
        kernel_module = sym2addr("kernel_module")
        if (kernel_module):
            module_list = readSymbol("module_list")
            for module in readStructNext(module_list, "next", inchead = False):
                if (long(module) == kernel_module):
                    break
                module_list.insert(0, module)
        else:
            # On new kernels, we have a listhead
            lh = ListHead(sym2addr("modules"), "struct module")
            for module in lh.list:
                module_list.insert(0, module)
    except:
        # If anything went wrong, return a partial list
        pass


    module_list = sorted(module_list, reverse=False)


def is_our_module(module_addr):
    module = readSU("struct module", module_addr)
    if module == None:
        return False

    if member_offset("struct module", "taints") > -1:
        if module.taints != 0:
            return False

    if member_offset("struct module", "sig_ok") > -1:
        return module.sig_ok != 0

    if member_offset("struct module", "gpgsig_ok") > -1:
        return module.gpgsig_ok != 0

    return True


def get_module_alloc_data(module):
    result = exec_crash_command("kmem 0x%x" % (long(module)))
    resultlines = result.splitlines()
    found = 0
    alloc_size = 0
    start_addr = 0
    end_addr = 0
    for line in resultlines:
        if found == 1:
            words = line.split()
            if len(words) < 6:
                found = 0
                continue
            alloc_size = words[5]
            start_addr = words[2]
            end_addr = words[4]
            break

        if "ADDRESS RANGE" in line:
            found = 1

    return int(alloc_size), int(start_addr, 16), int(end_addr, 16)


def do_check_unloaded_module(start_addr, end_addr):
    real_start_addr = -1
    real_end_addr = -1

    for i in range(start_addr, end_addr):
        try:
            readLong(i)
            real_start_addr = i
            break
        except:
            pass

    if real_start_addr == -1:
        return None

    real_end_addr = real_start_addr
    for i in range(real_start_addr, end_addr):
        try:
            readLong(i)
            real_end_addr = i
        except:
            break

    module, loaded_module = find_module_struct("0x%x" % real_start_addr)
    return module

'''
    Old method: Not going to use
    ----------------------------

    try:
        result = exec_crash_command("rd 0x%x -e 0x%x -a" % (real_start_addr, real_end_addr))
    except:
        result = ""
    result_lines = result.splitlines()
    prev_addr = 0
    prev_str_len = 0
    strtab_addr = 0
    for line in result_lines:
        words = line.split(':')
        line_addr = int(words[0], 16)
        if words[1].strip() == "__this_module":
            break
        if prev_addr != 0:
            if line_addr != (prev_addr + prev_str_len + 1):
                strtab_addr = line_addr - 1

        prev_addr = line_addr
        prev_str_len = len(words[1])


    if strtab_addr == 0:
        return None

    strtab_addr_str = "%x" % strtab_addr
    try:
        result = exec_crash_command("rd 0x%x -e 0x%x" % (real_start_addr, real_end_addr))
    except:
        result = ""
    result_lines = result.splitlines()
    strtab_line = ""
    for line in result_lines:
        if strtab_addr_str in line:
            strtab_line = line
            break
    if strtab_line == "":
        return None

    words = strtab_line.split(':')
    if len(words) < 2:
        return None
    addr = int(words[0], 16)
    values = words[1].split()
    strtab_offset = member_offset('struct module', 'strtab')
    module_addr = 0
    if len(values) < 2:
        return None
    if values[0] == strtab_addr_str:
        module_addr = addr - strtab_offset
    elif values[1] == strtab_addr_str:
        module_addr = (addr + 8) - strtab_offset

    if module_addr == 0:
        return None

    module = readSU("struct module", module_addr)
    return module
    '''


tainted_count = 0

taint_flags = [
    [ 'P', 'G', True ],     # TAINT_PROPRIETARY_MODULE
    [ 'F', '', True ],     # TAINT_FORCED_MODULE
    [ 'S', '', False ],    # TAINT_CPU_OUT_OF_SPEC
    [ 'R', '', False ],    # TAINT_FORCED_RMMOD
    [ 'M', '', False ],    # TAINT_MACHINE_CHECK
    [ 'B', '', False ],    # TAINT_BAD_PAGE
    [ 'U', '', False ],    # TAINT_USER
    [ 'D', '', False ],    # TAINT_DIE
    [ 'A', '', False ],    # TAINT_OVERRIDDEN_ACPI_TABLE
    [ 'W', '', False ],    # TAINT_WARN
    [ 'C', '', True ],     # TAINT_CRAP
    [ 'I', '', False ],    # TAINT_FIRMWARE_WORKAROUND
    [ 'O', '', True ],     # TAINT_OOT_MODULE
    [ 'E', '', True ],     # TAINT_UNSIGNED_MODULE
    [ 'L', '', False ],    # TAINT_SOFTLOCKUP
    [ 'K', '', True ],     # TAINT_LIVEPATCH
    [ '?', '', False ],    # TAINT_16
    [ '?', '', False ],    # TAINT_17
    [ '?', '', False ],    # TAINT_18
    [ '?', '', False ],    # TAINT_19
    [ '?', '', False ],    # TAINT_20
    [ '?', '', False ],    # TAINT_21
    [ '?', '', False ],    # TAINT_22
    [ '?', '', False ],    # TAINT_23
    [ '?', '', False ],    # TAINT_24
    [ '?', '', False ],    # TAINT_25
    [ '?', '', False ],    # TAINT_26
    [ '?', '', False ],    # TAINT_27
    [ 'H', '', False ],    # TAINT_HARDWARE_UNSUPPORTED
    [ 'T', '', True ],     # TAINT_TECH_PREVIEW
]

taint_flags_desc = {
'G' : "Tainted but all module is licensed under GNU or a compatible license",
'P' : "Proprietary module has been loaded.",
'F' : "Module has been forcibly loaded.",
'S' : "SMP with CPUs not designed for SMP.",
'R' : "User forced a module unload.",
'M' : "System experienced a machine check exception.",
'B' : "System has hit bad_page.",
'U' : "Userspace-defined naughtiness.",
'D' : "Kernel has oopsed before",
'A' : "ACPI table overridden.",
'W' : "Taint on warning.",
'C' : "modules from drivers/staging are loaded.",
'I' : "Working around severe firmware bug.",
'O' : "Out-of-tree module has been loaded.",
'E' : "Unsigned module has been loaded.",
'L' : "A soft lockup has previously occurred.",
'K' : "Kernel has been live patched.",
'T' : "TAINT_TECH_PREVIEW",
'H' : "TAINT_HARDWARE_UNSUPPORTED",
}

def taint_str(tainted_mask):
    result_str = ""

    if tainted_mask == 0:
        result_str = "Not tainted"
    else:
        result_str = "Tainted: "
        pos = 0
        while tainted_mask != 0:
            if (tainted_mask & 0x1) == 0x1:
                result_str = result_str + taint_flags[pos][0]
            else:
                result_str = result_str + taint_flags[pos][1]
            pos = pos + 1
            tainted_mask = tainted_mask >> 1

    return result_str

def module_info(options):
    global module_list
    global tainted_count

    if (len(module_list) == 0):
        load_module_details()

    print("%-18s %-25s %10s %s" % ("struct module *",
                      "MODULE_NAME",
                      "SIZE",
                      "ALLOC_SIZE    GAPSIZE" if options.shows_gaps else ""))

    tainted_count = 0
    prev_end_addr = 0
    for module in module_list:
        start_addr = end_addr = 0
        if options.shows_gaps or options.shows_addr or options.shows_unloaded:
            alloc_size, start_addr, end_addr = get_module_alloc_data(module)
            if prev_end_addr == 0:
                prev_end_addr = start_addr

        unloaded_module = None
        if options.shows_unloaded:
            if (start_addr - prev_end_addr) > 4096:
                # Check it only if the gap is more than 1 page.
                unloaded_module = do_check_unloaded_module(prev_end_addr, start_addr - 1)

        if unloaded_module != None:
            um_alloc_size, um_start_addr, um_end_addr = get_module_alloc_data(unloaded_module)
            gap_info_str = ""
            if options.shows_gaps:
                gap_info_str = "%10s %10s" % ("N/A", "N/A")
            print_module(unloaded_module, options, gap_info_str,
                         um_start_addr, um_end_addr, unloaded=True)

        gap_info_str = ""
        if options.shows_gaps:
            gap_info_str = "%10d %10d" % (alloc_size, start_addr - prev_end_addr)

        print_module(module, options, gap_info_str, start_addr, end_addr)

        if options.shows_gaps or options.shows_unloaded:
            prev_end_addr = end_addr

    tainted_mask = readSymbol("tainted_mask")
    taint_result = taint_str(tainted_mask)
    if tainted_mask > 0:
        print("=" * 75)
        print("There are %d tainted modules, tainted_mask = 0x%x (%s)" %
              (tainted_count, tainted_mask, taint_result))

    if options.shows_flags_str and tainted_mask > 0:
        for c in taint_result.split(':')[1]:
            if c in taint_flags_desc:
                print("\t%s : %s" % (c, taint_flags_desc[c]))

        print_last_unloaded_module()


def print_last_unloaded_module():
    last_unloaded_module = readSymbol("last_unloaded_module")
    if len(last_unloaded_module) > 0:
        crashcolor.set_color(crashcolor.BLUE)
        print("\n\tLast unloaded module : %s" % (last_unloaded_module))
        crashcolor.set_color(crashcolor.RESET)


def print_module(module, options, gap_info_str, start_addr, end_addr, unloaded=False):
    global tainted_count

    tainted = not is_our_module(module)
    if options.shows_tainted and not tainted:
        return
    if tainted:
        tainted_count = tainted_count + 1
        crashcolor.set_color(crashcolor.LIGHTRED)
    if unloaded:
        crashcolor.set_color(crashcolor.MAGENTA | crashcolor.BOLD)

    if member_offset("struct module", "core_layout") > -1:
        core_size = module.core_layout.size
    else:
        core_size = module.core_size

    print("0x%x %-25s %10d %s" % (long(module),
                             module.name,
                             core_size,
                             gap_info_str))
    if options.shows_addr:
        print(" " * 3, end="")
        crashcolor.set_color(crashcolor.UNDERLINE)
        print("addr range : 0x%x - 0x%x" % (start_addr, end_addr))
    crashcolor.set_color(crashcolor.RESET)


def find_module(module_name):
    global module_list

    if (len(module_list) == 0):
        load_module_details()

    for module in module_list:
        if (module.name == module_name):
            return module

    try:
        module = readSU("struct module", int(module_name, 16))
        return module
    except:
        pass

    return None


def disasm_one_func(func_detail):
    if func_detail == None or not isinstance(func_detail, list):
        return

    if len(func_detail) == 0:
        return

    try:
        disasm_str = exec_crash_command("dis -l 0x%s" % (func_detail[0]))
    except:
        return

    print ("%s BEGIN disassemble %s() %s" % ("-" * 10,
                                             func_detail[2],
                                             "-" * 10))
    print (disasm_str, end='')
    print ("%s END   disassemble %s() %s\n" % ("=" * 10,
                                               func_detail[2],
                                               "=" * 10))


def get_mod_sym_list(module_name,
                     exclude_types=None, include_types=None):
    mod_func_list = []
    try:
        for sym_str_list in exec_crash_command("sym -m %s" % (module_name)).splitlines():
            spl = sym_str_list.split(' ', 2)
            if (spl[1] == 'MODULE'):
                continue
            if (exclude_types is not None):
                if (spl[1] in exclude_types):
                    continue

            if (include_types is not None):
                if (spl[1] not in include_types):
                    continue

            mod_func_list.append(spl)
    except:
        pass

    return mod_func_list


def disasm_module(options):
    module = find_module(options.disasm_module)
    if (module is None):
        print("The module %s does not exist" % (options.disasm_module))
        return

    mod_func_list = []
    mod_func_list = get_mod_sym_list(module.name,
                                     include_types=['(t)', '(T)'])

    for a_func in mod_func_list:
        disasm_one_func(a_func)


def get_sym_type_key(sym_list):
    return sym_list[1]


def show_module_detail(options):
    module = find_module(options.module_detail)
    if (module is None):
        print("The module %s does not exist" % (options.disasm_module))
        return


    print ("%-15s : 0x%x" % ("struct module", long(module)))
    print ("%-15s : %s" % ("name", module.name))
    print ("%-15s : %s" % ("version", module.version))
    print ("%-15s : %s" % ("source ver", module.srcversion))
    print ("%-15s : %s (0x%x)" % ("init", addr2sym(module.init), module.init))
    print ("%-15s : %s (0x%x)" % ("exit", addr2sym(module.exit), module.exit))

    mod_sym_list = get_mod_sym_list(module.name)

    text_sym_list = []
    bss_sym_list = []
    data_sym_list = []
    readonly_sym_list = []

    for sym_entry in mod_sym_list:
        if (sym_entry[1] == '(T)' or sym_entry[1] == '(t)'):
            text_sym_list.insert(0, sym_entry)
            continue
        if (sym_entry[1] == '(B)' or sym_entry[1] == '(b)'):
            bss_sym_list.insert(0, sym_entry)
            continue
        if (sym_entry[1] == '(D)' or sym_entry[1] == '(d)'):
            data_sym_list.insert(0, sym_entry)
            continue
        if (sym_entry[1] == '(R)' or sym_entry[1] == '(r)'):
            readonly_sym_list.insert(0, sym_entry)
            continue


    text_sym_list = sorted(text_sym_list, reverse=False)
    bss_sym_list = sorted(bss_sym_list, reverse=False)
    data_sym_list = sorted(data_sym_list, reverse=False)
    readonly_sym_list = sorted(readonly_sym_list, reverse=False)

    print_sym_list_section("\n.text section", text_sym_list,
                           False, False, 0)
    print_sym_list_section("\n.bss section", bss_sym_list,
                           options.show_contents,
                           options.show_content_strings,
                           options.show_longer_than)
    print_sym_list_section("\n.data section", data_sym_list,
                           options.show_contents,
                           options.show_content_strings,
                           options.show_longer_than)
    print_sym_list_section("\n.readonly_data section", readonly_sym_list,
                           options.show_contents,
                           options.show_content_strings,
                           options.show_longer_than)


def check_slab(slab_addr, default_str):
     result = exec_crash_command("kmem %s" % slab_addr)
     resultlines = result.splitlines()
     found = False
     for line in resultlines:
         words = line.split()
         if found == True and words[0] != 'kmem:':
             return "SLAB: '%s'" % words[-1]

         if words[0] == 'CACHE':
             found = True
             continue

     return default_str


def print_sym_list_section(title, sym_list, show_contents,
                           show_strings, min_line_length):
    crashcolor.set_color(crashcolor.BLUE)
    print(title)
    crashcolor.set_color(crashcolor.RESET)
    start_addr = end_addr = ""
    for sym_entry in sym_list:
        if start_addr == "":
            start_addr = sym_entry[0]
        end_addr = sym_entry[0]

        print("0x%s %s %s" %
            (sym_entry[0], sym_entry[1], sym_entry[2]))
        if show_contents == False:
            continue

        data = "0x%016x" % readULong(int(sym_entry[0], 16))
        first_byte = str(chr(readU8(int(sym_entry[0], 16))))
        try:
            if data.startswith("0xf"):
                data_str = exec_crash_command("sym %s" % (data))
                if data_str.startswith("sym:"):
                    data_str = check_slab(data, "<no symbol>")
                else:
                    data_str = "sym: %s" % data_str.split()[2]
            elif first_byte.isprintable():
                try:
                    data_str = exec_crash_command("rd -a 0x%s" % (sym_entry[0]))
                    data_str = "\"%s\"" % data_str.split()[1]
                except:
                    data_str = "= %d" % int(data, 16)
                    pass
            else:
                data_str = "= %d" % int(data, 16)
        except:
            data_str = "= %d" % int(data, 16)
            pass

        crashcolor.set_color(crashcolor.YELLOW)
        print("\t( %s %s )" % (data, data_str))
        crashcolor.set_color(crashcolor.RESET)


    if show_strings == True and start_addr != "" and start_addr != end_addr:
        try:
            result = exec_crash_command("rd 0x%s -e 0x%s -a" %\
                                        (start_addr, end_addr))
        except:
            result = ""

        lines = result.splitlines()
        crashcolor.set_color(crashcolor.GREEN)
        for line in lines:
            words = line.split()
            if len(words) > 1:
                dataindex = line.index(words[0]) + len(words[0])
                content_len = len(line[dataindex:].strip())
                if content_len >= min_line_length:
                    print(line)
        crashcolor.set_color(crashcolor.RESET)


def batch_run_all(o):
    o.show_contents = True
    o.show_content_strings = True
    o.disasm_module = o.batch_run

    #o.shows_tainted = True
    o.shows_gaps = True
    o.shows_addr = True
    o.shows_unloaded = False
    o.shows_flags_str = True
    o.module_detail = o.batch_run

    '''
    print("\t%s %-40s %s\n" % ("="*10, "Module list for '%s'" % o.batch_run, "="*10))
    module_info(o)
    print("\n")
    '''

    print("\t%s %-40s %s\n" % ("="*10, "Module Details for '%s'" % o.batch_run, "="*10))
    show_module_detail(o)
    print("\n")

    print("\t%s %-40s %s\n" % ("="*10, "Module Disassemble for '%s'" % o.batch_run, "="*10))
    disasm_module(o)
    print("\n")



def get_module_list(tainted_only):
    global module_list

    if (len(module_list) == 0):
        load_module_details()

    result_list = []
    for module in module_list:
        if tainted_only and is_our_module(module):
            continue
        result_list.append(module)

    return result_list


def set_error(error_path):
    return "" # 'set error' seems buggy, avoid to use it for now.
    result = exec_crash_command("help -p")
    lines = result.splitlines()
    for line in lines:
        words = line.split()
        if words[0] == 'error_path:':
            exec_crash_command("set error %s" % error_path)
            return words[1]

    return ""


def try_get_module_struct(options):
    module, loaded_module = find_module_struct(options.module_addr)
    if module is not None:
        print("Found the below module")
        print("\tstruct module 0x%x" % module)
        print("\tname : %s" % module.name)
        print("\tstatus : %s" % loaded_module)
        if options.show_symtab:
            show_manual_module_detail(options, module)
    else:
        crashcolor.set_color(crashcolor.RED)
        print("\nCannot find module structure for %s" % options.module_addr)
        crashcolor.set_color(crashcolor.RESET)
        module_addr_min = 0
        module_addr_max = 0
        module_addr = int(options.module_addr, 16)
        try:
            module_addr_min = readSymbol("module_addr_min")
            module_addr_max = readSymbol("module_addr_max")
        except:
            pass

        if module_addr_max == 0:
            try:
                mod_tree = readSymbol("mod_tree")
                module_addr_min = mod_tree.addr_min
                module_addr_max = mod_tree.addr_max
            except:
                pass

        if (module_addr_min < module_addr) and (module_addr < module_addr_max):
            print("\nThis address belongs to module allocation memory range")
            print("\tmodule address min: 0x%x" % (module_addr_min))
            print("\tmodule address max: 0x%x" % (module_addr_max))

    print_last_unloaded_module()


def read_string(addr, delimiter=0x0):
    result = ""
    idx = 0
    while True:
        one_byte = readU8(addr + idx)
        idx = idx + 1
        if one_byte == delimiter:
            break
        result = result + str(chr(one_byte))

    return result


def get_strtab_dict(options, module):
    result = {}
    if member_offset("struct module", "core_kallsyms") >= 0:
        strtab = Addr(module.core_kallsyms.strtab)
    else:
        strtab = Addr(module.strtab)
    idx = 0
    no_more = False
    while True:
        one_symbol = read_string(strtab + idx, 0x0)
        result[idx] = one_symbol
        idx = idx + len(one_symbol) + 1
        if len(one_symbol) == 0:
            if no_more == True:
                break
            else:
                no_more = True

    return result


STT_NOTYPE  = 0
STT_OBJECT  = 1
STT_FUNC    = 2
STT_SECTION = 3
STT_FILE    = 4
STT_COMMON  = 5
STT_TLS     = 6


def get_sym_type_str(sym_type):
    sym_type = sym_type & 0xf
    if sym_type == (1 << STT_OBJECT):
        return "DATA"
    elif sym_type == (1 << STT_FUNC):
        return "FUNCTION"
    elif sym_type == (1 << STT_SECTION):
        return "SECTION"
    elif sym_type == (1 << STT_FILE):
        return "FILE"
    elif sym_type == (1 << STT_COMMON):
        return "COMMON"
    elif sym_type == (1 << STT_TLS):
        return "TLS"

    return "NOTYPE"


def show_manual_module_detail(options, module):
    # Not using at the moment
    syms = module.syms
    num_syms = module.num_syms
    num_gpl_syms = module.num_gpl_syms

    # symtab and core_symtab are same
    if member_offset("struct module", "core_kallsyms") >= 0:
        symtab = module.core_kallsyms.symtab
        num_symtab = module.core_kallsyms.num_symtab
    else:
        symtab = module.symtab
        num_symtab = module.num_symtab

    strtab = get_strtab_dict(options, module)
    symtab_per_type = {}

    for i in range(0, num_symtab):
        symtab_type = symtab[i].st_info & 0xf
        if symtab_type not in symtab_per_type:
            symtab_dict = {}
            symtab_per_type[symtab_type] = symtab_dict
        else:
            symtab_dict = symtab_per_type[symtab_type]

        symtab_dict[strtab[symtab[i].st_name]] = symtab[i]

    print()
    print("=+" * 30)
    reset_color = crashcolor.get_color(crashcolor.RESET)
    for sym_type in symtab_per_type:
        sym_type_str = get_sym_type_str(sym_type)
        print("[[[ %s ]]]" % (sym_type_str))
        symtab_dict = symtab_per_type[sym_type]
        if sym_type_str == "FUNCTION":
            sym_color = crashcolor.get_color(crashcolor.BLUE)
        elif sym_type_str == "DATA":
            sym_color = crashcolor.get_color(crashcolor.GREEN)
        else:
            sym_color = crashcolor.get_color(crashcolor.YELLOW)

        for sym_name in symtab_dict:
            sym_data = symtab_dict[sym_name]
            print("0x%x (%s%s%s) for %d bytes" %
                  (sym_data.st_value, sym_color, sym_name,
                   reset_color, sym_data.st_size))
            if options.show_contents or options.reverse_disasm:
                show_symbol_detail(options, sym_type, sym_data)
        print("--" * 30)
        print()


def show_symbol_detail(options, sym_type, sym_data):
    if sym_type == (1 << STT_FUNC) and options.reverse_disasm:
        print("\t", end="")
        print(sym_data)
        show_disasm(sym_data.st_value, sym_data.st_size)
        print()
    elif sym_type == (1 << STT_OBJECT) and options.show_contents:
        print("\t", end="")
        print(sym_data)
        show_variable(sym_data.st_value, sym_data.st_size)
        print()


def show_disasm(addr, size):
    if size == 0:
        return

    count = int(size / 2)
    if count < 10:
        count = 10

    result = exec_crash_command("dis 0x%x 0x%x" % (addr, count))
    lines = result.splitlines()
    end_addr = "0x%x" % (addr + size)
    for line in lines:
        if line == "Quit":
            sys.exit(0)
        if line.strip().startswith(end_addr):
            break
        print(line)


def show_variable(addr, size):
    if size < 8:
        size = 8
    result = exec_crash_command("rd 0x%x %d" % (addr, size/8))
    lines = result.splitlines()
    crashcolor.set_color(crashcolor.CYAN)
    for line in lines:
        print("\t%s" % (line))
    crashcolor.set_color(crashcolor.RESET)


MODULE_STATE_LIVE = 0

def find_module_struct(module_addr):
    try:
        result = exec_crash_command("kmem %s" % module_addr)
        found = False
        address_line = ""
        loaded_module = "unloaded"
        if result.find("__this_module") > 0:
            loaded_module = "loaded"

        for line in result.splitlines():
            if found == True:
                address_line = line
                break
            if line.strip().startswith("VMAP_AREA"):
                found = True

        words = address_line.split()
        start_addr = words[2]
        end_addr = words[4]
        module_ktype = sym2addr("module_ktype")
        result = exec_crash_command("search -s %s -e %s 0x%x" %
                                    (start_addr, end_addr, module_ktype))
        if len(result) > 0:
            ktype_location = int(result.split(":")[0], 16)
            offset = member_offset("struct module", "mkobj")
            offset = offset + member_offset("struct module_kobject", "kobj")
            offset = offset + member_offset("struct kobject", "ktype")
            module = readSU("struct module", ktype_location - offset)
            if module.state == MODULE_STATE_LIVE:
                loaded_module = "loaded"
            return module, loaded_module
    except:
        pass

    return None, ""


def modinfo():
    op = OptionParser()
    op.add_option("--disasm", dest="disasm_module", default=None,
                  action="store", type="string",
                  help="Disassemble a module functions")
    op.add_option("--details", dest="module_detail", default=None,
                  action="store", type="string",
                  help="Show details")
    op.add_option("-c", "--contents", dest="show_contents", default=False,
                  action="store_true",
                  help="Show contents of each symbols")
    op.add_option("-t", dest="shows_tainted", default=False,
                  action="store_true",
                  help="Shows tainted modules only")
    op.add_option("-g", dest="shows_gaps", default=False,
                  action="store_true",
                  help="Shows gaps between modules as well as phyiscally allocated sizes")
    op.add_option("-a", dest="shows_addr", default=False,
                  action="store_true",
                  help="Shows address range for the module")
    op.add_option("-u", dest="shows_unloaded", default=False,
                  action="store_true",
                  help="Shows unloaded module data if possible")
    op.add_option("-f", dest="shows_flags_str", default=False,
                  action="store_true",
                  help="Shows meanings of tainted flags")
    op.add_option("-s", dest="show_content_strings", default=False,
                  action="store_true",
                  help="Shows strings from each data section")
    op.add_option("-l", dest="show_longer_than", default=5,
                  action="store", type="int",
                  help="Set the minimum size to show for -s. default=5")
    op.add_option("--batch_run", dest="batch_run", default=None,
                  action="store", type="string",
                  help="Run major options all together to get detailed info")
    op.add_option("--target_dir", dest="target_dir", default=None,
                  action="store", type="string",
                  help="Result will be saved in this directory")
    op.add_option("--nodate", dest="nodate", default=False,
                  action="store_true",
                  help="Do not use date in target filename")
    op.add_option('-m', '--module', dest="module_addr", default=None,
                  action="store", type="string",
                  help="Trying to retrieve module structure")
    op.add_option('-y', '--symtab', dest="show_symtab", default=None,
                  action="store_true",
                  help="Trying to retrieve module's symbols")
    op.add_option('-r', '--reverse', dest="reverse_disasm", default=None,
                  action="store_true",
                  help="Trying to disasm from unloaded module")


    (o, args) = op.parse_args()

    if (o.module_addr is not None):
        try_get_module_struct(o)
        sys.exit(0)

    if (o.disasm_module is not None):
        error_origin = set_error("redirect")
        disasm_module(o)
        set_error(error_origin)
        sys.exit(0)

    if (o.module_detail is not None):
        error_origin = set_error("redirect")
        show_module_detail(o)
        set_error(error_origin)
        sys.exit(0)


    if (o.batch_run is not None):
        mod_list = []
        if o.batch_run == "*":
            mod_list = get_module_list(o.shows_tainted)
        else:
            mod_list = [find_module(o.batch_run)]

        orig_stdout = sys.stdout
        for module in mod_list:
            o.batch_run = module.name
            if o.target_dir is not None:
                sys.stdout = orig_stdout
                if o.nodate == False:
                    date_str = datetime.now().strftime("-%m%d%Y")
                else:
                    date_str = ""
                target_file = "%s/%s%s.txt" % (o.target_dir, o.batch_run, date_str)
                print("Processing module '%s' on %s" % (o.batch_run, target_file))
                sys.stdout = open(target_file, 'w')

            error_origin = set_error("redirect")
            batch_run_all(o)
            print()
            print("\t%s %s %s\n" % ("="*10, "vmcore information", "="*10))
            print(sys_info)
            set_error(error_origin)
            if o.target_dir is not None:
                sys.stdout.close()
                sys.stdout = orig_stdout
            print("Done\n")
        sys.exit(0)

    module_info(o)


if ( __name__ == '__main__'):
    modinfo()
