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

    result = exec_crash_command("rd 0x%x -e 0x%x -a" % (real_start_addr, real_end_addr))
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
    result = exec_crash_command("rd 0x%x -e 0x%x" % (real_start_addr, real_end_addr))
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

    if tainted_count > 0:
        tainted_mask = readSymbol("tainted_mask")
        taint_result = taint_str(tainted_mask)
        print("=" * 75)
        print("There are %d tainted modules, tainted_mask = 0x%x (%s)" %
              (tainted_count, tainted_mask, taint_result))
        if options.shows_flags_str and tainted_mask > 0:
            for c in taint_result.split(':')[1]:
                if c in taint_flags_desc:
                    print("\t%s : %s" % (c, taint_flags_desc[c]))


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

    return None


def disasm_one_func(func_detail):
    disasm_str = exec_crash_command("dis -l 0x%s" % (func_detail[0]))

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


    print_sym_list_section("\n.text section", text_sym_list, options)
    print_sym_list_section("\n.bss section", bss_sym_list, options)
    print_sym_list_section("\n.data section", data_sym_list, options)
    print_sym_list_section("\n.readonly_data section", readonly_sym_list, options)


def print_sym_list_section(title, sym_list, options):
    crashcolor.set_color(crashcolor.BLUE)
    print(title)
    crashcolor.set_color(crashcolor.RESET)
    for sym_entry in sym_list:
        print("0x%s %s %s" %
            (sym_entry[0], sym_entry[1], sym_entry[2]))
        if options.show_contents == False:
            continue

        data = "0x%016x" % readULong(int(sym_entry[0], 16))
        first_byte = str(chr(readU8(int(sym_entry[0], 16))))
        try:
            if data.startswith("0xf"):
                data_str = exec_crash_command("sym %s" % (data))
                if data_str.startswith("sym:"):
                    data_str = "<no symbol>"
                else:
                    data_str = "sym: %s" % data_str.split()[2]
            elif first_byte.isprintable():
                data_str = exec_crash_command("rd -a 0x%s" % (sym_entry[0]))
                data_str = "\"%s\"" % data_str.split()[1]
            else:
                data_str = "= %d" % int(data, 16)
        except:
            data_str = "= %d" % int(data, 16)
            pass

        crashcolor.set_color(crashcolor.YELLOW)
        print("\t( %s %s )" % (data, data_str))
        crashcolor.set_color(crashcolor.RESET)



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

    (o, args) = op.parse_args()

    if (o.disasm_module is not None):
        disasm_module(o)
        sys.exit(0)

    if (o.module_detail is not None):
        show_module_detail(o)
        sys.exit(0)

    module_info(o)


if ( __name__ == '__main__'):
    modinfo()
