"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *
from LinuxDump import Tasks
import sys
import crashcolor

module_list = []
def load_module_details():
    # Most of the part is borrowed from lsModules in API.py
    # - Daniel Kwon
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



def module_info(options):
    global module_list

    if (len(module_list) == 0):
        load_module_details()

    print("%-18s %-25s %10s %s" % ("struct module *",
                      "MODULE_NAME",
                      "SIZE",
                      "ALLOC_SIZE    GAPSIZE" if options.shows_gaps else ""))

    tainted_count = 0
    prev_end_addr = 0
    for module in module_list:
        if options.shows_gaps or options.shows_addr:
            alloc_size, start_addr, end_addr = get_module_alloc_data(module)
            if prev_end_addr == 0:
                prev_end_addr = start_addr

        tainted = not is_our_module(module)
        if options.shows_tainted and not tainted:
            continue
        if tainted:
            tainted_count = tainted_count + 1
            crashcolor.set_color(crashcolor.LIGHTRED)
        gap_info_str = ""
        if options.shows_gaps:
            gap_info_str = "%10d %10d" % (alloc_size, start_addr - prev_end_addr)
            prev_end_addr = end_addr

        print("0x%x %-25s %10d %s" % (long(module),
                                 module.name,
                                 module.core_size,
                                 gap_info_str))
        if options.shows_addr:
            print(" " * 3, end="")
            crashcolor.set_color(crashcolor.UNDERLINE)
            print("addr range : 0x%x - 0x%x" % (start_addr, end_addr))
        crashcolor.set_color(crashcolor.RESET)

    if tainted_count > 0:
        print("=" * 75)
        print("There are %d tainted modules" % (tainted_count))


    last_unloaded_module = readSymbol("last_unloaded_module")
    if len(last_unloaded_module) > 0:
        crashcolor.set_color(crashcolor.BLUE)
        print("\n\tLast unloaded module : %s" % (last_unloaded_module))
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


    print_sym_list_section("\n.text section", text_sym_list)
    print_sym_list_section("\n.bss section", bss_sym_list)
    print_sym_list_section("\n.data section", data_sym_list)
    print_sym_list_section("\n.readonly_data section", readonly_sym_list)


def print_sym_list_section(title, sym_list):
    crashcolor.set_color(crashcolor.BLUE)
    print(title)
    crashcolor.set_color(crashcolor.RESET)
    for sym_entry in sym_list:
        print("0x%s %s %s" %
            (sym_entry[0], sym_entry[1], sym_entry[2]))


def modinfo():
    op = OptionParser()
    op.add_option("--disasm", dest="disasm_module", default=None,
                  action="store", type="string",
                  help="Disassemble a module functions")
    op.add_option("--details", dest="module_detail", default=None,
                  action="store", type="string",
                  help="Show details")
    op.add_option("-t", dest="shows_tainted", default=False,
                  action="store_true",
                  help="Shows tainted modules only")
    op.add_option("-g", dest="shows_gaps", default=False,
                  action="store_true",
                  help="Shows gaps between modules as well as phyiscally allocated sizes")
    op.add_option("-a", dest="shows_addr", default=False,
                  action="store_true",
                  help="Shows address range for the module")

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
