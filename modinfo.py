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


def is_our_module(module_addr):
    module = readSU("struct module", module_addr)
    if module == None:
        return False

    if module.gpgsig_ok != 0:
        return True

    return False

def module_info(options):
    global module_list

    if (len(module_list) == 0):
        load_module_details()

    print("%-18s %-25s %10s" % ("struct module *",
                      "MODULE_NAME",
                      "SIZE"))

    for module in module_list:
        if not is_our_module(module):
            crashcolor.set_color(crashcolor.LIGHTRED)
        print("0x%x %-25s %10d" % (long(module),
                                 module.name,
                                 module.core_size))
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
