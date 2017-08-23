"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *
from LinuxDump import Tasks
import sys

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

def module_info(options):
    global module_list

    if (len(module_list) == 0):
        load_module_details()

    for module in module_list:
        print("0x%x %-20s %10d" % (long(module),
                                 module.name,
                                 module.core_size))


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

def disasm_module(options):
    module = find_module(options.disasm_module)
    if (module is None):
        print("The module %s does not exist" % (options.disasm_module))
        return

    mod_func_list = []
    for sym_str_list in exec_crash_command("sym -m %s" % (module.name)).splitlines():
        spl = sym_str_list.split(' ', 2)
        if (spl[1] == 'MODULE'):
            continue
        if (spl[1] != '(t)'):
            continue
        mod_func_list.append(spl)

    for a_func in mod_func_list:
        disasm_one_func(a_func)


def modinfo():
    op = OptionParser()
    op.add_option("--disasm", dest="disasm_module", default=None,
                  action="store", type="string",
                  help="Disassemble a module functions")
    op.add_option("--reload", dest="reload_modlist", default=0,
                  action="store_true",
                  help="Show details")

    (o, args) = op.parse_args()

    if (o.reload_modlist):
        load_module_details()

    if (o.disasm_module is not None):
        disasm_module(o)
        exit(0)

    module_info(o)

if ( __name__ == '__main__'):
    modinfo()
