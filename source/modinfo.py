"""
'modinfo' command: module list and per-module details, including disassembly.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from pykdump.API import *
from LinuxDump import Tasks
import sys
import re
import struct as pystruct
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
                if (int(module) == kernel_module):
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


# Since 6.4 (RHEL 9.4+) a module's memory is mem[MOD_MEM_NUM_TYPES], one
# struct module_memory per type, instead of core_layout and init_layout.
MOD_CORE_TYPES = (0, 1, 2, 3)   # MOD_TEXT, MOD_DATA, MOD_RODATA, MOD_RO_AFTER_INIT
MOD_INIT_TYPES = (4, 5, 6)      # MOD_INIT_TEXT, MOD_INIT_DATA, MOD_INIT_RODATA


def _mem_range(module, types):
    """(base, size) of the mem[] entries in `types`: the lowest base and the
    sum of the sizes, or (0, 0) when the kernel has no mem[]."""
    base = 0
    size = 0
    for t in types:
        m = module.mem[t]
        if int(m.size) == 0:
            continue
        b = int(m.base)
        base = b if base == 0 else min(base, b)
        size = size + int(m.size)
    return base, size


def get_module_core_size(module):
    """Return core section size across all kernel versions (RHEL6-10)."""
    try:                          # RHEL8, RHEL9 < 9.4: core_layout.size
        return int(module.core_layout.size)
    except Exception:
        pass
    try:                          # RHEL6/7: core_size field directly
        return int(module.core_size)
    except Exception:
        pass
    try:                          # 6.4+ (RHEL 9.4+, RHEL10): mem[]
        return _mem_range(module, MOD_CORE_TYPES)[1]
    except Exception:
        pass
    return 0


def get_module_core_base(module):
    """Return core section base address across all kernel versions (RHEL6-10)."""
    try:                          # RHEL8, RHEL9 < 9.4: core_layout.base
        return int(module.core_layout.base)
    except Exception:
        pass
    try:                          # RHEL6/7: module_core field directly
        return int(module.module_core)
    except Exception:
        pass
    try:                          # 6.4+ (RHEL 9.4+, RHEL10): mem[MOD_TEXT]
        return int(module.mem[0].base)
    except Exception:
        pass
    return 0


def get_module_init_range(module):
    """(base, size) of the init sections; size is 0 once they are freed
    after a successful load."""
    for get in (lambda: (int(module.init_layout.base), int(module.init_layout.size)),
                lambda: (int(module.module_init), int(module.init_size)),
                lambda: _mem_range(module, MOD_INIT_TYPES)):
        try:
            return get()
        except Exception:
            pass
    return 0, 0


def vmap_area(addr):
    """(size, start, end) of the vmap area 'kmem <addr>' shows, or None."""
    try:
        result = exec_crash_command("kmem 0x%x" % addr)
    except Exception:
        return None
    found = False
    for line in result.splitlines():
        if found:
            words = line.split()
            if len(words) < 6:
                found = False
                continue
            try:
                return int(words[5]), int(words[2], 16), int(words[4], 16)
            except ValueError:
                return None
        if "ADDRESS RANGE" in line:
            found = True
    return None


def get_module_alloc_data(module):
    """
    (allocated size, start, end) of a module's memory. Before 6.4 one vmap
    area holds the whole core, struct module included. With mem[] (RHEL
    9.4+) each core type has its own: the sizes are summed, and the range
    runs from the lowest start to the highest end.
    """
    areas = []
    try:
        for t in MOD_CORE_TYPES:
            m = module.mem[t]
            if int(m.size):
                area = vmap_area(int(m.base))
                if area and area not in areas:
                    areas.append(area)
    except Exception:
        area = vmap_area(int(module))
        if area:
            areas.append(area)
    if not areas:
        # No vmap area in 'kmem' output: use the core layout instead.
        base = get_module_core_base(module)
        size = get_module_core_size(module)
        return size, base, base + size
    return (sum(a[0] for a in areas), min(a[1] for a in areas),
            max(a[2] for a in areas))


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

# Used only when the vmcore has neither taint_flags[] (4.10+) nor tnts[]
# (RHEL 7): the RHEL 7 bits. RHEL assigns its own letters to bits 26-31 and
# they differ between releases, so they are read from the vmcore when it can.
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
] + [ [ '?', '', False ] for _bit in range(16, 28) ] + [
    [ 'H', '', False ],    # TAINT_HARDWARE_UNSUPPORTED (RHEL 7)
    [ 'T', '', True ],     # TAINT_TECH_PREVIEW (RHEL 7)
]

# What each letter means. RHEL 8 shows a removed feature as 'r', RHEL 9 as 'h'.
taint_flags_desc = {
'G' : "All loaded modules are GPL or a compatible license.",
'P' : "Proprietary module has been loaded.",
'F' : "Module has been forcibly loaded.",
'S' : "Kernel running on an out of specification system.",
'R' : "User forced a module unload.",
'M' : "System experienced a machine check exception.",
'B' : "System has hit bad_page (bad page reference or unexpected page flags).",
'U' : "Userspace-defined naughtiness.",
'D' : "Kernel has oopsed or BUGed before.",
'A' : "ACPI table overridden.",
'W' : "Kernel issued a warning.",
'C' : "Module from drivers/staging has been loaded.",
'I' : "Working around severe firmware bug.",
'O' : "Out-of-tree module has been loaded.",
'E' : "Unsigned module has been loaded.",
'L' : "A soft lockup has previously occurred.",
'K' : "Kernel has been live patched.",
'X' : "Auxiliary taint, defined for and used by distros.",
'T' : "Kernel was built with the struct randomization plugin"
      " (RHEL 7: a Technology Preview feature has been used).",
'N' : "An in-kernel test has been run.",
'J' : "Userspace used a mutating debug operation in fwctl.",
'r' : "RHEL: support for a feature or hardware in use has been removed.",
'h' : "RHEL: support for a feature or hardware in use has been removed.",
'p' : "RHEL: a partner-supported module has been loaded.",
't' : "RHEL: a Technology Preview feature has been used.",
'u' : "RHEL: unprivileged BPF has been enabled.",
'H' : "RHEL 7: unsupported hardware has been detected.",
}


def _flag_char(value):
    """A taint_flag c_true/c_false member as a one-character string."""
    if isinstance(value, int):
        return chr(value)
    return str(value)[:1] or " "


_taint_table = None

def kernel_taint_table():
    """
    [(c_true, c_false, module)] per taint bit, from the vmcore's own
    taint_flags[] when it has one, else the table above. c_false is ''
    when the kernel prints a blank for an unset bit.
    """
    global _taint_table
    if _taint_table is None:
        try:
            table = []
            for flag in readSymbol("taint_flags"):
                c_false = _flag_char(flag.c_false)
                table.append((_flag_char(flag.c_true),
                              "" if c_false in (" ", "-") else c_false,
                              bool(flag.module)))
            _taint_table = table
        except Exception:
            _taint_table = rhel7_taint_table()
    return _taint_table


def rhel7_taint_table():
    """The RHEL 7 kernel's tnts[] ({bit, true, false}) as a table, or the
    built-in table when the vmcore doesn't have it either."""
    table = [(t[0], t[1], t[2]) for t in taint_flags]
    try:
        for tnt in readSymbol("tnts"):
            bit = int(tnt.bit)
            c_false = _flag_char(getattr(tnt, "false"))
            entry = (_flag_char(getattr(tnt, "true")),
                     "" if c_false in (" ", "-") else c_false,
                     table[bit][2] if bit < len(table) else False)
            while len(table) <= bit:
                table.append(("?", "", False))
            table[bit] = entry
    except Exception:
        pass
    return table


def taint_letters(mask, table, module_only=False):
    """
    The letters for a taint mask, in bit order. For the kernel's mask an
    unset bit can still print a letter ('G' for no proprietary module);
    for a module's own taints (module_only) only the set bits that apply
    to modules print, as /proc/modules and 'mod -t' show them.
    """
    letters = ""
    for bit, (c_true, c_false, is_module) in enumerate(table):
        if module_only and not is_module:
            continue
        if mask & (1 << bit):
            letters = letters + c_true
        elif not module_only:
            letters = letters + c_false
    for bit in range(len(table), 64):       # bits the table doesn't name
        if mask & (1 << bit):
            letters = letters + "?"
    return letters


def taint_str(tainted_mask):
    if tainted_mask == 0:
        return "Not tainted"
    return "Tainted: " + taint_letters(tainted_mask, kernel_taint_table())


def module_taints(module):
    """A module's own taint letters, '' when it has none."""
    try:
        return taint_letters(int(module.taints), kernel_taint_table(),
                             module_only=True)
    except Exception:
        return ""


MODULE_STATES = {0: "LIVE", 1: "COMING", 2: "GOING", 3: "UNFORMED"}

def module_state(module):
    try:
        state = int(module.state)
    except Exception:
        return ""
    return MODULE_STATES.get(state, "state %d" % state)


def module_refs(module):
    """What lsmod shows as 'Used by': refcnt minus MODULE_REF_BASE (1).
    None when the kernel keeps per-cpu counters instead (before 4.0)."""
    try:
        return int(module.refcnt.counter) - 1
    except Exception:
        return None


def module_info(options):
    global module_list
    global tainted_count

    if (len(module_list) == 0):
        load_module_details()

    print("%-18s %-25s %10s %5s %-7s %s" % ("struct module *",
                      "MODULE_NAME",
                      "SIZE", "REFS", "TAINTS",
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
    if tainted_mask == 0 and (options.shows_tainted or options.shows_flags_str):
        print("=" * 75)
        print("Not tainted (tainted_mask = 0)")
    if tainted_mask > 0:
        print("=" * 75)
        print("There are %d tainted modules, tainted_mask = 0x%x (%s)" %
              (tainted_count, tainted_mask, taint_result))

    if options.shows_flags_str and tainted_mask > 0:
        print_taint_meanings(taint_result.split(':')[1].strip())
        print_last_unloaded_module()


def print_taint_meanings(letters, indent="\t"):
    for c in letters:
        if c in taint_flags_desc:
            print("%s%s : %s" % (indent, c, taint_flags_desc[c]))
        elif c != " ":
            print("%s%s : (no description; see the kernel's taint_flags)" % (indent, c))


def last_unloaded_module_str():
    """
    The last unloaded module's name, '' if none. RHEL 9.2+ keeps it as a
    struct with its taints as well ('name (taints: OE)'); older kernels as
    a char array.
    """
    try:
        lum = readSymbol("last_unloaded_module")
    except Exception:
        return ""
    if isinstance(lum, str):
        return lum
    try:
        name = str(lum.name)
        taints = str(lum.taints).strip()
    except Exception:
        return ""
    if name and taints:
        return "%s (taints: %s)" % (name, taints)
    return name


def print_last_unloaded_module():
    last_unloaded_module = last_unloaded_module_str()
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

    core_size = get_module_core_size(module)
    refs = module_refs(module)
    state = module_state(module)

    print("0x%x %-25s %10d %5s %-7s %s" % (int(module),
                             module.name,
                             core_size,
                             "-" if refs is None else refs,
                             module_taints(module) or "-",
                             gap_info_str), end="")
    if state not in ("", "LIVE"):
        # Being loaded or unloaded when the dump was taken.
        crashcolor.set_color(crashcolor.LIGHTYELLOW | crashcolor.BOLD)
        print(" [%s]" % state, end="")
        crashcolor.set_color(crashcolor.RESET)
    print()
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
        print("The module %s does not exist" % (options.module_detail))
        return


    show_module_summary(module)

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


def module_at(addr):
    """The loaded module whose struct, core or init memory holds addr."""
    if len(module_list) == 0:
        load_module_details()
    for module in module_list:
        if int(module) <= addr < int(module) + struct_size("struct module"):
            return module
        base = get_module_core_base(module)
        if base <= addr < base + get_module_core_size(module):
            return module
        init_base, init_size = get_module_init_range(module)
        if init_size and init_base <= addr < init_base + init_size:
            return module
    return None


def try_get_module_struct(options):
    try:
        addr = int(options.module_addr, 16)
    except ValueError:
        print("Not an address: %s" % options.module_addr)
        return
    module = module_at(addr)
    if module is not None:
        loaded_module = "loaded (%s)" % (module_state(module) or "?")
    else:
        module, loaded_module = find_module_struct(options.module_addr)
    if module is not None:
        print("Found the below module")
        print("\tstruct module 0x%x" % module)
        print("\tname : %s" % module.name)
        print("\tstatus : %s" % loaded_module)
        baseaddr = get_module_core_base(module)
        print("\tcore range 0x%x - 0x%x" % (baseaddr,
                                             baseaddr + get_module_core_size(module)))
        if options.show_symtab:
            show_manual_module_detail(options, module)
    else:
        crashcolor.set_color(crashcolor.RED)
        print("\nCannot find module structure for %s" % options.module_addr)
        crashcolor.set_color(crashcolor.RESET)
        module_addr_min = 0
        module_addr_max = 0
        mod_addr_min_str = "module_addr_min"
        mod_addr_max_str = "module_addr_max"
        module_addr = int(options.module_addr, 16)
        try:
            module_addr_min = readSymbol(mod_addr_min_str)
            module_addr_max = readSymbol(mod_addr_max_str)
        except:
            pass

        if module_addr_max == 0:
            try:
                mod_tree = readSymbol("mod_tree")
                module_addr_min = mod_tree.addr_min
                module_addr_max = mod_tree.addr_max
                mod_addr_min_str = "mod_tree.addr_min"
                mod_addr_max_str = "mod_tree.addr_max"
            except:
                pass

        if (module_addr_min < module_addr) and (module_addr < module_addr_max):
            print("\nThis address (0x%x) belongs to module allocation memory range" % \
                 module_addr)
            print("\tmodule address min (%s): 0x%x" % \
                  (mod_addr_min_str, module_addr_min))
            print("\tmodule address max (%s): 0x%x" % \
                  (mod_addr_max_str, module_addr_max))

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

    count = int(size // 2)
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
            # Not on the module list (module_at() looked there first): a
            # LIVE state is what an unloaded module that wasn't cleared
            # still says.
            if module.state == MODULE_STATE_LIVE:
                loaded_module = "unloaded, not cleared yet"
            return module, loaded_module
    except:
        pass

    return None, ""


# ============================================================================
# --details summary, -p parameters, -d dependencies
# ============================================================================

def _cstr(value):
    """A char * member as text, '' for NULL."""
    if value is None:
        return ""
    try:
        if isinstance(value, int) and value == 0:
            return ""
    except Exception:
        pass
    return str(value)


def _has_member(name):
    return member_offset("struct module", name) > -1


def show_module_summary(module, max_params=20):
    """The header of --details: what the module is and the state it was in."""
    def row(label, value):
        print("%-15s : %s" % (label, value))

    row("struct module", "0x%x" % int(module))
    row("name", module.name)
    row("state", module_state(module) or "-")
    row("version", _cstr(module.version) or "-")
    row("source ver", _cstr(module.srcversion) or "-")
    if _has_member("rhelversion"):
        row("rhel version", _cstr(module.rhelversion) or "-")
    if _has_member("sig_ok"):
        row("signed", "yes" if module.sig_ok else "no")
    taints = module_taints(module)
    row("taints", taints or "none")
    print_taint_meanings(taints, indent=" " * 18)

    uses, used_by = module_dependencies(module)
    refs = module_refs(module)
    row("refs", "-" if refs is None else refs)
    row("used by", ", ".join(used_by) or "-")
    row("uses", ", ".join(uses) or "-")

    base = get_module_core_base(module)
    size = get_module_core_size(module)
    row("core", "0x%x - 0x%x (%d bytes)" % (base, base + size, size))
    init_base, init_size = get_module_init_range(module)
    if init_size:
        row("init", "0x%x - 0x%x (%d bytes)" % (init_base, init_base + init_size, init_size))
    else:
        row("init", "freed after load")
    for label, fn in (("init()", "init"), ("exit()", "exit")):
        try:
            addr = int(getattr(module, fn))
        except Exception:
            continue
        if fn == "init" and not init_size:
            # The init sections are freed after load and the address may
            # now be another module's code: don't name what is there.
            sym = "(freed with the init sections)"
        else:
            sym = addr2sym(addr) if addr else None
        row(label, "%s (0x%x)" % (sym or "-", addr))

    params = module_params(module)
    if _has_member("args"):
        args = module_args(module, [p[0] for p in params])
        row("args", '"%s"' % args if args else "-")

    row("parameters", len(params))
    for name, value, perm, ops in params[:max_params]:
        print("    %-24s = %s%s" % (name, value,
                                    "" if perm else "  (not in sysfs)"))
    if len(params) > max_params:
        print("    ... %d more: modinfo -p %s" % (len(params) - max_params, module.name))


def rebuild_module_args(pieces, param_names):
    """
    The load arguments ('rx_ring=4096 debug') from mod->args after the
    kernel parsed it in place: parse_args() writes a NUL over each '=' and
    each separator, so the buffer reads 'rx_ring', '4096', 'debug'. A
    piece that names a parameter starts an argument; the next piece is its
    value unless it names a parameter too.
    """
    names = set(param_names)
    args = []
    i = 0
    while i < len(pieces):
        piece = pieces[i]
        if piece not in names and not re.match(r'^[A-Za-z_][\w.-]*$', piece):
            break       # not an argument name: past the end of the buffer
        if piece in names and i + 1 < len(pieces) and pieces[i + 1] not in names:
            args.append("%s=%s" % (piece, pieces[i + 1]))
            i = i + 2
            continue
        args.append(piece)
        i = i + 1
    return " ".join(args)


def module_args(module, param_names, limit=1024):
    """A module's load arguments as given to insmod/modprobe."""
    try:
        addr = readPtr(Addr(module) + member_offset("struct module", "args"))
    except Exception:
        return ""
    if addr == 0:
        return ""
    pieces = []
    current = []
    try:
        for i in range(limit):
            c = readU8(addr + i)
            if c != 0 and not (0x20 <= c < 0x7f):
                break                  # not text: past the end of the buffer
            if c != 0:
                current.append(chr(c))
                continue
            if not current:            # two NULs in a row: the end
                break
            pieces.append("".join(current))
            current = []
    except Exception:
        pass
    if current:
        pieces.append("".join(current))
    return rebuild_module_args(pieces, param_names)


def module_dependencies(module):
    """
    (uses, used_by): the names of the modules this one depends on and of
    those that depend on it. 'a uses b' is a struct module_use on
    a->target_list (use->target is b) and on b->source_list (use->source
    is a).
    """
    uses, used_by = [], []
    try:
        for use in readSUListFromHead(Addr(module.target_list), "target_list",
                                      "struct module_use"):
            uses.append(str(use.target.name))
        for use in readSUListFromHead(Addr(module.source_list), "source_list",
                                      "struct module_use"):
            used_by.append(str(use.source.name))
    except Exception:
        pass
    return uses, used_by


# How to read a parameter, by the kernel_param_ops it uses:
# (kind, size) with kind a struct format character or a name below.
PARAM_KINDS = {
    "param_ops_byte": ("B", 1),
    "param_ops_short": ("h", 2),
    "param_ops_ushort": ("H", 2),
    "param_ops_int": ("i", 4),
    "param_ops_uint": ("I", 4),
    "param_ops_hexint": ("hex", 4),
    "param_ops_long": ("q", 8),
    "param_ops_ulong": ("Q", 8),
    "param_ops_ullong": ("Q", 8),
    "param_ops_bool": ("bool", 1),
    "param_ops_bool_enable_only": ("bool", 1),
    "param_ops_invbool": ("invbool", 1),
    "param_ops_bint": ("bint", 4),
    "param_ops_charp": ("charp", 8),
    "param_ops_string": ("string", 0),
    "param_array_ops": ("array", 0),
}


def byte_order(machine):
    return ">" if machine in ("s390x", "s390", "ppc64", "ppc") else "<"


def format_param_scalar(kind, raw, order="<"):
    """The value of a scalar parameter from its bytes, as sysfs shows it
    (bool as Y/N). None for kinds that are not scalars."""
    if kind in ("bool", "invbool"):
        value = raw[0] != 0
        if kind == "invbool":
            value = not value
        return "Y" if value else "N"
    if kind == "bint":
        return "Y" if pystruct.unpack(order + "i", raw[:4])[0] else "N"
    if kind == "hex":
        return "0x%x" % pystruct.unpack(order + "I", raw[:4])[0]
    if len(kind) == 1:
        return str(pystruct.unpack(order + kind, raw[:pystruct.calcsize(kind)])[0])
    return None


def format_param_array(values, count, shown=16):
    """'[a, b, c]' for an array parameter's first `shown` of `count`
    values; the same value in every slot is '[v] x count'."""
    if count == 0:
        return "[]"
    if count > 1 and len(set(values)) == 1 and len(values) == count:
        return "[%s] x %d" % (values[0], count)
    more = " ... %d more" % (count - len(values)) if count > len(values) else ""
    return "[%s%s]" % (", ".join(values), more)


def param_ops_label(ops_name, arg):
    """'uint', 'charp', or 'array of int' for a parameter's ops."""
    label = ops_name.replace("param_ops_", "")
    if ops_name == "param_array_ops":
        try:
            elem_ops = addr2sym(readPtr(arg + member_offset("struct kparam_array", "ops")))
            label = "array of %s" % (elem_ops or "?").replace("param_ops_", "")
        except Exception:
            label = "array"
    return label


def read_cstring(addr, limit=256):
    if addr == 0:
        return None
    out = []
    try:
        for i in range(limit):
            c = readU8(addr + i)
            if c == 0:
                break
            out.append(chr(c))
        else:
            out.append("...")
    except Exception:
        return None
    return "".join(out)


def _quoted(text):
    return "(null)" if text is None else '"%s"' % text


def param_scalar_value(ops_name, addr, order):
    kind, size = PARAM_KINDS.get(ops_name, (None, 0))
    if kind is None:
        return None
    if kind == "charp":
        return _quoted(read_cstring(readPtr(addr)))
    if ops_name in ("param_ops_long", "param_ops_ulong") and sys_info.pointersize == 4:
        kind, size = {"q": "i", "Q": "I"}[kind], 4      # long is 32-bit here
    return format_param_scalar(kind, readmem(addr, size), order)


def param_value(ops_name, arg, order):
    """A parameter's value from its ops and its kernel_param arg pointer."""
    kind = PARAM_KINDS.get(ops_name, (None, 0))[0]
    if kind is None:
        return "(set by %s)" % ops_name
    if kind == "string":
        string_offset = member_offset("struct kparam_string", "string")
        return _quoted(read_cstring(readPtr(arg + string_offset)))
    if kind == "array":
        def field(name):
            return arg + member_offset("struct kparam_array", name)
        num_ptr = readPtr(field("num"))
        count = readU32(num_ptr) if num_ptr else readU32(field("max"))
        elemsize = readU32(field("elemsize"))
        elem = readPtr(field("elem"))
        elem_ops = addr2sym(readPtr(field("ops"))) or ""
        values = []
        for i in range(min(count, 16)):
            v = param_scalar_value(elem_ops, elem + i * elemsize, order)
            values.append(v if v is not None else "?")
        return format_param_array(values, count)
    return param_scalar_value(ops_name, arg, order)


def module_params(module):
    """[(name, value, perm, ops)] for a module's parameters (mod->kp)."""
    params = []
    try:
        count = int(module.num_kp)
        base = int(module.kp)
    except Exception:
        return params
    if count == 0 or base == 0:
        return params
    kp_size = struct_size("struct kernel_param")
    arg_offset = member_offset("struct kernel_param", "arg")
    order = byte_order(sys_info.machine)
    for i in range(count):
        addr = base + i * kp_size
        try:
            kp = readSU("struct kernel_param", addr)
            name = _cstr(kp.name)
            ops = addr2sym(int(kp.ops)) or "0x%x" % int(kp.ops)
            perm = int(kp.perm)
            arg = readPtr(addr + arg_offset)
        except Exception:
            continue
        try:
            value = param_value(ops, arg, order)
        except Exception as e:
            value = "(unreadable: %s)" % e
        params.append((name, value, perm, param_ops_label(ops, arg)))
    return params


def show_module_params(options):
    module = find_module(options.module_params)
    if module is None:
        print("The module %s does not exist" % options.module_params)
        return
    params = module_params(module)
    if not params:
        print("%s has no parameters" % module.name)
        return
    print("%-28s %-6s %-20s %s" % ("PARAMETER", "PERM", "OPS", "VALUE"))
    for name, value, perm, ops in params:
        print("%-28s %-6s %-20s %s" % (name, "%04o" % perm if perm else "-",
                                       ops, value))


def show_module_deps(options):
    module = find_module(options.module_deps)
    if module is None:
        print("The module %s does not exist" % options.module_deps)
        return
    uses, used_by = module_dependencies(module)
    refs = module_refs(module)
    print("%s (refs %s)" % (module.name, "-" if refs is None else refs))
    print("  uses    : %s" % (", ".join(uses) or "-"))
    print("  used by : %s" % (", ".join(used_by) or "-"))


# ============================================================================
# -b / --bt-all: modules in the backtraces
# ============================================================================

_RE_BT_TASK = re.compile(r'^PID:\s*(\d+)\s+TASK:\s*([0-9a-fA-F]+)\s+CPU:\s*(\d+)'
                         r'\s+COMMAND:\s*"(.*)"')
_RE_BT_FRAME = re.compile(r'^\s*(#\d+)\s+\[[0-9a-fA-F]+\]\s+(\S+)\s+at\s+([0-9a-fA-F]+)')
_RE_BT_EXCEPTION = re.compile(r'\[exception RIP:\s*([^\]]+)\]')
_RE_BT_RIP = re.compile(r'\bRIP:\s*([0-9a-fA-F]{8,})')


def parse_backtraces(text):
    """
    The frames of crash 'bt' output: [(pid, comm, cpu, frame, func, addr)].
    frame is '#N', or 'RIP' for the address in an exception frame, whose
    function is named by the '[exception RIP: func+off]' line above it.
    """
    frames = []
    task = None
    exception_func = None
    for line in text.splitlines():
        m = _RE_BT_TASK.match(line.strip())
        if m:
            task = (int(m.group(1)), m.group(4), int(m.group(3)))
            exception_func = None
            continue
        if task is None:
            continue
        m = _RE_BT_FRAME.match(line)
        if m:
            frames.append(task + (m.group(1), m.group(2), int(m.group(3), 16)))
            m = _RE_BT_EXCEPTION.search(line)
            exception_func = m.group(1).strip() if m else None
            continue
        m = _RE_BT_EXCEPTION.search(line)
        if m:
            exception_func = m.group(1).strip()
            continue
        m = _RE_BT_RIP.search(line)
        if m and exception_func is not None:
            frames.append(task + ("RIP", exception_func, int(m.group(1), 16)))
            exception_func = None
    return frames


def frames_by_module(frames, ranges):
    """
    {module name: [frames]} for the frames whose address is in a module,
    in the order the modules are first seen. ranges: [(name, start, end)].
    """
    found = {}
    order = []
    for frame in frames:
        addr = frame[5]
        for name, start, end in ranges:
            if start <= addr < end:
                if name not in found:
                    found[name] = []
                    order.append(name)
                found[name].append(frame)
                break
    return [(name, found[name]) for name in order]


def module_ranges():
    """[(name, start, end)] of every module's core and init sections."""
    if len(module_list) == 0:
        load_module_details()
    ranges = []
    for module in module_list:
        name = str(module.name)
        base = get_module_core_base(module)
        size = get_module_core_size(module)
        if base and size:
            ranges.append((name, base, base + size))
        init_base, init_size = get_module_init_range(module)
        if init_base and init_size:
            ranges.append((name, init_base, init_base + init_size))
    return ranges


def show_bt_modules(options, max_frames=8):
    command = "foreach bt" if options.bt_all else "bt -a"
    try:
        text = exec_crash_command(command)
    except Exception as e:
        print("'%s' failed: %s" % (command, e))
        return
    frames = parse_backtraces(text)
    tasks = len(set((f[0], f[2]) for f in frames))
    result = frames_by_module(frames, module_ranges())
    print("Modules in '%s' (%d frames in %d tasks)" % (command, len(frames), tasks))
    if not result:
        print("  No frame is in module code")
        return
    for name, mod_frames in result:
        mod_tasks = len(set((f[0], f[2]) for f in mod_frames))
        crashcolor.set_color(crashcolor.LIGHTRED)
        print("\n%s: %d frame%s in %d task%s" % (name, len(mod_frames),
                                                "s" if len(mod_frames) != 1 else "",
                                                mod_tasks, "s" if mod_tasks != 1 else ""))
        crashcolor.set_color(crashcolor.RESET)
        for pid, comm, cpu, frame, func, addr in mod_frames[:max_frames]:
            print("    PID %-7d %-16s CPU %-3d %-4s %s (0x%x)" % (pid, comm, cpu,
                                                               frame, func, addr))
        if len(mod_frames) > max_frames:
            print("    ... %d more" % (len(mod_frames) - max_frames))


def modinfo():
    op = OptionParser(usage="%prog [options] [<module>]\n\n"
                      "With no options, list the loaded modules. 'modinfo <module>'"
                      " is the same as\n'modinfo --details <module>'.")
    op.add_option("--disasm", dest="disasm_module", default=None, metavar="MODULE",
                  action="store", type="string",
                  help="Disassemble a module functions")
    op.add_option("--details", dest="module_detail", default=None, metavar="MODULE",
                  action="store", type="string",
                  help="Show details: state, signature, taints, refs, what it"
                       " uses and what uses it, memory ranges, load arguments,"
                       " parameters, then its symbols")
    op.add_option("-p", "--params", dest="module_params", default=None, metavar="MODULE",
                  action="store", type="string",
                  help="Show a module's parameters and their current values")
    op.add_option("-d", "--deps", dest="module_deps", default=None, metavar="MODULE",
                  action="store", type="string",
                  help="Show the modules a module uses and those that use it")
    op.add_option("-b", "--bt", dest="bt_modules", default=False,
                  action="store_true",
                  help="Show the modules whose code is in the backtraces of"
                       " the active tasks ('bt -a')")
    op.add_option("--bt-all", dest="bt_all", default=False,
                  action="store_true",
                  help="Like -b, for every task ('foreach bt'; can be slow)")
    op.add_option("-c", "--contents", dest="show_contents", default=False,
                  action="store_true",
                  help="Show contents of each symbols")
    op.add_option("-t", dest="shows_tainted", default=False,
                  action="store_true",
                  help="Shows tainted modules only")
    op.add_option("-g", dest="shows_gaps", default=False,
                  action="store_true",
                  help="Shows gaps between modules as well as physically allocated sizes")
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
    op.add_option("-l", dest="show_longer_than", default=5, metavar="N",
                  action="store", type="int",
                  help="Set the minimum size to show for -s. default=5")
    op.add_option("--batch_run", dest="batch_run", default=None, metavar="MODULE",
                  action="store", type="string",
                  help="Run major options all together to get detailed info")
    op.add_option("--target_dir", dest="target_dir", default=None, metavar="DIR",
                  action="store", type="string",
                  help="Result will be saved in this directory")
    op.add_option("--nodate", dest="nodate", default=False,
                  action="store_true",
                  help="Do not use date in target filename")
    op.add_option('-m', '--module', dest="module_addr", default=None, metavar="ADDRESS",
                  action="store", type="string",
                  help="Trying to retrieve module structure")
    op.add_option('-y', '--symtab', dest="show_symtab", default=None,
                  action="store_true",
                  help="Trying to retrieve module's symbols")
    op.add_option('-r', '--reverse', dest="reverse_disasm", default=None,
                  action="store_true",
                  help="Trying to disasm from unloaded module")


    (o, args) = op.parse_args()

    # 'modinfo <module>' is 'modinfo --details <module>'.
    if args and o.module_detail is None and o.disasm_module is None and \
       o.module_params is None and o.module_deps is None and \
       o.batch_run is None and o.module_addr is None:
        o.module_detail = args[0]

    if o.bt_modules or o.bt_all:
        show_bt_modules(o)
        sys.exit(0)

    if o.module_params is not None:
        show_module_params(o)
        sys.exit(0)

    if o.module_deps is not None:
        show_module_deps(o)
        sys.exit(0)

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
            module = find_module(o.batch_run)
            if module is None:
                print("The module %s does not exist" % o.batch_run)
                sys.exit(0)
            mod_list = [module]

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
