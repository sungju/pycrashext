"""
 Written by Daniel Sungju Kwon
"""

from pykdump.API import *

from LinuxDump import Tasks
from LinuxDump import percpu

import os
import sys
import operator
import gc  # For garbage collection
import re
from collections import defaultdict
import shutil
import copy

import crashcolor
from crashhelper import *


debug_mode = False

page_size = 4096
page_shift = 12

# Bar chart width constants
ITEM_BAR_WIDTH = 20   # Width for individual process/slab bars
TOTAL_BAR_WIDTH = 40  # Width for total usage bar (2x for emphasis)

VM_HUGETLB = 0x00400000

VM_WRITE = 0x00000002
VM_SHARED = 0x00000008

first_ksymbol = 0

stack_pools = None
stack_handle_version = 0

# Page struct conversion parameters (initialized once for performance)
mem_map_base = None
vmemmap_base = None
phys_base = None
page_struct_size = None
using_vmemmap = False
page_conversion_initialized = False

def check_global_symbols():
    global first_ksymbol

    try:
        first_ksymbol = int(get_machine_symbol("kvbase").split()[0], 16)
    except:
        pass

    return


machine_symbols = {}
minus_one_addr = 0

def get_machine_symbol(symbol, cmd="help -m"):
    global machine_symbols
    global minus_one_addr
    global page_size

    try:
        #if len(machine_symbols) == 0:
        if (len(machine_symbols) == 0) or (symbol not in machine_symbols):
            help_s_out = exec_crash_command(cmd)
            lines = help_s_out.splitlines()
            for line in lines:
                if ":" not in line:
                    continue
                words = line.split(":")
                key = words[0].strip()
                value = words[1].strip()
                machine_symbols[key] = value
                if key == "bits":
                    minus_one_addr = (1 << int(value)) - 1
                if key == "pagesize":
                    page_size = int(value)
    except Exception as e:
        pass

    if symbol in machine_symbols:
        return machine_symbols[symbol]

    return ""


def get_release_str():
    sys_output = exec_crash_command("sys")
    for line in sys_output.splitlines():
        words = line.split()
        if words[0] == "RELEASE:":
            return words[1]

    return ""

gfp_dict = {}
gfp_full_match = {}


def set_gfp_dict():
    global gfp_dict
    global gfp_full_match

    release_str = get_release_str()
    if "el7" in release_str:
        gfp_dict = {
                    0x01: "__GFP_DMA",
                    0x02: "__GFP_HIGHMEM",
                    0x04: "__GFP_DMA32",
                    0x08: "__GFP_MOVABLE : Flag that this page will be movable by the page migration mechanism or reclaimed",
                    0x10: "__GFP_WAIT : Can wait and reschedule?",
                    0x20: "__GFP_HIGH : Should access emergency pools?",
                    0x40: "__GFP_IO : Can start physical IO?",
                    0x80: "__GFP_FS : Can call down to low-level FS?",
                    0x100: "__GFP_COLD : Cache-cold page required",
                    0x200: "__GFP_NOWARN : Suppress page allocation failure warning",
                    0x400: "__GFP_REPEAT : Try hard to allocate the memory, but the allocation attempt _might_ fail.  This depends upon the particular VM implementation.",
                    0x800: "__GFP_NOFAIL : The VM implementation _must_ retry infinitely: the caller cannot handle allocation failures.",
                    0x1000: "__GFP_NORETRY : The VM implementation must not retry indefinitely",
                    0x2000: "__GFP_MEMALLOC : Allow access to emergency reserves",
                    0x4000: "__GFP_COMP : Add compound page metadata",
                    0x8000: "__GFP_ZERO : Return zeroed page on success",
                    0x10000: "__GFP_NOMEMALLOC : Don't use emergency reserves",
                    0x20000: "__GFP_HARDWALL : Enforce hardwall cpuset memory allocs",
                    0x40000: "__GFP_THISNODE : No fallback, no policies",
                    0x80000: "__GFP_RECLAIMABLE : Page is reclaimable",
                    0x100000: "__GFP_ACCOUNT",
                    0x200000: "__GFP_NOTRACK : Don't track with kmemcheck",
                    0x400000: "__GFP_NO_KSWAPD",
                    0x800000: "__GFP_OTHER_NODE : On behalf of other node",
                    0x1000000: "__GFP_WRITE : Allocator intends to dirty page",
                   }

        gfp_full_match = {
                           0x200d2: "GFP_HIGHUSER",
                           0x200d0: "GFP_USER",
                           0xd0: "GFP_KERNEL",
                           0x50: "GFP_NOFS",
                           0x20: "GFP_ATOMIC",
                           0x10: "GFP_NOIO",
                          }
    elif "el8" in release_str:
        gfp_dict = {
                    0x01: "__GFP_DMA",
                    0x02: "__GFP_HIGHMEM",
                    0x04: "__GFP_DMA32",
                    0x08: "__GFP_MOVABLE : Flag that this page will be movable by the page migration mechanism or reclaimed",
                    0x10: "__GFP_RECLAIMABLE",
                    0x20: "__GFP_HIGH : Should access emergency pools?",
                    0x40: "__GFP_IO : Can start physical IO?",
                    0x80: "__GFP_FS : Can call down to low-level FS?",
                    0x100: "__GFP_WRITE",
                    0x200: "__GFP_NOWARN : Suppress page allocation failure warning",
                    0x400: "__GFP_RETRY_MAYFAIL",
                    0x800: "__GFP_NOFAIL : The VM implementation _must_ retry infinitely: the caller cannot handle allocation failures.",
                    0x1000: "__GFP_NORETRY : The VM implementation must not retry indefinitely",
                    0x2000: "__GFP_MEMALLOC : Allow access to emergency reserves",
                    0x4000: "__GFP_COMP : Add compound page metadata",
                    0x8000: "__GFP_ZERO : Return zeroed page on success",
                    0x10000: "__GFP_NOMEMALLOC : Don't use emergency reserves",
                    0x20000: "__GFP_HARDWALL : Enforce hardwall cpuset memory allocs",
                    0x40000: "__GFP_THISNODE : No fallback, no policies",
                    0x80000: "__GFP_ATOMIC",
                    0x100000: "__GFP_ACCOUNT",
                    0x200000: "__GFP_DIRECT_RECLAIM",
                    0x400000: "__GFP_KSWAPD_RECLAIM",
                    0x800000: "__GFP_NOLOCKDEP",
                   }

        gfp_full_match = {
                           0x6200c2: "GFP_HIGHUSER",
                           0x6200c0: "GFP_USER",
                           0x6000c0: "GFP_KERNEL",
                           0x600040: "GFP_NOFS",
                           0x600000: "GFP_NOIO",
                           0x480020: "GFP_ATOMIC",
                          }
    elif "el9" in release_str:
        gfp_dict = {
                    0x01: "__GFP_DMA",
                    0x02: "__GFP_HIGHMEM",
                    0x04: "__GFP_DMA32",
                    0x08: "__GFP_MOVABLE : Flag that this page will be movable by the page migration mechanism or reclaimed",
                    0x10: "__GFP_RECLAIMABLE",
                    0x20: "__GFP_HIGH : Should access emergency pools?",
                    0x40: "__GFP_IO : Can start physical IO?",
                    0x80: "__GFP_FS : Can call down to low-level FS?",
                    0x100: "__GFP_ZERO",
                    0x200: "__GFP_ATOMIC",
                    0x400: "__GFP_DIRECT_RECLAIM",
                    0x800: "__GFP_KSWAPD_RECLAIM",
                    0x1000: "__GFP_WRITE",
                    0x2000: "__GFP_NOWARN",
                    0x4000: "__GFP_RETRY_MAYFAIL",
                    0x8000: "__GFP_NOFAIL",
                    0x10000: "__GFP_NORETRY",
                    0x20000: "__GFP_MEMALLOC",
                    0x40000: "__GFP_COMP",
                    0x80000: "__GFP_NOMEMALLOC",
                    0x100000: "__GFP_HARDWALL",
                    0x200000: "__GFP_THISNODE",
                    0x400000: "__GFP_ACCOUNT",
                    0x800000: "__GFP_ZEROTAGS",
                    0x1000000: "__GFP_SKIP_ZERO",
                    0x2000000: "__GFP_SKIP_KASAN_UNPOISON",
                    0x4000000: "__GFP_SKIP_KASAN_POISON",
                    0x8000000: "__GFP_NOLOCKDEP",
                   }

        gfp_full_match = {
                           0x1000d2: "GFP_HIGHUSER",
                           0x1000d0: "GFP_USER",
                           0xc00: "__GFP_RECLAIM",
                           0xa20: "GFP_ATOMIC",
                           0xd0: "GFP_KERNEL",
                           0x50: "GFP_NOFS",
                           0x10: "GFP_NOIO",
                          }


def get_gfp_mask_str(gfp_mask):
    global gfp_dict
    global gfp_full_match

    if len(gfp_dict) == 0:
        set_gfp_dict()

    result = []
    for val in gfp_full_match:
        if val & gfp_mask == val:
            gfp_mask = gfp_mask & ~val
            result.append(gfp_full_match[val])

    for val in gfp_dict:
        if val & gfp_mask == val:
            gfp_mask = gfp_mask & ~val
            result.append(gfp_dict[val].split()[0])


    return "|".join(result)


def show_gfp_mask(options):
    global gfp_dict
    global gfp_full_match

    if len(gfp_dict) == 0:
        set_gfp_dict()

    gfp_mask = int(options.gfp_mask, 16)

    for val in gfp_full_match:
        if val & gfp_mask == val:
            print(gfp_full_match[val])
            gfp_mask = gfp_mask & ~val

    for val in gfp_dict:
        if val & gfp_mask == val:
            print(gfp_dict[val])
            gfp_mask = gfp_mask & ~val


def get_max_order():
    node_data = readSymbol("node_data")
    nr_online_nodes = readSymbol("nr_online_nodes")

    node_index = 0
    max_order_index = 0
    for node in node_data:
        if node:
            for zone in node.node_zones:
                if len(zone.free_area) > max_order_index:
                    max_order_index = len(zone.free_area)
        elif node_index >= nr_online_nodes:
            break

        node_index = node_index + 1

    return max_order_index - 1


def show_buddyinfo(options):
    node_data = readSymbol("node_data")
    nr_online_nodes = readSymbol("nr_online_nodes")

    node_index = 0
    max_order_index = 0
    for node in node_data:
        if node:
            for zone in node.node_zones:
                print("Node%2d, zone %8s" % (node.node_id, zone.name), end="")
                if len(zone.free_area) > max_order_index:
                    max_order_index = len(zone.free_area)

                for order in zone.free_area:
                    print("%7d" % (order.nr_free), end="")
                print("")
        elif node_index >= nr_online_nodes:
            break

        node_index = node_index + 1

    if options.details:
        print("\n#%-20s" % " Order", end="")
        for i in range(0, max_order_index):
            print("%7s" % ("2^%d" % (i)), end="")
        print("")
        page_size = 1 << get_page_shift()
        print("#%-20s" % " Size (KB)", end="")
        for i in range(0, max_order_index):
            print("%7d" % (((2**i) * page_size)/1024), end="")
        print("")


def get_node_numbers(nr_blks=1):
    node_numbers = []
    try:
        addrs = percpu.get_cpu_var("node_number")
        for cpu, addr in enumerate(addrs):
            node = readInt(addr)
            if node not in node_numbers:
                node_numbers.append(node)

        nr_blks = len(node_numbers)
    except:
        node_numbers = None

    return nr_blks, node_numbers


def get_numa_meminfo():
    numa_meminfo = None
    nr_blks = 1
    try:
        numa_meminfo = readSymbol("numa_meminfo")
        nr_blks = numa_meminfo.nr_blks
    except:
        numa_meminfo = None
        nr_blks = 1

    return nr_blks, numa_meminfo


def show_numa_info(options):
    try:
        nr_blks, numa_meminfo = get_numa_meminfo()
        nr_blks, node_numbers = get_node_numbers(nr_blks)

        if numa_meminfo == None and node_numbers == None:
            print("No NUMA information available")
            return

        node_cpus = {}
        try:
            addrs = percpu.get_cpu_var("x86_cpu_to_node_map")
            for cpu, addr in enumerate(addrs):
                node = readInt(addr)
                if node in node_cpus:
                    cpu_list = node_cpus[node]
                else:
                    cpu_list = []
                cpu_list.append(cpu)
                node_cpus[node] = cpu_list
        except:
            pass

        print("available: %d node%s (0" % (nr_blks, "s" if nr_blks > 1 else ""), end="")
        if nr_blks > 1:
            print("-%d" % (nr_blks - 1), end="")
        print(")")
        for idx in range(0, nr_blks):
            if numa_meminfo != None:
                numa_memblk = numa_meminfo.blk[idx]
                numa_memblk_nid = numa_memblk.nid
            else:
                numa_memblk_nid = idx

            if numa_memblk_nid in node_cpus:
                print("node %d cpus: " % (numa_memblk_nid), end="")
                cpu_list = node_cpus[idx]
                for cpu in range(0, len(cpu_list)):
                    print(" %d" % cpu_list[cpu], end="")
                print("")
            if numa_meminfo == None or numa_memblk.nid < 0:
                continue
            print("node %d : 0x%016x - 0x%016x" % (numa_memblk.nid, numa_memblk.start, numa_memblk.end))
            print("node %d size : %d MB" % (numa_memblk.nid, (numa_memblk.end - numa_memblk.start) / (1024 * 1024)))

        if nr_blks <= 1:
            return
        numa_distance = readSymbol("numa_distance")
        numa_distance_cnt = readSymbol("numa_distance_cnt")
        print("")
        print("node distances:")
        print(" %5s" % ("node"), end="")
        for i in range(0, nr_blks):
            print("%5d" % i, end="")
        print("")
        for i in range(0, numa_meminfo.nr_blks):
            print("%5d:" % (i), end="")
            for j in range(0, numa_meminfo.nr_blks):
                distance = numa_distance[i * numa_distance_cnt + j]
                print("%5d" % (distance), end="")
            print("")
    except:
        pass



def get_entry_in_dict(dict_data, entry, extra):
    result = ""
    if entry in dict_data:
        width = 30 - len(entry)
        result = entry + ": " +\
                "{0: >{width}}".format(dict_data[entry], width=width) +\
                extra

    return result


def get_hugepages_details():
    hstates = readSymbol("hstates")
    default_hstate_idx = readSymbol("default_hstate_idx")
    h = hstates[default_hstate_idx]
    return h.nr_huge_pages, h.free_huge_pages, h.resv_huge_pages,\
            h.surplus_huge_pages, 1 << (h.order + get_page_shift() - 10)


def get_directmap_details():
    try:
        direct_pages_count = readSymbol("direct_pages_count")
    except: # This feature is only available on x86 arch
        return 0, 0, 0, 0

    idx = 0
    dmval = [0, 0, 0, 0, 0]
    shift_val = [2, 11, 12, 20, 0]
    for dp in direct_pages_count:
        dmval[idx] = dp << shift_val[idx]
        idx = idx + 1

    return dmval[0], dmval[1], dmval[2], dmval[3]


def hugetlb_total_pages():
    hstates = readSymbol("hstates")
    try:
        hugetlb_max_hstate = readSymbol("hugetlb_max_hstate")
    except:
        hugetlb_max_hstate = None
        pass

    if hugetlb_max_hstate is None or hugetlb_max_hstate == 0:
        hugetlb_max_hstate = 3 # Intel = 2, PPC = 3

    nr_total_pages = 0
    count = 0
    for hstate in hstates:
        nr_total_pages = nr_total_pages + hstate.nr_huge_pages * \
                (1 << hstate.order)
        count = count + 1
        if count == hugetlb_max_hstate:
            break

    return nr_total_pages


def get_page_shift():
    resultline = exec_crash_command("ptob 1")
    if len(resultline) == 0:
        return 0

    words = resultline.split()
    if len(words) < 2:
        return 0

    value = int(words[1], 16)
    idx = 0
    while (value > 0):
        value = value >> 1
        idx = idx + 1

    return idx - 1


vm_stat = None

def global_page_state(idx):
    global vm_stat

    x = vm_stat[idx].counter
    if x < 0:
        x = 0

    return x


def si_mem_available():
    global vm_stat

    pages = []
    lru_list = EnumInfo("enum lru_list")
    LRU_INACTIVE_ANON = lru_list.LRU_INACTIVE_ANON
    LRU_BASE = LRU_INACTIVE_ANON
    LRU_ACTIVE_FILE = lru_list.LRU_ACTIVE_FILE
    LRU_INACTIVE_FILE = lru_list.LRU_INACTIVE_FILE
    NR_LRU_LISTS = lru_list.NR_LRU_LISTS
    if symbol_exists("vm_stat"):
        vm_stat = readSymbol("vm_stat")
    elif symbol_exists("vm_zone_stat"):
        vm_stat = readSymbol("vm_zone_stat")
    else:
        vm_stat = None

    for i in range(LRU_BASE, NR_LRU_LISTS):
        pages.append(global_page_state(i))

    zone_stat_lines = exec_crash_command("kmem -z").splitlines()
    zone_watermarks = EnumInfo("enum zone_watermarks")
    WMARK_LOW = zone_watermarks.WMARK_LOW
    wmark_low = 0
    for line in zone_stat_lines:
        if not line.startswith("NODE:"):
            continue
        words = line.split()
        task_addr = words[5]
        zone = readSU("struct zone", int(task_addr, 16))
        if member_offset("struct zone", "watermark") >= 0:
            wmark_low = wmark_low + zone.watermark[WMARK_LOW]
        elif member_offset("struct zone", "_watermark") >= 0:
            wmark_low = wmark_low + zone._watermark[WMARK_LOW]

    zone_state_item = EnumInfo("enum zone_stat_item")
    node_state_item = EnumInfo("enum node_stat_item")
    NR_FREE_PAGES = zone_state_item.NR_FREE_PAGES
    try:
        NR_SLAB_RECLAIMABLE = zone_state_item.NR_SLAB_RECLAIMABLE
    except:
        try:
            NR_SLAB_RECLAIMABLE = node_state_item.NR_SLAB_RECLAIMABLE_B
        except:
            NR_SLAB_RECLAIMABLE = 5

    totalreserve_pages = readSymbol("totalreserve_pages")
    available = global_page_state(NR_FREE_PAGES) - totalreserve_pages

    pagecache = pages[LRU_ACTIVE_FILE] + pages[LRU_INACTIVE_FILE]
    pagecache = pagecache - min(pagecache // 2, wmark_low)
    available = available + pagecache

    available = available + global_page_state(NR_SLAB_RECLAIMABLE) - \
            min(global_page_state(NR_SLAB_RECLAIMABLE) // 2, wmark_low)

    if (available < 0):
        available = 0

    return round(available) << (get_page_shift() - 10)


def get_hardware_corrupted():
    num_poisoned_pages = readSymbol("num_poisoned_pages")
    return num_poisoned_pages.counter << (get_page_shift() - 10)


def get_vmalloc_info():
    resultlines = exec_crash_command("kmem -v").splitlines()
    iterlines = iter(resultlines)
    next(iterlines)
    total_used = 0
    prev_end = -1
    largest_chunk = 0
    vmalloc_start = -1
    vmalloc_end = -1
    for vmline in iterlines:
        words = vmline.split()
        total_used = total_used + int(words[5])
        start = int(words[2], 16)
        end = int(words[4], 16)
        if prev_end == -1:
            prev_end = start
            vmalloc_start = start

        vmalloc_end = end
        if start - prev_end > largest_chunk:
            largest_chunk = start - prev_end

        prev_end = end


    return vmalloc_end - vmalloc_start, total_used, largest_chunk


def vm_commit_limit():
    sysctl_overcommit_kbytes = readSymbol("sysctl_overcommit_kbytes")
    if symbol_exists("totalram_pages"):
        totalram_pages = readSymbol("totalram_pages")
    elif symbol_exists("_totalram_pages"):
        totalram_pages = readSymbol("_totalram_pages")
    else:
        totalram_pages = 0

    sysctl_overcommit_ratio = readSymbol("sysctl_overcommit_ratio")
    total_swap_pages = readSymbol("total_swap_pages")
    allowed = 0
    if sysctl_overcommit_kbytes > 0:
        allowed = sysctl_overcommit_kbytes >> (get_page_shift() - 10)
    else:
        allowed = ((totalram_pages - hugetlb_total_pages()) *\
                   sysctl_overcommit_ratio // 100)

    allowed += total_swap_pages

    return round(allowed) << (get_page_shift() - 10)


def vm_committed_as():
    vm_committed_as = readSymbol("vm_committed_as")
    return (vm_committed_as.count << (get_page_shift() - 10))

def total_swapcache_pages():
    try:
        swapper_space = readSymbol("swapper_space") # For RHEL6 or earlier
    except:
        swapper_space = None

    if swapper_space is not None:
        return swapper_space.nrpages

    swapper_spaces = readSymbol("swapper_spaces")
    swap_aops = readSymbol("swap_aops")
    total = 0
    count = 0
    for swapper_space in swapper_spaces:
        if swapper_space is None or swapper_space == 0:
            break
        if swapper_space.a_ops != swap_aops: # As pykdump is not detecting
                                             # array size properly
            break
        total = total + swapper_space.nrpages

    return total

def get_meminfo():
    global page_size

    page_size = 1 << get_page_shift()
    meminfo={}

    resultlines = exec_crash_command("kmem -i").splitlines()
    page_unit = page_size // 1024
    meminfo['MemFree'] = 0
    for line in resultlines:
        words = line.split()
        if len(words) == 0:
            continue
        if words[0] == 'TOTAL':
            if words[1] == 'MEM':
                meminfo['MemTotal'] = round(int(words[2]) * page_unit) # Convert pages
            elif words[1] == 'HUGE':
                meminfo['HugePages_Total'] = int(words[2])
            elif words[1] == 'SWAP':
                meminfo['SwapTotal'] = round(int(words[2]) * page_unit)
            else:
                pass
        elif words[0] == 'HUGE':
            if words[1] == 'FREE':
                meminfo['HugePages_Free'] = int(words[2])
        elif words[0] == 'FREE':
            val = words[1]
            if words[1] == 'HIGH' or words[1] == 'LOW':
                val = words[2]
            meminfo['MemFree'] = meminfo['MemFree'] + \
                    round(int(val) * page_unit)
        elif words[0] == 'BUFFERS':
            meminfo['Buffers'] = round(int(words[1]) * page_unit)
        elif words[0] == 'CACHED':
            meminfo['Cached'] = round(int(words[1]) * page_unit)
        elif words[0] == 'SWAP':
            if words[1] == 'FREE':
                meminfo['SwapFree'] = round(int(words[2]) * page_unit)
            else:
                pass
        else:
            pass


    meminfo["SwapCached"] = total_swapcache_pages()

    resultlines = exec_crash_command("kmem -V").splitlines()
    meminfo['Active'] = 0
    meminfo['Inactive'] = 0
    meminfo['Slab'] = 0
    for line in resultlines:
        words = line.split()
        if len(words) == 0:
            continue
        if words[0] == "NR_ACTIVE_ANON:":
            meminfo["Active(anon)"] = round(int(words[1]) * page_unit)
            meminfo["Active"] = meminfo["Active"] + meminfo["Active(anon)"]
        elif words[0] == "NR_INACTIVE_ANON:":
            meminfo["Inactive(anon)"] = round(int(words[1]) * page_unit)
            meminfo["Inactive"] = meminfo["Inactive"] + meminfo["Inactive(anon)"]
        elif words[0] == "NR_ACTIVE_FILE:":
            meminfo["Active(file)"] = round(int(words[1]) * page_unit)
            meminfo["Active"] = meminfo["Active"] + meminfo["Active(file)"]
        elif words[0] == "NR_INACTIVE_FILE:":
            meminfo["Inactive(file)"] = round(int(words[1]) * page_unit)
            meminfo["Inactive"] = meminfo["Inactive"] + meminfo["Inactive(file)"]
        elif words[0] == "NR_UNEVICTABLE:":
            meminfo["Unevictable"] = round(int(words[1]) * page_unit)
        elif words[0] == "NR_MLOCK:":
            meminfo["Mlocked"] = round(int(words[1]) * page_unit)
        elif words[0] == "NR_FILE_DIRTY:":
            meminfo["Dirty"] = round(int(words[1]) * page_unit)
        elif words[0] == "NR_WRITEBACK:":
            meminfo["Writeback"] = round(int(words[1]) * page_unit)
        elif words[0] == "NR_ANON_PAGES:":
            meminfo["AnonPages"] = round(int(words[1]) * page_unit)
        elif words[0] == "NR_FILE_MAPPED:":
            meminfo["Mapped"] = round(int(words[1]) * page_unit)
        elif words[0] == "NR_SHMEM:":
            meminfo["Shmem"] = round(int(words[1]) * page_unit)
        elif words[0] == "NR_SLAB_RECLAIMABLE:":
            meminfo["SReclaimable"] = round(int(words[1]) * page_unit)
            meminfo["Slab"] = meminfo["Slab"] + meminfo["SReclaimable"]
        elif words[0] == "NR_SLAB_UNRECLAIMABLE:":
            meminfo["SUnreclaim"] = round(int(words[1]) * page_unit)
            meminfo["Slab"] = meminfo["Slab"] + meminfo["SUnreclaim"]
        elif words[0] == "NR_KERNEL_STACK:":
            meminfo["KernelStack"] = round(int(words[1]) * page_unit)
        elif words[0] == "NR_PAGETABLE:":
            meminfo["PageTables"] = round(int(words[1]) * page_unit)
        elif words[0] == "NR_UNSTABLE_NFS:":
            meminfo["NFS_Unstable"] = round(int(words[1]) * page_unit)
        elif words[0] == "NR_BOUNCE:":
            meminfo["Bounce"] = round(int(words[1]) * page_unit)
        elif words[0] == "NR_WRITEBACK_TEMP:":
            meminfo["WritebackTmp"] = round(int(words[1]) * page_unit)
        elif words[0] == "NR_ANON_TRANSPARENT_HUGEPAGES:":
            meminfo["AnonHugePages"] = round(int(words[1]) * page_unit)


    meminfo["CommitLimit"] = vm_commit_limit()
    meminfo["Committed_AS"] = vm_committed_as()

    if 'MemTotal' in meminfo and 'MemFree' in meminfo:
        meminfo['MemAvailable'] = si_mem_available()

    vmalloctotal, vmallocused, vmallocchunk = get_vmalloc_info()
    meminfo['VmallocTotal'] = vmalloctotal
    meminfo['VmallocUsed'] = vmallocused
    meminfo['VmallocChunk'] = vmallocchunk

    if symbol_exists("pcpu_nr_populated") and symbol_exists("pcpu_nr_units"):
        pcpu_nr_populated = readSymbol("pcpu_nr_populated")
        pcpu_nr_units = readSymbol("pcpu_nr_units")
        meminfo['Percpu'] = int(pcpu_nr_populated * pcpu_nr_units * page_unit)

    meminfo['HardwareCorrupted'] = get_hardware_corrupted()

    hp_total, hp_free, hp_rsvd, hp_surp, hp_size = get_hugepages_details()
    meminfo['HugePages_Total'] = hp_total
    meminfo['HugePages_Free'] = hp_free
    meminfo['HugePages_Rsvd'] = hp_rsvd
    meminfo['HugePages_Surp'] = hp_surp
    meminfo['Hugepagesize'] = hp_size
    dm4k, dm2m, dm4m, dm1g = get_directmap_details()
    if dm4k > 0:
        meminfo["DirectMap4k"] = dm4k
    if dm2m > 0:
        meminfo["DirectMap2M"] = dm2m
    if dm4m > 0:
        meminfo["DirectMap4M"] = dm4m
    if dm4k > 0:
        meminfo["DirectMap1G"] = dm1g
    result_str = "" + get_entry_in_dict(meminfo, "MemTotal", " kB\n") +\
                get_entry_in_dict(meminfo, "MemFree", " kB\n") +\
                get_entry_in_dict(meminfo, "MemAvailable", " kB\n") +\
                get_entry_in_dict(meminfo, "Buffers", " kB\n") +\
                get_entry_in_dict(meminfo, "Cached", " kB\n") +\
                get_entry_in_dict(meminfo, "SwapCached", " kB\n") +\
                get_entry_in_dict(meminfo, "Active", " kB\n") +\
                get_entry_in_dict(meminfo, "Inactive", " kB\n") +\
                get_entry_in_dict(meminfo, "Active(anon)", " kB\n") +\
                get_entry_in_dict(meminfo, "Inactive(anon)", " kB\n") +\
                get_entry_in_dict(meminfo, "Active(file)", " kB\n") +\
                get_entry_in_dict(meminfo, "Inactive(file)", " kB\n") +\
                get_entry_in_dict(meminfo, "Unevictable", " kB\n") +\
                get_entry_in_dict(meminfo, "Mlocked", " kB\n") +\
                get_entry_in_dict(meminfo, "SwapTotal", " kB\n") +\
                get_entry_in_dict(meminfo, "SwapFree", " kB\n") +\
                get_entry_in_dict(meminfo, "Dirty", " kB\n") +\
                get_entry_in_dict(meminfo, "Writeback", " kB\n") +\
                get_entry_in_dict(meminfo, "AnonPages", " kB\n") +\
                get_entry_in_dict(meminfo, "Mapped", " kB\n") +\
                get_entry_in_dict(meminfo, "Shmem", " kB\n") +\
                get_entry_in_dict(meminfo, "Slab", " kB\n") +\
                get_entry_in_dict(meminfo, "SReclaimable", " kB\n") +\
                get_entry_in_dict(meminfo, "SUnreclaim", " kB\n") +\
                get_entry_in_dict(meminfo, "KernelStack", " kB\n") +\
                get_entry_in_dict(meminfo, "PageTables", " kB\n") +\
                get_entry_in_dict(meminfo, "NFS_Unstable", " kB\n") +\
                get_entry_in_dict(meminfo, "Bounce", " kB\n") +\
                get_entry_in_dict(meminfo, "WritebackTmp", " kB\n") +\
                get_entry_in_dict(meminfo, "CommitLimit", " kB\n") +\
                get_entry_in_dict(meminfo, "Committed_AS", " kB\n") +\
                get_entry_in_dict(meminfo, "VmallocTotal", " kB\n") +\
                get_entry_in_dict(meminfo, "VmallocUsed", " kB\n") +\
                get_entry_in_dict(meminfo, "VmallocChunk", " kB\n") + \
                get_entry_in_dict(meminfo, "Percpu", " kB\n") + \
                get_entry_in_dict(meminfo, "HardwareCorrupted", " kB\n") +\
                get_entry_in_dict(meminfo, "AnonHugePages", " kB\n") +\
                get_entry_in_dict(meminfo, "HugePages_Total", "\n") +\
                get_entry_in_dict(meminfo, "HugePages_Free", "\n") +\
                get_entry_in_dict(meminfo, "HugePages_Rsvd", "\n") +\
                get_entry_in_dict(meminfo, "HugePages_Surp", "\n") +\
                get_entry_in_dict(meminfo, "Hugepagesize", " kB\n") +\
                get_entry_in_dict(meminfo, "DirectMap4k", " kB\n") +\
                get_entry_in_dict(meminfo, "DirectMap2M", " kB\n") +\
                get_entry_in_dict(meminfo, "DirectMap4M", " kB\n") +\
                get_entry_in_dict(meminfo, "DirectMap1G", " kB\n")

    return result_str


def get_meminfo_dict():
    """
    Get memory information as a dictionary (without formatting).

    Returns:
        dict: Memory information dictionary with keys like 'MemTotal', 'MemFree', etc.
              Values are in KB.
    """
    global page_size

    page_size = 1 << get_page_shift()
    meminfo={}

    resultlines = exec_crash_command("kmem -i").splitlines()
    page_unit = page_size // 1024
    meminfo['MemFree'] = 0
    for line in resultlines:
        words = line.split()
        if len(words) == 0:
            continue
        if words[0] == 'TOTAL':
            if words[1] == 'MEM':
                meminfo['MemTotal'] = round(int(words[2]) * page_unit) # Convert pages
            elif words[1] == 'HUGE':
                meminfo['HugePages_Total'] = int(words[2])
            elif words[1] == 'SWAP':
                meminfo['SwapTotal'] = round(int(words[2]) * page_unit)
        elif words[0] == 'HUGE':
            if words[1] == 'FREE':
                meminfo['HugePages_Free'] = int(words[2])
        elif words[0] == 'FREE':
            val = words[1]
            if words[1] == 'HIGH' or words[1] == 'LOW':
                val = words[2]
            meminfo['MemFree'] = meminfo['MemFree'] + \
                    round(int(val) * page_unit)
        elif words[0] == 'BUFFERS':
            meminfo['Buffers'] = round(int(words[1]) * page_unit)
        elif words[0] == 'CACHED':
            meminfo['Cached'] = round(int(words[1]) * page_unit)
        elif words[0] == 'SLAB':
            meminfo['Slab'] = round(int(words[1]) * page_unit)
        elif words[0] == 'SWAP':
            if words[1] == 'FREE':
                meminfo['SwapFree'] = round(int(words[2]) * page_unit)

    # Get actual huge page details from kernel structures
    # Note: kmem -i shows huge pages in regular 4KB page units, but we need
    # the actual count of huge pages from the kernel structures
    try:
        hp_total, hp_free, hp_rsvd, hp_surp, hp_size = get_hugepages_details()
        if hp_total > 0:
            meminfo['HugePages_Total'] = hp_total  # Actual count of huge pages
            meminfo['HugePages_Free'] = hp_free
            meminfo['Hugepagesize'] = hp_size  # Size of each huge page in KB
    except:
        pass

    return meminfo


def get_size_str(size, coloring = False):
    size_str = ""
    if size > (1024 * 1024 * 1024): # GiB
        size_str = "%.1f GiB" % (size / (1024*1024*1024))
        if coloring == True:
            crashcolor.set_color(crashcolor.RED)
    elif size > (1024 * 1024): # MiB
        size_str = "%.1f MiB" % (size / (1024*1024))
        if coloring == True:
            crashcolor.set_color(crashcolor.MAGENTA)
    elif size > (1024): # KiB
        size_str = "%.1f KiB" % (size / (1024))
        if coloring == True:
            crashcolor.set_color(crashcolor.GREEN)
    else:
        size_str = "%.0f B" % (size)

    return size_str


def get_terminal_width():
    """
    Get terminal width - tries multiple methods for SSH/tunneled environments.

    Returns:
        int: Terminal width in columns, or 80 if unable to determine
    """
    try:
        # Method 1: Try os.get_terminal_size on stdout (works in SSH)
        # This directly queries the file descriptor, bypassing shell
        try:
            import sys
            # Try stdout first (most likely to work in SSH)
            size = os.get_terminal_size(sys.stdout.fileno())
            if size.columns > 0:
                return size.columns
        except:
            pass

        # Method 2: Try os.get_terminal_size on stderr
        try:
            import sys
            size = os.get_terminal_size(sys.stderr.fileno())
            if size.columns > 0:
                return size.columns
        except:
            pass

        # Method 3: Try os.get_terminal_size on stdin
        try:
            import sys
            size = os.get_terminal_size(sys.stdin.fileno())
            if size.columns > 0:
                return size.columns
        except:
            pass

        # Method 4: Try shutil (uses os.get_terminal_size internally but with fallback)
        try:
            terminal_size = shutil.get_terminal_size(fallback=(80, 24))
            if terminal_size.columns > 0:
                return terminal_size.columns
        except:
            pass

        # Method 5: Use crash's shell execution to run tput cols
        try:
            result = exec_crash_command("! tput cols 2>/dev/null")
            width = int(result.strip())
            if width > 0:
                return width
        except:
            pass

        # Method 6: Use crash's shell execution to run stty size
        try:
            result = exec_crash_command("! stty size 2>/dev/null")
            parts = result.strip().split()
            if len(parts) >= 2:
                width = int(parts[1])
                if width > 0:
                    return width
        except:
            pass

        # Method 7: Check COLUMNS environment variable
        try:
            columns = os.environ.get('COLUMNS')
            if columns and int(columns) > 0:
                return int(columns)
        except:
            pass

        # Fallback to 80 columns if all methods fail
        return 80
    except:
        # Fallback to 80 columns if unable to determine
        return 80


def get_optimal_max_widths(show_graph=False):
    """
    Calculate optimal maximum column widths based on terminal width.

    Args:
        show_graph: If True, account for graph column in calculations

    Returns:
        dict: Maximum widths for different column types
            - 'process_name': Max width for process names
            - 'slab_name': Max width for SLAB names
    """
    terminal_width = get_terminal_width()

    # Reserve space for other columns and padding
    # This matches separator_width formula: pname_width + 24 + 15 + 6 (graph)
    if show_graph:
        # With graph: Process_Name + Percent(24) + Usage(15) + padding(6)
        reserved_space = 24 + 15 + 6  # = 45
    else:
        # Without graph: Process_Name + Usage(15) + padding(3)
        # Based on show_oom_memory_usage: pname_width + 15 + 3
        reserved_space = 15 + 3  # = 18

    available_width = terminal_width - reserved_space

    # Set reasonable bounds
    # Process names: minimum 20, maximum based on available space (but cap at 100)
    process_max = max(20, min(100, available_width))

    # SLAB names: slightly smaller to account for additional columns
    # This matches separator_width formula: kmem_cache(18) + slab_width + graph(24) + TOTAL(12) + OBJSIZE(8) + padding(8)
    if show_graph:
        # SLAB table has: kmem_cache(18) + NAME + Percent(24) + TOTAL(12) + OBJSIZE(8) + padding(8)
        slab_reserved = 18 + 24 + 12 + 8 + 8  # = 70
    else:
        # SLAB table uses fixed width in non-graph mode, but calculate for consistency
        # Formula would be: kmem_cache(18) + NAME + TOTAL(12) + OBJSIZE(8) + padding(3)
        slab_reserved = 18 + 12 + 8 + 3  # = 41

    slab_available = terminal_width - slab_reserved
    slab_max = max(20, min(80, slab_available))

    return {
        'process_name': process_max,
        'slab_name': slab_max
    }


def truncate_middle(text, max_width):
    """
    Truncate text with ellipsis in the middle to preserve the end.

    This is useful for process names with full paths where the end
    contains the actual executable name.

    Args:
        text: String to truncate
        max_width: Maximum width including ellipsis

    Returns:
        Truncated string with '...' in the middle if needed

    Examples:
        truncate_middle("/usr/bin/very_long_process_name", 20)
        -> "/usr/bin/...s_name"
    """
    if len(text) <= max_width:
        return text

    if max_width < 4:
        return text[:max_width]

    # Reserve 3 characters for '...'
    available = max_width - 3
    # Split available space: slightly favor the end to preserve executable name
    left_chars = available // 2
    right_chars = available - left_chars

    return text[:left_chars] + "..." + text[-right_chars:]


def get_memory_bar(percentage, width=20):
    """
    Generate ASCII bar chart for memory usage percentage with 4 gradual shading levels

    Args:
        percentage: Usage percentage (0-100)
        width: Total width of bar in characters

    Returns:
        String representation of bar chart like: [████▓▒░░░░░]
        Uses 4 shading characters:
        ░ (light)  - empty portion
        ▒ (medium) - 0-33% of fractional character
        ▓ (heavy)  - 33-66% of fractional character
        █ (full)   - fully filled characters
    """
    if percentage < 0:
        percentage = 0
    if percentage > 100:
        percentage = 100

    # Calculate exact filled width (as float to get fractional part)
    exact_filled = (percentage / 100.0) * width
    filled_count = int(exact_filled)
    fraction = exact_filled - filled_count

    # Shading characters for gradual fill
    empty_char = '░'   # Light shade for empty
    light_char = '▒'   # Medium shade for 0-33% fill
    medium_char = '▓'  # Heavy shade for 33-66% fill
    full_char = '█'    # Full block for 100% fill

    # Build the bar with gradual shading
    bar_chars = []

    # Add fully filled characters
    bar_chars.extend([full_char] * filled_count)

    # Add fractional character if there's remaining space
    if filled_count < width:
        if fraction >= 0.66:
            bar_chars.append(full_char)    # 66-100% shows as full (almost complete)
        elif fraction >= 0.33:
            bar_chars.append(medium_char)  # 33-66% shows as heavy shade
        elif fraction > 0:
            bar_chars.append(light_char)   # 1-33% shows as medium shade
        else:
            bar_chars.append(empty_char)   # Exactly 0 shows as empty

    # Fill remaining with empty characters
    remaining = width - len(bar_chars)
    bar_chars.extend([empty_char] * remaining)

    bar = '[' + ''.join(bar_chars) + ']'

    # Add color coding based on usage level
    if percentage >= 90:
        crashcolor.set_color(crashcolor.RED)
    elif percentage >= 70:
        crashcolor.set_color(crashcolor.YELLOW)
    elif percentage >= 50:
        crashcolor.set_color(crashcolor.CYAN)
    else:
        crashcolor.set_color(crashcolor.GREEN)

    return bar

def get_pss_for_physical(paddr):
#    print(paddr)
    result_lines = []
    try:
        result_lines = exec_crash_command("kmem -p %s" % (paddr)).splitlines()
        if len(result_lines) != 2:
            return 0
    except:
#        print("kmem error on %s" % (paddr))
        return 0

    page_addr = result_lines[1].split()[0]
    pss = 0.0
    try:
        page = readSU("struct page", int(page_addr, 16))
#        print(page)
        if member_offset("struct page", "_refcount") >= 0:
            pss = 4096 / page._refcount.counter
        else:
            pss = 4096 / page._count.counter
#            print(pss)
    except:
#        print("error on %s" % (page_addr))
        pass

    return pss


def get_pss_for_task(task_addr):
    task = readSU("struct task_struct", int(task_addr, 16))
    if task.mm == 0:
        return 0
#    print(task)
    rss = 0
    idx = 0
    result_lines = exec_crash_command("vm -p %s" % (task_addr)).splitlines()
    total_lines = len(result_lines)
    while True:
        while idx < total_lines and not result_lines[idx].startswith("VIRTUAL"):
            idx = idx + 1

        idx = idx + 1
        if idx >= total_lines:
            break
        while idx < total_lines:
            line = result_lines[idx].split()
            idx = idx + 1
            if len(line) > 2 or len(line) == 0:
                continue

            if line[1] != 'PHYSICAL':
                rss = rss + get_pss_for_physical(line[1])

    if rss > 0:
        rss = rss / 4096.0
    return rss


def _init_page_conversion_parameters():
    """
    Initialize kernel parameters needed for physical-to-page-struct conversion.

    This should be called ONCE at module initialization, before any page
    conversion operations.

    Handles both old (mem_map) and new (vmemmap) kernel memory models.
    """
    global mem_map_base, vmemmap_base, phys_base, page_struct_size
    global using_vmemmap, page_conversion_initialized

    if page_conversion_initialized:
        return True

    try:
        # Determine page struct size
        page_struct_size = getSizeOf("struct page")
        if page_struct_size <= 0:
            print("[ERROR] Cannot determine sizeof(struct page)")
            return False

        # Try to use vmemmap (newer kernels with CONFIG_SPARSEMEM_VMEMMAP)
        try:
            vmemmap_base = readSymbol("vmemmap_base")
            using_vmemmap = True
            if debug_mode:
                print("[INFO] Using vmemmap_base for page struct conversion")
        except:
            # Fall back to mem_map array (older kernels or CONFIG_FLATMEM)
            try:
                mem_map_base = readSymbol("mem_map")
                using_vmemmap = False
                if debug_mode:
                    print("[INFO] Using mem_map for page struct conversion")
            except:
                print("[ERROR] Cannot find vmemmap_base or mem_map")
                return False

        # Get physical memory base
        # For x86_64, this is typically __START_KERNEL_map or phys_base
        try:
            phys_base = readSymbol("phys_base")
        except:
            # If phys_base doesn't exist, try page_offset or assume 0
            try:
                phys_base = readSymbol("page_offset")
            except:
                phys_base = 0

        if debug_mode:
            print("[INFO] Page conversion parameters initialized:")
            print("  - Page struct size: %d bytes" % page_struct_size)
            print("  - Using vmemmap: %s" % using_vmemmap)
            if using_vmemmap:
                print("  - vmemmap_base: 0x%x" % vmemmap_base)
            else:
                print("  - mem_map: 0x%x" % mem_map_base)
            print("  - phys_base: 0x%x" % phys_base)

        page_conversion_initialized = True
        return True

    except Exception as e:
        print("[ERROR] Failed to initialize page conversion: %s" % str(e))
        return False


def _physical_to_page_struct(phys_addr):
    """
    Convert a physical address to its corresponding page struct address.

    This replaces the need for calling 'vtop' command for every single page,
    which is the main performance bottleneck in shared memory analysis.

    Args:
        phys_addr: Physical address (integer)

    Returns:
        Page struct address (integer), or 0 on error

    Algorithm:
        PFN (Page Frame Number) = phys_addr / PAGE_SIZE

        For vmemmap model (newer kernels):
            page_struct = vmemmap_base + (PFN * sizeof(struct page))

        For mem_map model (older kernels):
            page_struct = mem_map + (PFN * sizeof(struct page))

    Performance:
        - Old approach: exec_crash_command("vtop 0x12345") takes ~10-50ms
        - New approach: Direct calculation takes ~0.001ms
        - Speedup: 10,000x - 50,000x per page
    """
    global mem_map_base, vmemmap_base, phys_base, page_struct_size
    global using_vmemmap, page_conversion_initialized

    # Validate initialization
    if not page_conversion_initialized:
        raise RuntimeError("Page conversion not initialized. Call _init_page_conversion_parameters() first.")

    # Handle zero/invalid addresses
    if phys_addr == 0:
        return 0

    # Calculate Page Frame Number (PFN)
    # Standard page size is 4096 bytes (4K)
    PAGE_SIZE = 4096
    pfn = phys_addr // PAGE_SIZE

    # Calculate page struct address based on kernel memory model
    if using_vmemmap:
        # vmemmap model: direct mapping of pfn to page struct array
        page_addr = vmemmap_base + (pfn * page_struct_size)
    else:
        # mem_map model: subtract physical base before indexing
        adjusted_pfn = (phys_addr - phys_base) // PAGE_SIZE
        page_addr = mem_map_base + (adjusted_pfn * page_struct_size)

    return page_addr


def _resolve_page_struct_address(vaddr):
    vtop_result = exec_crash_command("vtop %s" % (vaddr))
    if vtop_result == "":
        return 0

    vtop_lines = vtop_result.splitlines()
    if len(vtop_lines) == 0:
        return 0

    for line in reversed(vtop_lines):
        words = line.split()
        if len(words) == 0:
            continue
        try:
            return int(words[0], 16)
        except:
            continue
    return 0


def _collect_page_keys_for_vma(vma_addr, task_addr):
    global debug_mode
    page_keys = set()
    pages_skipped_zero_phys = 0
    pages_skipped_zero_struct = 0
    pages_added = 0

    try:
        # CRITICAL: vm -P requires task context to be set first
        # Set the task context, then run vm -P on the specific VMA
        exec_crash_command("set %s" % task_addr)
        result_str = exec_crash_command("vm -P %s" % (vma_addr))
        if result_str == "":
            if debug_mode:
                print("[DEBUG] vm -P returned empty for VMA %s" % vma_addr)
            return page_keys

        result_lines = result_str.splitlines()
        if len(result_lines) < 5:
            if debug_mode:
                print("[DEBUG] vm -P returned only %d lines for VMA %s" % (len(result_lines), vma_addr))
            return page_keys

        for i in range(4, len(result_lines)):
            page_words = result_lines[i].split()
            if len(page_words) < 2:
                continue

            try:
                physical_addr = int(page_words[1], 16)
                if physical_addr == 0:
                    pages_skipped_zero_phys += 1
                    continue
                vaddr = page_words[0]
            except:
                continue

            # Convert to PFN immediately to save memory
            # PFN = physical_address / page_size (4096 bytes)
            pfn = physical_addr >> 12
            page_keys.add(pfn)
            pages_added += 1

        if debug_mode and (pages_added > 0 or pages_skipped_zero_phys > 0 or pages_skipped_zero_struct > 0):
            print("[DEBUG] VMA %s: added=%d, skipped_phys=0:%d, skipped_struct=0:%d" %
                  (vma_addr, pages_added, pages_skipped_zero_phys, pages_skipped_zero_struct))

    except KeyboardInterrupt:
        # Propagate interrupt up
        raise

    return page_keys


def _collect_shared_page_keys(task_addr, task_name):
    global debug_mode
    vma_pages = set()
    shared_candidate_count = 0
    vma_count = 0
    shared_vma_count = 0

    try:
        result_str = exec_crash_command("vm %s" % task_addr)
        if not result_str:
            return vma_pages, shared_candidate_count

        result_lines = result_str.splitlines()
        if len(result_lines) < 4:
            return vma_pages, shared_candidate_count

        for i in range(4, len(result_lines)):
            vma_count += 1
            words = result_lines[i].split()
            if len(words) < 4:
                continue

            try:
                vma_start = int(words[1], 16)
                vma_end = int(words[2], 16)
                vm_flags = int(words[3], 16)
                vma_addr = words[0]
            except:
                continue

            if vma_end <= vma_start:
                continue

            filename = ' '.join(words[4:]) if len(words) >= 5 else ""

            # Only scan VMAs that can be genuinely shared between processes:
            # 1. VMAs with VM_SHARED flag (explicitly shared mappings)
            # 2. File-backed VMAs (shared libraries, executables)
            # 3. SYSV shared memory segments
            #
            # EXCLUDE private anonymous VMAs (heap, stack, private mmap):
            # - After fork(), child processes have COW (copy-on-write) references
            #   to parent's anonymous pages, so they map to the same PFNs initially
            # - These are PRIVATE pages that will become physically separate on write
            # - Including them would incorrectly count them as "shared"
            #
            # Note: Threads sharing mm_struct are already deduplicated via count_rss check
            is_potentially_shared = False

            # Check 1: Explicitly shared mappings (VM_SHARED or SHM segments)
            if vm_flags & (VM_SHARED | VM_SHM):
                is_potentially_shared = True
            # Check 2: File-backed VMAs (libraries, executables, mapped files)
            # But NOT anonymous regions like [heap], [stack], [anon:...]
            elif filename and not filename.startswith('['):
                is_potentially_shared = True

            # Dead code path removed: filename.startswith('SYSV') already caught above
            # Dead code path removed: anonymous VMAs without VM_SHARED should NOT be scanned

            if not is_potentially_shared:
                continue

            # This is the slow part - allow interruption
            page_keys = _collect_page_keys_for_vma(vma_addr, task_addr)
            if len(page_keys) > 0:
                shared_vma_count += 1
                vma_pages.update(page_keys)
                try:
                    shared_candidate_count = shared_candidate_count + ((vma_end - vma_start) // page_size)
                except:
                    shared_candidate_count = shared_candidate_count

    except KeyboardInterrupt:
        # Propagate interrupt up to the caller
        raise

    if debug_mode:
        print("[DEBUG] Task %s: %d VMAs total, %d potentially shared, %d unique pages collected" %
              (task_name, vma_count, shared_vma_count, len(vma_pages)))

    return vma_pages, shared_candidate_count


def collect_shared_mappings_global(task_list):
    """
    Collect shared pages across all tasks to identify overlaps by unique page frame.

    Memory-efficient implementation using PFNs and batch processing.

    Args:
        task_list: List of tuples (pname, task_addr, rss_kb)

    Returns:
        dict: {
            'page_to_task_count': {page_addr: count}, # Task count per unique mapped page frame
            'task_pages': {pname: set(page_addrs)},   # Pages per task
            'task_rss': {pname: rss_kb},              # RSS per task from ps
            'total_shared_kb': global shared,
            'total_private_kb': global private,
            'over_counted_kb': over-counted amount
        }
    """
    global page_size
    global debug_mode

    # Initialize page conversion parameters (ONCE)
    global page_conversion_initialized
    if not page_conversion_initialized:
        if not _init_page_conversion_parameters():
            crashcolor.set_color(crashcolor.YELLOW)
            print("WARNING: Cannot initialize optimized page conversion")
            print("Falling back to vtop (this will be VERY slow)")
            crashcolor.set_color(crashcolor.RESET)
            # Continue anyway, will use fallback

    # Use PFNs (Page Frame Numbers) instead of full addresses to save memory
    # PFN = page_addr >> 12, converting back: page_addr = PFN << 12
    # This saves ~50% memory since we only store the page frame number
    pfn_to_task_count = {} # Track each unique PFN and how many tasks reference it
    task_pfns = {}         # Track PFNs per task
    task_rss = {}          # Track RSS per task
    seen_mm_for_rss = {}   # Track unique mm_struct addresses per pname to avoid thread double-counting
    scanned_vma_bytes = 0

    total_tasks = len(task_list)
    tasks_analyzed = 0

    sys.stdout.write("Analyzing shared mappings:\n")
    sys.stdout.flush()

    try:
        for idx, (pname, task_addr, rss_kb) in enumerate(task_list):
            try:
                _pid = readSU("task_struct", int(task_addr, 16)).pid
                _task_label = "%.12s (PID %d)" % (pname, _pid)
            except:
                _task_label = "%.12s" % pname
            _progress_msg = "  %d/%d tasks | Current: %-28s (Ctrl-C)" % (
                idx + 1, total_tasks, _task_label)
            sys.stdout.write("\r" + _progress_msg)
            sys.stdout.flush()

            # Deduplicate threads by mm_struct: only accumulate RSS once per unique
            # mm_struct address. Threads share mm_struct, so counting all would
            # inflate task_rss and corrupt the unscanned-page fallback calculation.
            # This must run BEFORE the try block so the exception handler can use it.
            count_rss = True
            try:
                task_struct = readSU("task_struct", int(task_addr, 16))
                mm_addr = task_struct.mm
                if mm_addr == 0:
                    count_rss = False  # Kernel thread
                elif mm_addr in seen_mm_for_rss.get(pname, set()):
                    count_rss = False
                else:
                    seen_mm_for_rss.setdefault(pname, set()).add(mm_addr)
            except:
                pass  # If unreadable, count conservatively

            # Skip PFN scan for duplicate mm_struct (threads share page tables)
            if not count_rss:
                continue

            try:
                page_keys, candidate_bytes = _collect_shared_page_keys(task_addr, pname)
                scanned_vma_bytes = scanned_vma_bytes + candidate_bytes

                # page_keys already contains PFNs (converted in _collect_page_keys_for_vma)
                pfn_keys = page_keys

                # Debug: Show page collection for first few tasks
                if debug_mode and idx < 3:
                    print("\n[DEBUG] Task %d (%s):" % (idx, pname))
                    print("  task_addr: %s, rss: %d KB" % (task_addr, rss_kb))
                    print("  Collected %d unique pages from potentially shared VMAs" % len(pfn_keys))
                    print("  Scanned VMA bytes: %d" % candidate_bytes)

                # Accumulate PFNs and RSS for processes with same name (grouped processes)
                if pname in task_pfns:
                    task_pfns[pname].update(pfn_keys)  # Add to existing set
                    if count_rss:
                        task_rss[pname] += rss_kb      # Add to existing RSS only for unique mm
                else:
                    task_pfns[pname] = pfn_keys.copy() # Create new set
                    task_rss[pname] = rss_kb if count_rss else 0

                for pfn in pfn_keys:
                    if pfn in pfn_to_task_count:
                        pfn_to_task_count[pfn] += 1
                    else:
                        pfn_to_task_count[pfn] = 1

                tasks_analyzed += 1

                # Garbage collect every 100 tasks to prevent memory buildup
                if (idx + 1) % 100 == 0:
                    gc.collect()

            except KeyboardInterrupt:
                # Re-raise to outer handler
                raise
            except Exception as e:
                if debug_mode:
                    print("Error analyzing task %s: %s" % (pname, str(e)))
                # Accumulate RSS even if page collection fails, respecting mm_struct dedup
                if pname in task_rss:
                    if count_rss:
                        task_rss[pname] += rss_kb
                else:
                    task_pfns[pname] = set()
                    task_rss[pname] = rss_kb if count_rss else 0

    except KeyboardInterrupt:
        print("\n")
        crashcolor.set_color(crashcolor.YELLOW)
        print("\n*** Analysis interrupted by user (Ctrl-C) ***")
        print("Analyzed %d out of %d tasks" % (tasks_analyzed, total_tasks))
        print("Showing partial results based on analyzed tasks...\n")
        crashcolor.set_color(crashcolor.RESET)

    sys.stdout.write("\r" + " " * 79 + "\r")  # Clear progress line
    sys.stdout.flush()

    # Debug: Show analysis summary
    if debug_mode:
        print("\n[DEBUG] Shared memory analysis summary:")
        print("  Total tasks analyzed: %d" % len(task_pfns))
        print("  Total unique pages tracked: %d" % len(pfn_to_task_count))

        # Count how many pages are shared
        shared_page_count = sum(1 for count in pfn_to_task_count.values() if count >= 2)
        private_page_count = sum(1 for count in pfn_to_task_count.values() if count == 1)
        print("  Pages mapped by 2+ tasks: %d" % shared_page_count)
        print("  Pages mapped by 1 task: %d" % private_page_count)

        # Show some example shared pages
        if shared_page_count > 0:
            print("  Sample of shared pages:")
            count = 0
            for pfn, task_count in pfn_to_task_count.items():
                if task_count >= 2 and count < 5:
                    print("    PFN 0x%x: mapped by %d tasks" % (pfn, task_count))
                    count += 1

    # Calculate global totals
    total_shared_bytes = 0
    total_private_bytes = 0
    over_counted_bytes = 0
    for _, count in pfn_to_task_count.items():
        if count >= 2:
            total_shared_bytes += page_size
            if count > 1:
                over_counted_bytes += (count - 1) * page_size
        else:
            total_private_bytes += page_size

    # Calculate per-task private and shared
    task_private = {}
    task_shared = {}
    for pname, pfn_set in task_pfns.items():
        shared_kb = 0
        private_kb = 0
        for pfn in pfn_set:
            if pfn_to_task_count.get(pfn, 1) >= 2:
                shared_kb += page_size // 1024
            else:
                private_kb += page_size // 1024

        # RSS might be larger than scanned pages (not all VMAs are scanned)
        # Unscanned portion is assumed private
        rss = task_rss.get(pname, 0)
        scanned_total = shared_kb + private_kb
        if rss > scanned_total:
            private_kb += (rss - scanned_total)

        task_shared[pname] = shared_kb
        task_private[pname] = private_kb

    # Keep total_private_bytes and total_shared_bytes from page-level scan (lines 1654-1660)
    # Do NOT recalculate from per-task sums, as they include unscanned RSS portions
    # which would inflate totals far beyond physical RAM (see bug causing 2311% overflow)
    # Per-task values can show unscanned RSS for display, but global totals must
    # be based on actual scanned page frames only.

    # Free memory before returning
    del pfn_to_task_count
    del task_pfns
    gc.collect()

    return {
        'page_to_task_count': {},  # Empty now, no longer needed
        'task_shared': task_shared,
        'task_private': task_private,
        'task_rss': task_rss,
        'total_shared_kb': total_shared_bytes // 1024,
        'total_private_kb': total_private_bytes // 1024,
        'over_counted_kb': over_counted_bytes // 1024,
        'scanned_vma_bytes': scanned_vma_bytes
    }


def show_tasks_memusage(options):
    mem_usage_dict = {}
    pid_count_dict = {}   # tracks how many PIDs are grouped per name
    account_shared = getattr(options, 'account_shared', False)

    if options.memusage_pss:
        print("Experimental stage for Pss")
        print("It will take quite sometime to gather Pss based memory usage")

    if account_shared:
        crashcolor.set_color(crashcolor.YELLOW)
        print("Analyzing VM details for shared memory accounting...")
        print("This will take some time as it analyzes page reference counts.")
        print("Press Ctrl-C to stop and show partial results.\n")
        crashcolor.set_color(crashcolor.RESET)

    # Get system's total memory for percentage calculation
    system_meminfo = get_meminfo_dict()
    system_total_mem_kb = system_meminfo.get('MemTotal', 0)

    if (options.nogroup):
        crash_command = "ps"
    else:
        crash_command = "ps -G"

    result = exec_crash_command(crash_command)
    result_lines = result.splitlines(True)
    total_rss = 0
    total_shared = 0
    total_private = 0

    # First pass: collect all tasks with RSS
    task_list = []  # List of (pname, task_addr, rss_kb)
    seen_mm_structs = set()  # Track unique mm_struct addresses to avoid counting threads twice

    for i in range(1, len(result_lines)):
        if (result_lines[i].find('>') == 0):
            result_lines[i] = result_lines[i].replace('>', ' ', 1)
        result_line = result_lines[i].split()
        if (len(result_line) < 9):
            continue
        pid = result_line[0]
        cmd = result_line[8]
        cmd = result_lines[i][result_lines[i].find(cmd):].strip()
        if options.all:
            pname = "%s (%s)" % (cmd, pid)
        else:
            pname = cmd

        # Get RSS from ps output (this is the correct value)
        rss = int(result_line[7])
        if options.memusage_pss:
            rss = get_pss_for_task(result_line[3])

        task_addr = result_line[3]  # TASK address

        # Store task info for potential shared memory analysis
        if account_shared:
            task_list.append((pname, task_addr, rss))

        # Deduplicate threads: only count RSS for unique mm_struct addresses.
        # Threads in the same process share mm_struct, so counting all threads
        # would inflate total_rss by the thread count per process.
        is_unique_process = True
        try:
            task_struct = readSU("task_struct", int(task_addr, 16))
            mm_addr = task_struct.mm
            if mm_addr == 0:
                is_unique_process = False  # Kernel thread, no user memory
            elif mm_addr in seen_mm_structs:
                is_unique_process = False
            else:
                seen_mm_structs.add(mm_addr)
        except:
            pass  # If mm_struct unreadable, count conservatively

        if is_unique_process:
            total_rss = total_rss + rss
        if (pname in mem_usage_dict):
            rss = mem_usage_dict[pname] + rss

        if rss != 0:
            mem_usage_dict[pname] = rss
        if not options.all:
            pid_count_dict[pname] = pid_count_dict.get(pname, 0) + 1

    # Second pass: analyze shared memory if requested
    task_private_dict = {}  # Per-task private memory
    task_shared_dict = {}   # Per-task shared memory

    if account_shared and len(task_list) > 0:
        crashcolor.set_color(crashcolor.YELLOW)
        print("\nAnalyzing shared memory mappings (Ctrl-C to stop)...")
        print("Total tasks to analyze: %d" % len(task_list))

        # Show distribution of tasks by process name
        if getattr(options, 'debug', False):
            try:
                from collections import Counter
                task_names = [pname for pname, _, _ in task_list]
                name_counts = Counter(task_names)
                print("[DEBUG] Process distribution:")
                for name, count in sorted(name_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
                    print("  %s: %d instances" % (name, count))
            except Exception as e:
                print("[DEBUG] Error showing process distribution: %s" % str(e))

        crashcolor.set_color(crashcolor.RESET)
        shared_info = collect_shared_mappings_global(task_list)

        # Total shared pages (counted once) - pages mapped by 2+ tasks
        total_shared = shared_info['total_shared_kb']

        # Over-counted amount - shared pages were counted N times in RSS, but should be counted once
        # So we over-counted them (N-1) times
        over_counted = shared_info['over_counted_kb']

        # Get per-task breakdowns
        task_private_dict = shared_info['task_private']
        task_shared_dict = shared_info['task_shared']

        # Calculate private memory correctly:
        # total_rss includes all memory (private + shared counted multiple times)
        # total_shared is the unique count of shared pages
        # over_counted is how many times shared pages were over-counted (N-1 for each)
        # Therefore: total_private = total_rss - total_shared - over_counted
        total_private = total_rss - total_shared - over_counted
        actual_total_kb = total_private + total_shared

        # Sanity check: ensure no negative values
        if total_private < 0:
            if debug_mode:
                print("Warning: Calculated negative private memory, adjusting")
                print("  total_rss=%d KB, over_counted=%d KB, total_shared=%d KB" %
                      (total_rss, over_counted, total_shared))
            total_private = 0
            actual_total_kb = total_shared

        if debug_mode:
            print("Debug: total_rss=%d KB, total_shared=%d KB, over_counted=%d KB" %
                  (total_rss, total_shared, over_counted))
            print("Debug: actual_total=%d KB, total_private=%d KB" %
                  (actual_total_kb, total_private))

        print("Shared memory analysis complete.\n")

    sorted_usage = sorted(mem_usage_dict.items(),
                          key=operator.itemgetter(1), reverse=True)

    min_number = 10
    if (options.all):
        min_number = len(sorted_usage) - 1

    print_count = min(len(sorted_usage) - 1, min_number)

    # Detect terminal width fresh right before display to catch any resizes
    # Calculate optimal column width based on terminal width and longest process name
    if options.graph:
        initial_terminal_width = get_terminal_width()
        max_widths = get_optimal_max_widths(show_graph=True)
        max_pname_len = max(len(sorted_usage[i][0]) for i in range(0, print_count)) if print_count > 0 else 20
        pname_width = max(20, min(max_widths['process_name'], max_pname_len + 1))

        if account_shared:
            # Wider format for Private/Shared/Total breakdown
            separator_width = pname_width + 15 + 15 + 15 + 8  # Process + Private + Shared + Total + padding
        else:
            separator_width = pname_width + 24 + 15 + 6  # Process_Name + Percent + Usage + padding
    else:
        separator_width = 70
        initial_terminal_width = 80

    # Print header
    print("=" * separator_width)
    if options.graph:
        if account_shared:
            format_str = "%-" + str(pname_width) + "s %15s %15s %15s"
            print(format_str % ("Process_Name", "Private", "Shared", "Total(RSS)"))
        else:
            format_str = "%-" + str(pname_width) + "s %-24s %15s"
            print(format_str % ("Process_Name", "Usage_Percent", "RSS_Usage"))
    else:
        print("%24s          %-s" % (" [ RSS usage ]", "[ Process name ]"))
    print("-" * separator_width)  # Add separator line between header and data

    for i in range(0, print_count):
        # Check for terminal resize every 10 rows (to avoid excessive system calls)
        if options.graph and i > 0 and i % 10 == 0:
            current_width = get_terminal_width()
            if abs(current_width - initial_terminal_width) > 5:
                # Terminal resized significantly - restart table with new width
                print("=" * separator_width)
                crashcolor.set_color(crashcolor.YELLOW)
                print("\n[Terminal resized - adjusting table width]\n")
                crashcolor.set_color(crashcolor.RESET)

                # Recalculate widths
                initial_terminal_width = current_width
                max_widths = get_optimal_max_widths(show_graph=True)
                pname_width = max(20, min(max_widths['process_name'], max_pname_len + 1))

                if account_shared:
                    separator_width = pname_width + 15 + 15 + 15 + 8
                else:
                    separator_width = pname_width + 24 + 15 + 6

                # Reprint header
                print("=" * separator_width)
                if account_shared:
                    format_str = "%-" + str(pname_width) + "s %15s %15s %15s"
                    print(format_str % ("Process_Name", "Private", "Shared", "Total(RSS)"))
                else:
                    format_str = "%-" + str(pname_width) + "s %-24s %15s"
                    print(format_str % ("Process_Name", "Usage_Percent", "RSS_Usage"))
                print("-" * separator_width)

        pname = sorted_usage[i][0]
        rss_kb = sorted_usage[i][1]
        # Append process count when grouping by name (not -a mode)
        if not options.all:
            cnt = pid_count_dict.get(pname, 1)
            if cnt > 1:
                pname = "%s (%d×)" % (pname, cnt)

        if options.graph:
            # Truncate process name to fit column width
            pname_display = truncate_middle(pname, pname_width)

            if account_shared:
                # Show Private, Shared, Total breakdown
                private_kb = task_private_dict.get(pname, rss_kb)  # Default to rss if not analyzed
                shared_kb = task_shared_dict.get(pname, 0)

                format_str = "%-" + str(pname_width) + "s %15s %15s %15s"
                print(format_str % (
                    pname_display,
                    get_size_str(private_kb * 1024),
                    get_size_str(shared_kb * 1024),
                    get_size_str(rss_kb * 1024)
                ))
                crashcolor.set_color(crashcolor.RESET)
            else:
                # Standard display with percentage bar
                percentage = (rss_kb * 100.0 / system_total_mem_kb) if system_total_mem_kb > 0 else 0
                bar = get_memory_bar(percentage, width=20)
                format_str = "%-" + str(pname_width) + "s %s %15s"
                print(format_str % (pname_display, bar, get_size_str(rss_kb * 1024)))
                crashcolor.set_color(crashcolor.RESET)
        else:
            print("%14s (%10.2f KiB)   %-s" %
                    (get_size_str(rss_kb * 1024, True),
                     rss_kb,
                     pname))
            crashcolor.set_color(crashcolor.RESET)

    if print_count < len(sorted_usage) - 1:
        print("\t<...>")
    print("=" * separator_width)

    # Calculate percentages for shared accounting (even if zero)
    shared_percentage = 0.0
    private_percentage = 0.0
    if account_shared and system_total_mem_kb > 0:
        shared_percentage = (total_shared * 100.0 / system_total_mem_kb)
        private_percentage = (total_private * 100.0 / system_total_mem_kb)

    # Show shared memory breakdown if --shared was used
    if account_shared:
        print()
        crashcolor.set_color(crashcolor.YELLOW)
        print("=" * 80)
        print("MEMORY BREAKDOWN (accounting for shared pages)")
        print("=" * 80)
        crashcolor.set_color(crashcolor.RESET)

        print("\nPer-Process Columns:")
        print("  Private  = Memory used only by this process (heap, stack, private data)")
        print("  Shared   = Memory shared with other processes (libraries, shared objects)")
        print("  Total    = RSS from ps (Private + Shared, may count shared pages multiple times)")

        print("\nGlobal Summary:")
        crashcolor.set_color(crashcolor.GREEN)
        print("  Total Private (all processes)           = %s" %
              (get_size_str(total_private * 1024)))
        if system_total_mem_kb > 0:
            print("    %.2f%% of total system memory" % private_percentage)
            if options.graph:
                bar = get_memory_bar(private_percentage, width=TOTAL_BAR_WIDTH)
                print("    %s" % bar)
        crashcolor.set_color(crashcolor.RESET)

        crashcolor.set_color(crashcolor.CYAN)
        print("  Total Shared (counted once, not per-process) = %s" %
              (get_size_str(total_shared * 1024)))
        if system_total_mem_kb > 0:
            print("    %.2f%% of total system memory" % shared_percentage)
            if options.graph:
                bar = get_memory_bar(shared_percentage, width=TOTAL_BAR_WIDTH)
                print("    %s" % bar)
        crashcolor.set_color(crashcolor.RESET)

        # Show actual total (private + shared, no double-counting)
        actual_total = total_private + total_shared
        crashcolor.set_color(crashcolor.BLUE)
        print("\n  Actual Total Memory Used (no duplicates)   = %s" %
              (get_size_str(actual_total * 1024)))

        if system_total_mem_kb > 0:
            actual_percentage = (actual_total * 100.0 / system_total_mem_kb)
            system_total_mem_bytes = system_total_mem_kb * 1024
            print("    %.2f%% of total system memory (%s)" %
                  (actual_percentage, get_size_str(system_total_mem_bytes)))
            if options.graph:
                bar = get_memory_bar(actual_percentage, width=TOTAL_BAR_WIDTH)
                print("    %s" % bar)
        crashcolor.set_color(crashcolor.RESET)

        # Also show raw RSS total for comparison
        crashcolor.set_color(crashcolor.YELLOW)
        print("\n  Raw RSS Total (for comparison)             = %s" %
              (get_size_str(total_rss * 1024)))
        if system_total_mem_kb > 0:
            rss_percentage = (total_rss * 100.0 / system_total_mem_kb)
            over_count_kb = total_rss - actual_total
            print("    %.2f%% of total system memory" % rss_percentage)
            print("    Over-counted by: %s (shared pages counted multiple times)" %
                  get_size_str(over_count_kb * 1024))
        crashcolor.set_color(crashcolor.RESET)

        print("\n" + "=" * 80)

    if not account_shared:
        crashcolor.set_color(crashcolor.BLUE)
        print("Total memory usage from user-space = %s" %
              (get_size_str(total_rss * 1024)))

        # Show total usage percentage with bar graph
        if system_total_mem_kb > 0:
            total_percentage = (total_rss * 100.0 / system_total_mem_kb)
            system_total_mem_bytes = system_total_mem_kb * 1024
            print("\tNotes) %.2f percent from total system memory(%s)" %
                  (total_percentage, get_size_str(system_total_mem_bytes)))
            if options.graph:
                bar = get_memory_bar(total_percentage, width=TOTAL_BAR_WIDTH)
                print("\t       %s" % bar)

    crashcolor.set_color(crashcolor.RESET)


def show_slabtop(options):
    # Get system's total memory for percentage calculation
    system_meminfo = get_meminfo_dict()
    system_total_mem_kb = system_meminfo.get('MemTotal', 0)

    result = exec_crash_command("kmem -s")
    result_lines = result.splitlines(True)
    slab_list = {}
    for i in range(1, len(result_lines) -1):
        result_line = result_lines[i].split()
        if (len(result_line) < 7):
            continue
        result_line[5] = result_line[5].replace("k", "")
        if options.compact:
            # There were case that SLABS * SSIZE shows wrongly
            # So, let's do it with objsize * total
            total_used = (int(result_line[1]) * int(result_line[3])) // 1024
        else:
            total_used = int(result_line[4]) * int(result_line[5])
        slab_list[result_line[0]] = total_used

    sorted_slabtop = sorted(slab_list.items(),
                            key=operator.itemgetter(1), reverse=True)
    min_number = 10
    if (options.all):
        min_number = len(sorted_slabtop) - 1

    print_count = min(len(sorted_slabtop) - 1, min_number)

    # Calculate total for display purposes
    total_slab = sum([item[1] for item in sorted_slabtop[:print_count]])

    # Calculate optimal column width based on terminal width and longest SLAB name
    if options.graph:
        # Get terminal width and calculate available space for NAME column
        initial_terminal_width = get_terminal_width()
        terminal_width = initial_terminal_width

        # Reserve space for: kmem_cache(18) + spaces + graph(24) + TOTAL(12) + OBJSIZE(8) + padding
        kmem_cache_width = 18  # "0x" + 16 hex digits
        graph_width = 24  # Graph column with brackets
        total_width = 12  # TOTAL column
        objsize_width = 8  # OBJSIZE column
        padding = 8  # Spaces between columns

        reserved = kmem_cache_width + graph_width + total_width + objsize_width + padding
        available_for_name = terminal_width - reserved

        # First pass: collect all SLAB names to find longest
        slab_names = []
        for i in range(0, print_count):
            kmem_cache = readSU("struct kmem_cache", int(sorted_slabtop[i][0], 16))
            slab_names.append(kmem_cache.name)

        max_slab_len = max(len(name) for name in slab_names) if slab_names else 15
        # Ensure NAME width fits: min 15 chars, max based on available space, prefer actual max length
        slab_width = max(15, min(available_for_name, max_slab_len + 1))

        # Calculate actual separator width to match terminal or be narrower
        separator_width = kmem_cache_width + slab_width + graph_width + total_width + objsize_width + padding
        # Cap at terminal width to prevent overflow
        separator_width = min(separator_width, terminal_width)
    else:
        slab_width = 29  # Default width when not using graph
        separator_width = 70
        initial_terminal_width = 80

    print("=" * separator_width)
    if options.graph:
        format_str = "%-18s %-" + str(slab_width) + "s %-24s %12s %8s"
        print(format_str % ("kmem_cache", "NAME", "Usage_Percent", "TOTAL", "OBJSIZE"))
    else:
        print("%-18s %-29s %12s %8s" % ("kmem_cache", "NAME", "TOTAL", "OBJSIZE"))
    print("-" * separator_width)  # Add separator line between header and data

    for i in range(0, print_count):
        # Check for terminal resize every 10 rows (to avoid excessive system calls)
        if options.graph and i > 0 and i % 10 == 0:
            current_width = get_terminal_width()
            if abs(current_width - initial_terminal_width) > 5:
                # Terminal resized significantly - restart table with new width
                print("=" * separator_width)
                crashcolor.set_color(crashcolor.YELLOW)
                print("\n[Terminal resized - adjusting table width]\n")
                crashcolor.set_color(crashcolor.RESET)

                # Recalculate widths
                initial_terminal_width = current_width
                terminal_width = current_width
                available_for_name = terminal_width - reserved
                slab_width = max(15, min(available_for_name, max_slab_len + 1))
                separator_width = kmem_cache_width + slab_width + graph_width + total_width + objsize_width + padding
                separator_width = min(separator_width, terminal_width)

                # Reprint header
                print("=" * separator_width)
                format_str = "%-18s %-" + str(slab_width) + "s %-24s %12s %8s"
                print(format_str % ("kmem_cache", "NAME", "Usage_Percent", "TOTAL", "OBJSIZE"))
                print("-" * separator_width)

        kmem_cache = readSU("struct kmem_cache", int(sorted_slabtop[i][0], 16))
        obj_size = 0
        if (member_offset('struct kmem_cache', 'buffer_size') >= 0):
            obj_size = kmem_cache.buffer_size
        elif (member_offset('struct kmem_cache', 'object_size') >= 0):
            obj_size = kmem_cache.object_size

        slab_name = kmem_cache.name
        # Truncate SLAB name to fit column width
        slab_name = truncate_middle(slab_name, slab_width)

        if options.graph:
            # Calculate percentage based on system's total memory
            percentage = (sorted_slabtop[i][1] * 100.0 / system_total_mem_kb) if system_total_mem_kb > 0 else 0
            bar = get_memory_bar(percentage, width=20)
            format_str = "0x%16s %-" + str(slab_width) + "s %s %12s %8d"
            print(format_str % (sorted_slabtop[i][0], slab_name, bar,
                               get_size_str(sorted_slabtop[i][1] * 1024), obj_size))
            crashcolor.set_color(crashcolor.RESET)
        else:
            print("0x%16s %-29s %12s %8d" %
                    (sorted_slabtop[i][0],
                     slab_name,
                     get_size_str(sorted_slabtop[i][1] * 1024, True),
                     obj_size))
            crashcolor.set_color(crashcolor.RESET)

    if print_count < len(sorted_slabtop) - 1:
        print("\t<...>")
    print("=" * separator_width)

    # Show total slab usage
    crashcolor.set_color(crashcolor.BLUE)
    print("Total slab memory usage = %s" % get_size_str(total_slab * 1024))

    # Show total usage percentage with bar graph
    if system_total_mem_kb > 0:
        total_percentage = (total_slab * 100.0 / system_total_mem_kb)
        system_total_mem_bytes = system_total_mem_kb * 1024
        print("\tNotes) %.2f percent from total system memory(%s)" %
              (total_percentage, get_size_str(system_total_mem_bytes)))
        if options.graph:
            bar = get_memory_bar(total_percentage, width=TOTAL_BAR_WIDTH)
            print("\t       %s" % bar)
            crashcolor.set_color(crashcolor.RESET)

    crashcolor.set_color(crashcolor.RESET)


def show_full_slab(options, kmem_cache, addr, slab_addr, offset):
    page = readSU("struct page", slab_addr)
    total_slab = page.objects & 0xff # Make sure it only uses a byte
    alloc_item = True
    if kmem_cache.max.x != total_slab:
        print("kmem_cache.max.x = %d" % (kmem_cache.max.x))
        print("total_slab in page = %d" % (total_slab))

    for idx in range(0, total_slab):
        obj_addr = addr + kmem_cache.size * idx
        #print("0x%x" % obj_addr)


def show_partial_slab(options, kmem_cache, slab_addr, offset):
    lines = exec_crash_command("kmem -S 0x%x" % (slab_addr)).splitlines()
    is_head = True

    for line in lines:
        line = line.strip()
        if line.startswith("FREE"):
            is_head = False
            continue

        if is_head:
            continue

        if not line.startswith("["):
            if not options.all:
                continue
            alloc_item = False
            line = line.split()[0]
        else:
            alloc_item = True
            line = line[1:-1]

        obj_addr = int(line, 16)
        print("0x%x" % obj_addr)


###
### readList and readSUListFromHead are revised to improve performance
###

_MAXEL = 10000

def readList(start, offset=0, *, maxel=_MAXEL, inchead=True, warn=True):
    start = int(start)  # Equivalent to (void *) cast
    if start == 0:
        return []

    out = [start] if inchead else []
    known = {start} if inchead else set()
    count = 1 if inchead else 0
    next_ptr = start

    while count < maxel:
        try:
            next_ptr = readPtr(next_ptr + offset)
        except crash.error as val:
            print(val)
            break

        if next_ptr == 0 or next_ptr == start or next_ptr in known:
            if next_ptr in known:
                pylog.error("Circular dependency in list")
            break

        out.append(next_ptr)
        known.add(next_ptr)
        count += 1

    if count == maxel:
        if warn:
            warn_maxel(maxel)

    return out


def readSUListFromHead(headaddr, listfieldname, mystruct,
                                 maxel=1000000, inchead=False, warn=True):
    global debug_mode

    if debug_mode:
        print("readSUListFromHead()")

    msi = getStructInfo(mystruct)
    offset = msi[listfieldname].offset

    if isinstance(headaddr, str):
        headaddr = sym2addr(headaddr) + offset

    addresses = readList(headaddr, 0, maxel=maxel+1, inchead=inchead, warn=warn)

    truncated = len(addresses) > maxel
    if truncated:
        addresses = addresses[:-1]

    # Preallocate and avoid repeated list growth
    out = [readSU(mystruct, p - offset) for p in addresses]

    if truncated and warn:
        warn_maxel(maxel)

    if debug_mode:
        print("readSUListFromHead() Done")
    return out

###
### readList and readSUListFromHead are revised to improve performance
###


def show_slabs_in_node(options, kmem_cache, kc_node, offset):
    global alloc_count

    alloc_count = 0
    try:
        if member_offset("struct slab", "slab_list") >= 0:
            offset_name = "slab_list"
            struct_name = "struct slab"
        else:
            offset_name = "lru"
            struct_name = "struct page"

        if member_offset("struct kmem_cache_node", "partial") >= 0:
            for page in readSUListFromHead(kc_node.partial,
                                            offset_name,
                                            struct_name,
                                            maxel=1000000000):
                show_one_slab(options, kmem_cache, Addr(page), False, offset)

                if options.maxcount > 0 and alloc_count > options.maxcount:
                    break


        if member_offset("struct kmem_cache_node", "full") >= 0:
            for page in readSUListFromHead(kc_node.full,
                                            offset_name,
                                            struct_name,
                                            maxel=1000000000):
                show_one_slab(options, kmem_cache, Addr(page), False, offset)

                if options.maxcount > 0 and alloc_count > options.maxcount:
                    break
    except Exception as e:
        print(e)


    if alloc_count > 0:
        show_slab_alloc_result(options, kmem_cache)

    return alloc_count > 0



def show_one_slab(options, kmem_cache, slab_addr, full_mode, offset):
    global alloc_count

    lines = exec_crash_command("kmem -S 0x%x" % slab_addr).splitlines()

    for line in lines[3:]:
        words = line.split()
        if len(words) < 5 or words[0] == "SLAB":
            continue

        try:
            if full_mode:
                show_alloc_track(options, kmem_cache, int(words[1], 16),
                        int(words[0], 16), offset)
            else:
                show_partial_alloc_track(options, kmem_cache,
                        int(words[0], 16), offset)
        except Exception as e:
            print(e)
            break

        if options.maxcount > 0 and alloc_count > options.maxcount:
            break



def show_slab_alloc_result(options, kmem_cache):
    global alloc_func_list
    global alloc_pid_list
    global alloc_count

    global free_func_list
    global free_pid_list
    global free_count

    global calltrace_list


    sorted_alloc_func_list = sorted(alloc_func_list.items(),
                          key=operator.itemgetter(1), reverse=True)
    print_count = 0
    if alloc_count > 0:
        print("%10s %10s : %s" % ("OBJ_COUNT", "TOTAL_SIZE", "FUNCTION"))
    for addr, count in sorted_alloc_func_list:
        if addr == 0:
            continue
        sym_name = get_function_name(addr)
        print("%10d (%8s) : %s" %
              (count, get_size_str(count * kmem_cache.object_size),
               sym_name))
        print_count = print_count + 1
        if not options.all and print_count > 9:
            if len(sorted_alloc_func_list) > 10:
                print("\n%15s %d %s" % (
                        "... < skiped ",
                        len(sorted_alloc_func_list) - 10,
                        " items > ..."))
            break

    print("")
    print("Total allocated object count = %d" % (alloc_count))
    print("      allocated object size  = %s" %
          (get_size_str(alloc_count * kmem_cache.object_size, True)))
    print("\n\t", end="")
    crashcolor.set_color(crashcolor.LIGHTGRAY + crashcolor.UNDERLINE)
    print("Caution: This size doesn't include data structure and padding, etc")
    crashcolor.set_color(crashcolor.RESET)

    if not options.details:
        return

    # Some further details
    show_alloc_pid_list(options)

    print("\nFrequence of calltraces:")
    if options.memory_limit > 0 and len(calltrace_list) >= options.memory_limit:
        print("  (Limited to %d unique patterns for memory optimization)" % options.memory_limit)
    print("=" * 60)
    sorted_calltrace_list = sorted(calltrace_list.items(),
                          key=operator.itemgetter(1), reverse=True)
    print_count = 0
    max_print_count = 3
    for addr_tuple, count in sorted_calltrace_list:
        crashcolor.set_color(crashcolor.BLUE)
        print("%d times:" % (count))
        crashcolor.set_color(crashcolor.RESET)
        # Convert tuple back to function names for output
        for addr in addr_tuple:
            if addr != 0:  # Skip zero addresses
                sym_name = get_function_name(addr)
                if sym_name != None and not sym_name.startswith("sym: invalid address"):
                    parts = sym_name.split(maxsplit=2)
                    if len(parts) == 3:
                        try:
                            addr_str, type_str, rest = parts
                            addr_int = int(addr_str, 16)
                            print(f"  0x{addr_int:014x} {type_str:>3} {rest}")
                        except Exception as e:
                            print(e)
                    #print(sym_name)
        print()
        print_count = print_count + 1
        if not options.all and print_count >= max_print_count:
            if len(sorted_calltrace_list) > max_print_count:
                print("\n%15s %d %s" % (
                        "... < skiped ",
                        len(sorted_calltrace_list) - max_print_count,
                        " items > ..."))
            break


def check_slab_corruption(options):
    """
    Check SLAB/SLUB corruption by examining kmem_cache_cpu freelists.

    Usage: meminfo --corrupt <kmem_cache_addr|slab_name>[:<cpu_num>]

    Examples:
        meminfo --corrupt ffff93e400008e00
        meminfo --corrupt kmalloc-128
        meminfo --corrupt kmalloc-128:22

    If cpu_num is not specified, all CPUs are checked.
    """
    import re

    # Parse input: address/name and optional cpu number
    parts = options.corrupt.split(':')
    slab_input = parts[0]

    # Determine if input is a hex address or slab name
    kmem_cache_addr = None
    try:
        # Try to parse as hex address
        kmem_cache_addr = int(slab_input, 16)
    except ValueError:
        # Not a hex address, treat as slab name
        # Use kmem -s to look up the slab by name
        lines = exec_crash_command("kmem -s %s" % slab_input)
        if len(lines) == 0:
            print("Error: Slab '%s' not found" % slab_input)
            print("Usage: meminfo --corrupt <kmem_cache_addr|slab_name>[:<cpu_num>]")
            return

        # Parse the kmem -s output to get the address
        # The output may contain error lines like:
        #   CACHE             OBJSIZE  ALLOCATED     TOTAL  SLABS  SSIZE  NAME
        #   kmem: kmalloc-128: slab: ffffe5e81b157f00 invalid freepointer: e83de3b4c24007fc
        #   ffff93e400008e00      128      22403     50176    784     8k  kmalloc-128
        # We need to find the line that starts with a hex address (the actual data line)
        lines_split = lines.splitlines()
        kmem_cache_addr = None
        for line in lines_split:
            line = line.strip()
            if not line or line.startswith("CACHE") or line.startswith("kmem:"):
                continue
            # Try to parse the first word as a hex address
            words = line.split()
            if len(words) > 0:
                try:
                    kmem_cache_addr = int(words[0], 16)
                    break  # Found the data line
                except ValueError:
                    continue  # Not a hex address, skip this line

        if kmem_cache_addr is None:
            print("Error: Could not extract kmem_cache address for slab '%s'" % slab_input)
            return

    target_cpu = None
    if len(parts) > 1:
        try:
            target_cpu = int(parts[1])
        except ValueError:
            print("Error: Invalid CPU number: %s" % parts[1])
            return

    # Read kmem_cache structure
    try:
        kmem_cache = readSU("struct kmem_cache", kmem_cache_addr)
    except Exception as e:
        print("Error reading kmem_cache at 0x%x: %s" % (kmem_cache_addr, str(e)))
        return

    # Get cache name and cpu_slab offset
    try:
        cache_name = kmem_cache.name
        cpu_slab_offset = kmem_cache.cpu_slab
    except Exception as e:
        print("Error reading kmem_cache fields: %s" % str(e))
        return

    print("\nChecking SLAB corruption for cache: %s (0x%x)" % (cache_name, kmem_cache_addr))
    print("CPU slab offset: 0x%x" % cpu_slab_offset)
    print("=" * 80)

    # Get number of CPUs
    num_cpus = sys_info.CPUS

    # Check specified CPU or all CPUs
    cpus_to_check = [target_cpu] if target_cpu is not None else range(num_cpus)
    corruption_found = False

    for cpu_num in cpus_to_check:
        try:
            # Convert percpu offset to virtual address for this CPU
            percpu_offset = cpu_slab_offset
            cpu_slab_vaddr = percpu.percpu_ptr(percpu_offset, cpu_num)

            # Read kmem_cache_cpu structure
            try:
                kmem_cache_cpu = readSU("struct kmem_cache_cpu", cpu_slab_vaddr)
            except Exception as e:
                print("CPU %d: Error reading kmem_cache_cpu at 0x%x: %s" %
                      (cpu_num, cpu_slab_vaddr, str(e)))
                continue

            # Check freelist pointer
            freelist = kmem_cache_cpu.freelist
            tid = kmem_cache_cpu.tid
            # kernel 5.17+ renamed 'page' to 'slab' in struct kmem_cache_cpu
            try:
                page = kmem_cache_cpu.page
            except:
                try:
                    page = kmem_cache_cpu.slab
                except:
                    page = 0

            # Skip CPUs with no active slab - freelist is irrelevant (may be
            # an obfuscated NULL from SLAB freelist hardening or stale data)
            if page == 0:
                if target_cpu is not None or debug_mode:
                    print("CPU %d: No active slab (page=NULL), skipping" % cpu_num)
                continue

            # Validate freelist by testing actual memory readability
            # This works with KASLR, 5-level paging, and any address layout
            freelist_is_valid = False
            if freelist == 0:
                freelist_is_valid = True  # NULL is valid
            else:
                try:
                    # Try to read 8 bytes from freelist address
                    test_read = readULong(freelist)
                    freelist_is_valid = True
                except:
                    # Cannot read - this is corruption
                    freelist_is_valid = False

            if not freelist_is_valid:
                corruption_found = True
                crashcolor.set_color(crashcolor.RED)
                print("\n[CORRUPTION DETECTED] CPU %d:" % cpu_num)
                crashcolor.set_color(crashcolor.CYAN)
                print("crash> kmem_cache_cpu 0x%x" % cpu_slab_vaddr)
                print("struct kmem_cache_cpu {")
                print("  freelist = 0x%x, (INVALID - memory not accessible)" % freelist)
                print("  tid = 0x%x," % tid)
                print("  page = 0x%x," % page)
                print("  ...")
                print("}")
                crashcolor.set_color(crashcolor.RESET)
            else:
                # Only print if checking specific CPU or in verbose mode
                if target_cpu is not None or debug_mode:
                    crashcolor.set_color(crashcolor.GREEN)
                    print("CPU %d: OK" % cpu_num)
                    crashcolor.set_color(crashcolor.RESET)
                    if debug_mode:
                        print("  kmem_cache_cpu address: 0x%x" % cpu_slab_vaddr)
                        print("  freelist: 0x%x" % freelist)
                        print("  tid: 0x%x" % tid)
                        print("  page: 0x%x" % page)

        except Exception as e:
            print("CPU %d: Error during check: %s" % (cpu_num, str(e)))
            if debug_mode:
                import traceback
                traceback.print_exc()

    print("=" * 80)
    if corruption_found:
        crashcolor.set_color(crashcolor.RED)
        print("\n[RESULT] SLAB CORRUPTION DETECTED")
        crashcolor.set_color(crashcolor.RESET)
    else:
        crashcolor.set_color(crashcolor.GREEN)
        print("\n[RESULT] No corruption detected")
        crashcolor.set_color(crashcolor.RESET)
    print()


def show_slabdetail(options):
    N_ONLINE=1
    node_states = readSymbol("node_states")
    node_list = []
    for i in range(16):
        for b in range(64):
            if (node_states[N_ONLINE].bits[i] >> b) & 1:
                node_list.append(i *64 + b)


    lines = exec_crash_command("kmem -s %s" % options.slabdetail)
    if len(lines) == 0:
        return

    words = lines.splitlines()[1].split()
    kmem_cache = readSU("struct kmem_cache", int(words[0], 16))

    total_slabs = 0
    total_partial = 0
    for node in node_list:
        kmem_cache_node = kmem_cache.node[node]
        nr_slabs = kmem_cache_node.nr_slabs.counter
        nr_partial = kmem_cache_node.nr_partial
        print(nr_slabs, nr_partial)
        total_slabs = total_slabs + nr_slabs
        total_partial = total_partial + nr_partial

    print(total_slabs)
    print(total_partial)

    return



def show_objects_in_slab(options, kmem_cache, offset):
    global total_objects

    # Extracting the data in the way the kernel get for slabinfo
    try:
        nr_blks, numa_meminfo = get_numa_meminfo()
        nr_blks, node_numbers = get_node_numbers(nr_blks)

        '''
        if numa_meminfo == None and node_numbers == None:
            print("No NUMA information available")
            print(nr_blks)
            #return
        '''

        total_objects = 0
        for node in range(0, nr_blks):
            n = kmem_cache.node[node]
            if n == None:
                continue

            total_objects = total_objects + n.total_objects.counter

            show_slabs_in_node(options, kmem_cache, n, offset)

        return True
    except KeyboardInterrupt:
        return True
    except Exception as e:
        print(e)
        return False
    # end of it



def show_percpu(options):
    total_count = 0
    addr = int(options.percpu, 16)
    func = None
    if options.percpu_type == "u8":
        func = readU8
    elif options.percpu_type == "u16":
        func = readU16
    elif options.percpu_type == "u32":
        func = readU32
    elif options.percpu_type == "s32":
        func = readS32
    elif options.percpu_type == "u64":
        func = readU64
    elif options.percpu_type == "s64":
        func = readS64
    elif options.percpu_type == "int":
        func = readInt

    for i in range(sys_info.CPUS):
        percpu_addr = percpu.percpu_ptr(addr, i)
        print("CPU %d : 0x%x" % (i, percpu_addr))
        if options.percpu_type != "":
            if func:
                count = func(percpu_addr)
                print("\t= %d" % (count))
                total_count = total_count + count
            else:
                print("%s" % (readSU(options.percpu_type, percpu_addr)))
    if func:
        print("\tTotal = %d" % (total_count))

    print("\n\tnotes) You can use the below instead")
    print("\tcrash> ptov %s:a\n" % (options.percpu))



def show_vm_details(options, words):
    private_mem_pages = 0
    shared_mem_pages = 0

    result_str = exec_crash_command("vm -P %s" % (words[0]))
    if result_str == "":
        return
    result_lines = result_str.splitlines()
    total_lines = len(result_lines)
    if total_lines < 4:
        return
    for i in range(4, total_lines):
        page_words = result_lines[i].split()
        try:
            physical_addr = int(page_words[1], 16)
        except:
            physical_addr = 0

        if physical_addr != 0:
            vtop_result = exec_crash_command("vtop %s" % (page_words[0]))
            if vtop_result == "":
                continue
            vtop_list = vtop_result.splitlines()
            vtop_len = len(vtop_list)
            page_addr_str = vtop_list[vtop_len - 1].split()[0]
            try:
                page_addr = int(page_addr_str, 16)
            except:
                page_addr = 0

            if page_addr == 0:
                continue

            page_data = readSU("struct page", page_addr)
            if member_offset("struct page", "_refcount") >= 0:
                counter = page_data._refcount.counter 
            else:
                counter = page_data._count.counter

            if counter == 1:
                private_mem_pages = private_mem_pages + 1
            else:
                shared_mem_pages = shared_mem_pages + 1

    return [private_mem_pages, shared_mem_pages]


def show_all_vm(options):
    all_tasks = exec_crash_command("ps -G").splitlines()
    for task in all_tasks[1:]:
        words = task.split()
        pid = words[0]
        if words[0] == '>':
            pid = words[1]

        if pid == '0':
            continue
        show_vm(options, int(pid))
        print()


VM_READ         = 0x00000001   # currently active flags
VM_WRITE        = 0x00000002
VM_EXEC         = 0x00000004
VM_SHARED       = 0x00000008
VM_MAYREAD      = 0x00000010   # limits for mprotect() etc
VM_MAYWRITE     = 0x00000020
VM_MAYEXEC      = 0x00000040
VM_MAYSHARE     = 0x00000080
VM_GROWSDOWN    = 0x00000100   # general info on the segment
VM_GROWSUP      = 0x00000200
VM_NOHUGEPAGE   = 0x00000200   # MADV_NOHUGEPAGE marked this vma
VM_SHM          = 0x00000400   # shared memory area, don't swap out
VM_PFNMAP       = 0x00000400
VM_DENYWRITE    = 0x00000800   # ETXTBSY on write attempts..
VM_EXECUTABLE   = 0x00001000
VM_LOCKED       = 0x00002000
VM_IO           = 0x00004000   # Memory mapped I/O or similar
VM_SEQ_READ     = 0x00008000   # App will access data sequentially
VM_RAND_READ    = 0x00010000   # App will not benefit from clustered reads
VM_DONTCOPY     = 0x00020000   # Do not copy this vma on fork
VM_DONTEXPAND   = 0x00040000   # Cannot expand with mremap()
VM_RESERVED     = 0x00080000   # Don't unmap it from swap_out

VM_BIGPAGE      = 0x00100000   # bigpage mappings, no pte's
VM_BIGMAP       = 0x00200000   # user wants bigpage mapping

VM_WRITECOMBINED = 0x00100000   # Write-combined
VM_NONCACHED     = 0x00200000   # Noncached access
VM_HUGETLB       = 0x00400000   # Huge tlb Page*/
VM_ACCOUNT       = 0x00100000   # Memory is a vm accounted object

VM_NONLINEAR     = 0x00800000   # Is non-linear (remap_file_pages)

VM_MAPPED_COPY  = 0x01000000    # T if mapped copy of data (nommu mmap)
VM_HUGEPAGE     = 0x01000000    # MADV_HUGEPAGE marked this vma

VM_INSERTPAGE   = 0x02000000    # The vma has had "vm_insert_page()" done on it
VM_ALWAYSDUMP   = 0x04000000    # Always include in core dumps

VM_CAN_NONLINEAR = 0x08000000   # Has ->fault & does nonlinear pages
VM_MIXEDMAP     = 0x10000000    # Can contain "struct page" and pure PFN pages
VM_SAO          = 0x20000000    # Strong Access Ordering (powerpc)
VM_PFN_AT_MMAP  = 0x40000000    # PFNMAP vma that is fy mapped at mmap time
VM_MERGEABLE    = 0x80000000    # KSM may merge identical pages

vm_flags_dict = {
	0x00000001 : "VM_READ",
	0x00000002 : "VM_WRITE",
	0x00000004 : "VM_EXEC",
	0x00000008 : "VM_SHARED",
	0x00000010 : "VM_MAYREAD",
	0x00000020 : "VM_MAYWRITE",
	0x00000040 : "VM_MAYEXEC",
	0x00000080 : "VM_MAYSHARE",
	0x00000100 : "VM_GROWSDOWN",
	0x00000200 : "VM_GROWSUP",
	0x00000200 : "VM_NOHUGEPAGE",
	0x00000400 : "VM_SHM",
	0x00000400 : "VM_PFNMAP",
	0x00000800 : "VM_DENYWRITE",
	0x00001000 : "VM_EXECUTABLE",
	0x00002000 : "VM_LOCKED",
	0x00004000 : "VM_IO",
	0x00008000 : "VM_SEQ_READ",
	0x00010000 : "VM_RAND_READ",
	0x00020000 : "VM_DONTCOPY",
	0x00040000 : "VM_DONTEXPAND",
	0x00080000 : "VM_RESERVED",

	0x00100000 : "VM_BIGPAGE",
	0x00200000 : "VM_BIGMAP",

	0x00100000 : "VM_WRITECOMBINED",
	0x00200000 : "VM_NONCACHED",
	0x00400000 : "VM_HUGETLB",
	0x00100000 : "VM_ACCOUNT",

	0x00800000 : "VM_NONLINEAR",

	0x01000000 : "VM_MAPPED_COPY",
	0x01000000 : "VM_HUGEPAGE",

	0x02000000 : "VM_INSERTPAGE",
	0x04000000 : "VM_ALWAYSDUMP",

	0x08000000 : "VM_CAN_NONLINEAR",
	0x10000000 : "VM_MIXEDMAP",
	0x20000000 : "VM_SAO",
	0x40000000 : "VM_PFN_AT_MMAP",
	0x80000000 : "VM_MERGEABLE",
}

def show_flags_str(vm_flags):
    for val in vm_flags_dict:
        if val & vm_flags == val:
            print(" %s" % (vm_flags_dict[val]), end="")


def show_vm(options, pid):
    private_mem_pages = 0
    shared_mem_pages = 0

    if pid == -1:
        result_str = exec_crash_command("vm")
    else:
        result_str = exec_crash_command("vm %d" % (pid))

    result_lines = result_str.splitlines()
    total_lines = len(result_lines)
    if total_lines < 4: # For kernel tasks
        print(result_str)
        return

    # Extract process name and PID from the first line
    # Format: PID: 15539    TASK: ff235ea432eb0000  CPU: 3    COMMAND: "P37_00_DIA_W85"
    process_name = "unknown"
    actual_pid = pid
    if total_lines > 0:
        try:
            # The first line contains PID and COMMAND
            first_line = result_lines[0]
            # Parse the vm command output format
            # Example: PID: 15539    TASK: ff235ea432eb0000  CPU: 3    COMMAND: "P37_00_DIA_W85"
            if "PID:" in first_line and "COMMAND:" in first_line:
                # Extract PID
                if pid == -1:
                    pid_part = first_line.split("TASK:")[0]  # Get the part before TASK:
                    pid_str = pid_part.split("PID:")[1].strip()  # Get the number after PID:
                    actual_pid = int(pid_str)

                # Extract COMMAND (process name)
                cmd_part = first_line.split("COMMAND:")[1].strip()  # Get the part after COMMAND:
                # Remove quotes if present
                process_name = cmd_part.strip('"')
        except Exception as e:
            if debug_mode:
                print("Error parsing vm output: %s" % str(e))

    for i in range(0, 3):
        print(result_lines[i])
    print("%10s %s" % ("", result_lines[3]))

    # Dictionary to track memory by type
    mem_by_type = {}
    total_vm_size = 0

    for i in range(4, total_lines):
        words = result_lines[i].split()
        size = int(words[2], 16) - int(words[1], 16)
        total_vm_size += size

        size_str = get_size_str(size, True)

        # Categorize this VMA by type
        try:
            vma_addr = int(words[0], 16)
            vma = readSU("struct vm_area_struct", vma_addr)
            vm_flags = int(words[3], 16)

            # Determine the type of this VMA
            vma_type = None
            vma_name = ""

            # Get filename from vm output if available (words[4])
            filename = None
            if len(words) >= 5:
                filename = ' '.join(words[4:])  # Join in case filename has spaces

            # Check for HugePages
            if vm_flags & VM_HUGETLB:
                vma_type = "HugePages"
            # Check for SYSV shared memory first (by filename)
            elif filename and filename.startswith('SYSV'):
                vma_type = "Shared Memory (SYSV)"
                vma_name = filename
            # Check if it has a file mapping (do this before VM_SHM check)
            elif vma.vm_file != 0:
                try:
                    # If we don't have filename from vm output, get it from structure
                    if not filename:
                        vm_file = vma.vm_file
                        dentry = vm_file.f_path.dentry
                        filename = dentry.d_name.name.string_()

                    # Categorize by filename
                    if filename.endswith('.so') or '.so.' in filename:
                        vma_type = "Shared Objects (.so)"
                        vma_name = filename
                    elif filename.startswith('['):
                        # Special mappings like [heap], [stack], [vdso], etc.
                        vma_type = filename
                        vma_name = filename
                    else:
                        # Regular file mapping (executable, data files, etc.)
                        vma_type = "File Mapping"
                        vma_name = filename
                except Exception as e:
                    # Debug: print exception to understand what's failing
                    if debug_mode:
                        print(f"Exception getting filename: {e}")
                    vma_type = "File Mapping"
            # Check for shared memory flag (as fallback)
            elif vm_flags & VM_SHM:
                vma_type = "Shared Memory (SYSV)"
            else:
                # Anonymous mapping
                if vm_flags & VM_GROWSDOWN:
                    vma_type = "[stack]"
                else:
                    vma_type = "Anonymous"

            # Aggregate size by type
            if vma_type:
                if vma_type not in mem_by_type:
                    mem_by_type[vma_type] = 0
                mem_by_type[vma_type] += size
        except:
            # If we can't categorize, skip
            pass

        print("%10s %s" % (size_str, result_lines[i]), end="")
        if options.longer:
            show_flags_str(int(words[3], 16))

        if options.details:
            pages_list = show_vm_details(options, words)
            private_mem_pages = private_mem_pages + pages_list[0]
            shared_mem_pages = shared_mem_pages + pages_list[1]
            print(", P: %d, S: %d" % (pages_list[0], pages_list[1]), end="")
            vm_ops = readSU("struct vm_area_struct", int(words[0], 16)).vm_ops
            try:
                vm_ops_name = " (" + addr2sym(vm_ops) + ")"
            except:
                vm_ops_name = ""
            print(", %x%s" % (vm_ops, vm_ops_name), end="")
        print("")
        crashcolor.set_color(crashcolor.RESET)

    if options.details:
        print("\n\tPrivate memory pages = %d" % private_mem_pages)
        print("\n\tShared memory pages = %d" % shared_mem_pages)

    # Show graphical breakdown by memory type
    if len(mem_by_type) > 0:
        print("\n")
        crashcolor.set_color(crashcolor.BLUE)
        print("=" * 80)
        if actual_pid != -1:
            print("MEMORY BREAKDOWN BY TYPE FOR \"%s\" (%d)" % (process_name, actual_pid))
        else:
            print("MEMORY BREAKDOWN BY TYPE")
        print("=" * 80)
        crashcolor.set_color(crashcolor.RESET)

        # Sort by size (descending)
        sorted_types = sorted(mem_by_type.items(), key=lambda x: x[1], reverse=True)

        # Display header
        print("\nTotal Virtual Memory: %s\n" % get_size_str(total_vm_size))
        print("%-25s %10s %7s  %s" % ("Type", "Size", "Percent", "Usage Bar"))
        print("-" * 80)

        # Display each type with bar graph
        for mem_type, size in sorted_types:
            percentage = (size * 100.0 / total_vm_size) if total_vm_size > 0 else 0
            bar = get_memory_bar(percentage, width=25)

            print("%-25s %10s %6.2f%%  %s" %
                  (mem_type[:25], get_size_str(size), percentage, bar))

        print("=" * 80)



error_str = [
    ["no page found", "protection fault"],
    ["read access", "write access"],
    ["kernel-mode", "user-mode"],
    ["", "use of reserved bit detected"],
    ["", "fault was an instruction fetch"],
    ["", "protection keys block access"],
]

def show_error_code(options):
    error_val = int(options.error_code, 16)
    for i in range(0, len(error_str)):
        idx = 0
        if ((1 << i) & error_val) != 0:
            idx = 1
        if error_str[i][idx] != "":
            print("[%d,%d] : %s" % (i, idx, error_str[i][idx]))


def show_tlb_csd_list(options):
    csd_addr =int(options.tlb_list, 16)
    for csd in readSUListFromHead(csd_addr,
                                         "llist",
                                         "struct __call_single_data",
                                         maxel=1000000):
        func_str = addr2sym(csd.func)
        print("0x%x: func = 0x%x (%s), info = 0x%x, flags = 0x%x" %
              (csd, csd.func, func_str, csd.info, csd.flags))
        if options.details:
            if func_str == "flush_tlb_func_remote":
                f = readSU("struct flush_tlb_info", csd.info)
                print("\tmm : 0x%x (owner = %d, %s), range = 0x%x - 0x%x" %
                      (f.mm, f.mm.owner.pid, f.mm.owner.comm, f.start, f.end))


SLAB_STORE_USER=0x10000
SLAB_RED_ZONE=0x00000400

# Use defaultdict for better performance and memory efficiency
alloc_func_list = defaultdict(int)
alloc_pid_list = defaultdict(int)
alloc_count = 0
total_objects = 0

free_func_list = defaultdict(int)
free_pid_list = defaultdict(int)
free_count = 0

calltrace_list = defaultdict(int)

def read_a_track(options, kmem_cache, obj_addr, offset, alloc_item=True):
    global alloc_func_list
    global alloc_pid_list
    global alloc_count

    global free_func_list
    global free_pid_list
    global free_count

    global calltrace_list
    global total_objects


    if options.progress:
        percent = (alloc_count / total_objects) * 100
        print(f"Checked {alloc_count:,} objects out of {total_objects:,}. {percent:.2f}%", end='\r')
        if alloc_count > 0 and (alloc_count % options.pager) == 0:
            print()
            show_slab_alloc_result(options, kmem_cache)

    track_addr = obj_addr + offset
    track = readSU("struct track", track_addr)

    # Efficient updates using defaultdict
    if alloc_item:
        alloc_count = alloc_count + 1
        alloc_func_list[track.addr] += 1
    else:
        free_count = free_count + 1
        free_func_list[track.addr] += 1


    if options.details:
        # Use tuples for memory efficiency and direct assignment
        pid_key = (track.addr, track.pid)
        if alloc_item:
            alloc_pid_list[pid_key] += 1
        else:
            free_pid_list[pid_key] += 1

        if member_offset("struct track", "addrs") >= 0:
            # Memory optimization: use tuple of addresses instead of string
            # Apply memory limit to prevent excessive memory usage
            addr_tuple = tuple(track.addrs)
        elif member_offset("struct track", "handle") >= 0:
            nr_entries, trace_entries = get_stack_entries(track.handle)
            addr_tuple = tuple(trace_entries)
        else:
            addr_tuple = None

        if addr_tuple != None:
            if options.memory_limit == 0 or len(calltrace_list) < options.memory_limit:
                # No limit or under limit - store all patterns
                calltrace_list[addr_tuple] += 1
            elif addr_tuple in calltrace_list:
                # When limit reached, only update existing entries
                calltrace_list[addr_tuple] += 1


        if options.all:
            if alloc_item:
                print("OBJ at [0x%x]" % (obj_addr))
            else:
                print("OBJ at  0x%x" % (obj_addr))
            print("< struct track 0x%x >" % (track_addr))
            print(exec_crash_command("rd 0x%x -S 16" % track_addr))


def print_slab_layout(kmem_cache, offset):
    red_str = crashcolor.get_color(crashcolor.LIGHTRED)
    green_str = crashcolor.get_color(crashcolor.GREEN)
    blue_str = crashcolor.get_color(crashcolor.BLUE)
    reset_str = crashcolor.get_color(crashcolor.RESET)
    g_line = "%6s" % "+"
    t_line = "%6s" % "|"
    d_line = "%6s" % "|"
    if (kmem_cache.flags & SLAB_RED_ZONE) == SLAB_RED_ZONE:
        t_line = t_line + red_str + ("%6s" % "RED") + reset_str + "|"
        g_line = g_line + "-" * 6 + "+"
        d_line = d_line + red_str + ("%6d" % kmem_cache.red_left_pad) + reset_str + "|"

    t_line = t_line + green_str + ("%8s" % "OBJ Size") + reset_str + "|"
    g_line = g_line + "-" * 8 + "+"
    d_line = d_line + green_str + ("%8d" % kmem_cache.object_size) + reset_str + "|"

    if (kmem_cache.flags & SLAB_RED_ZONE) == SLAB_RED_ZONE:
        t_line = t_line + red_str + ("%6s" % "RED") + reset_str + "|"
        g_line = g_line + "-" * 6 + "+"
        d_line = d_line + red_str + ("%6d" % (kmem_cache.inuse - kmem_cache.object_size)) + reset_str + "|"

    track_at = readSU("struct track", 0)
    if ((kmem_cache.flags & SLAB_STORE_USER) == SLAB_STORE_USER):
        track_len = len(track_at)
        t_line = t_line + blue_str + ("%16s" % "Track size(at)") + reset_str + "|"
        g_line = g_line + "-" * 16 + "+"
        d_line = d_line + blue_str + ("%16s" % ("%d(%d)=%d" % (track_len, offset, track_len*2))) + reset_str + "|"

    print("%4s" % "", end="")
    print(kmem_cache)
    print("%6s%s" % ("", "SLAB Layout for " + blue_str +
                       kmem_cache.name + reset_str))
    print(g_line)
    print(t_line)
    print(g_line)
    print(d_line)
    print(g_line)
    print("")


def show_alloc_track(options, kmem_cache, addr, slab_addr, offset):
    page = readSU("struct page", slab_addr)
    total_slab = page.objects & 0xff # Make sure it only uses a byte
    alloc_item = True

    if options.debug:
        print("show_alloc_track")
    for idx in range(0, total_slab):
        obj_addr = addr + kmem_cache.size * idx
        read_a_track(options, kmem_cache, obj_addr, offset, alloc_item)

    if options.debug:
        print("show_alloc_track done")


def show_partial_alloc_track(options, kmem_cache, slab_addr, offset):
    lines = exec_crash_command("kmem -S 0x%x" % (slab_addr)).splitlines()
    is_head = True

    for line in lines:
        line = line.strip()
        if line.startswith("FREE"):
            is_head = False
            continue

        if is_head:
            continue

        if not line.startswith("["):
            if not options.all:
                continue
            alloc_item = False
        else:
            alloc_item = True
            line = line[1:-1]

        obj_addr = int(line, 16)
        read_a_track(options, kmem_cache, obj_addr, offset, alloc_item)


'''
 SLUB Debug Memory Optimizations:
 
 The show_slub_debug_user function has been optimized for large datasets:
 
 Performance Improvements:
 - Tuple-based call trace storage (60-80% memory reduction)
 - defaultdict for efficient data structures
 - Batch processing with progress reporting
 - Periodic garbage collection
 - Early termination with --maxcount
 
 Memory Management Options:
 - --memory_limit N : Limit call trace patterns to N unique entries (default: 10000)
 - --memory_limit 0 : No limit (use for complete analysis of smaller datasets)
 - --maxcount N     : Stop processing after N objects
 
 Usage Examples:
   meminfo -U kmalloc-64 -d                    # Standard analysis
   meminfo -U kmalloc-64 -d --memory_limit 5000  # Limit call traces for memory
   meminfo -U kmalloc-64 -d --maxcount 50000    # Process only first 50K objects
   meminfo -U kmalloc-64 -d --memory_limit 0    # No memory limits (complete data, default)
'''
def show_slub_debug_user_all(options):
    lines = exec_crash_command("kmem -s").splitlines()
    if len(lines) < 2:
        return
    for line in lines:
        words = line.split()
        if len(words) < 7:
            continue
        if words[0] == "CACHE":
            continue

        options.user_alloc = words[6]
        show_slub_debug_user(options)
        print("-=" * 20)
        print("")


BIG_OBJ_COUNT = 100000

def show_slub_debug_user(options):
    global alloc_func_list
    global alloc_count
    global calltrace_list
    global alloc_pid_list
    global free_func_list
    global free_pid_list
    global free_count
    global total_objects


    # Clear previous data to prevent accumulation
    alloc_func_list.clear()
    alloc_pid_list.clear()
    free_func_list.clear()
    free_pid_list.clear()
    calltrace_list.clear()
    alloc_count = 0
    free_count = 0

    lines = exec_crash_command("kmem -s %s" % options.user_alloc)
    if len(lines) == 0:
        return
    words = lines.splitlines()[1].split()
    kmem_cache = readSU("struct kmem_cache", int(words[0], 16))
    total_objects = int(words[2])

    if kmem_cache.offset >= kmem_cache.object_size:
        offset = kmem_cache.offset + getSizeOf("long")
    else:
        offset = kmem_cache.inuse

    if (kmem_cache.flags & SLAB_RED_ZONE) == SLAB_RED_ZONE:
        offset = offset + kmem_cache.red_left_pad
        offset = offset + (kmem_cache.inuse - kmem_cache.object_size)

    if total_objects > BIG_OBJ_COUNT and options.progress == False:
        response = ""
        try:
            response = input(f"⚠️ There is {total_objects:,} allocated objects.\nShow progress every how many objects? (0 : no shows): ")
            if response == "":
                response = "0"
            pager = int(response)
            print()
            if pager > 0:
                options.progress = True
                options.pager = pager
        except:
            if response == None or response.strip() == "":
                return
            print(f"Invalid number '{response}'")
            return

    print_slab_layout(kmem_cache, offset)

    if ((kmem_cache.flags & SLAB_STORE_USER) != SLAB_STORE_USER):
        print("Please use 'slub_deubg=U' to collect alloc tracking")
        return

    get_stack_bits()

    if show_objects_in_slab(options, kmem_cache, offset):
        return

    lines = exec_crash_command("kmem -S %s" % options.user_alloc).splitlines()
    full_mode = False
    partial_mode = False
    
    # Count total slabs for progress reporting
    total_slabs = 0
    slab_lines = []
    for line in lines:
        line = line.strip()
        words = line.split()
        if len(words) >= 5 and words[0] != "SLAB" and not line.startswith("NODE") and not line.startswith("KMEM_CACHE_NODE"):
            if words[0].startswith("0x"):  # It's a slab line
                slab_lines.append(line)
                total_slabs += 1

    print("Processing %d slabs for %s..." % (total_slabs, options.user_alloc))
    
    # Process slabs with progress reporting
    processed_slabs = 0
    last_progress = 0
    #batch_size = max(1, total_slabs // 20)  # Report progress every 5%
    batch_size = options.pager
    
    alloc_count = 0

    for line in lines:
        line = line.strip()
        if line.startswith("NODE") or line.startswith("KMEM_CACHE_NODE"):
            full_mode = False
            partial_mode = False

            if not line.endswith("FULL:") and not line.endswith("PARTIAL:"):
                continue

        if line.endswith("FULL:"):
            full_mode = True

        if line.endswith("PARTIAL:"):
            partial_mode = True

        if full_mode != True and partial_mode != True:
            continue

        words = line.split()
        if len(words) < 5 or words[0] == "SLAB":
            continue

        try:
            if full_mode:
                show_alloc_track(options, kmem_cache, int(words[1], 16),
                        int(words[0], 16), offset)
            elif partial_mode:
                show_partial_alloc_track(options, kmem_cache,
                        int(words[0], 16), offset)
                        
            processed_slabs += 1
            
            # Progress reporting for large datasets
            if total_slabs > 100 and processed_slabs % batch_size == 0:
                progress = (processed_slabs * 100) // total_slabs
                if progress > last_progress:
                    print("Progress: %d%% (%d/%d slabs, %d objects processed)" % 
                          (progress, processed_slabs, total_slabs, alloc_count + free_count))
                    last_progress = progress
                    
                    # Periodic garbage collection for memory management
                    if processed_slabs % (batch_size * 4) == 0:
                        gc.collect()
                        
        except Exception as e:
            print("Error processing slab: %s" % e)
            break

        if options.maxcount > 0 and alloc_count > options.maxcount:
            print("Reached maxcount limit of %d objects" % options.maxcount)
            break



    if alloc_count > 0:
        show_slab_alloc_result(options, kmem_cache)

    '''
    print("\nOptimization Summary:")
    print("===================")
    print("- Used tuple-based call trace storage (reduced memory by ~60-80%%)")
    print("- Used defaultdict for efficient data structures")
    print("- Unique call trace patterns stored: %d" % len(calltrace_list))
    print("- Unique allocation functions: %d" % len(alloc_func_list))
    if options.details:
        print("- Unique (function, PID) pairs: %d" % len(alloc_pid_list))
    if options.memory_limit > 0 and len(calltrace_list) >= options.memory_limit:
        print("- Memory limit applied: call traces limited to %d patterns" % options.memory_limit)
        print("  (Use --memory_limit 0 to disable, or increase limit for more patterns)")
    elif options.memory_limit > 0:
        print("- Memory limit set to %d (not reached)" % options.memory_limit)
    '''

function_name_dict = {}

def get_function_name(addr):
    global function_name_dict

    if addr == 0:
        return None
    if addr in function_name_dict:
        return function_name_dict[addr]
    sym_name = exec_crash_command("sym 0x%x" % (addr))
    words = sym_name.split()
    if len(words) == 5:
        sym_name = sym_name[:sym_name.find(words[3])]
    if sym_name.find(" /") > 0:
        sym_name = sym_name[:sym_name.find(" /")] # Don't require source code info

    sym_name = sym_name.strip()
    function_name_dict[addr] = sym_name
    return sym_name


def show_alloc_pid_list(options):
    global alloc_pid_list

    sorted_alloc_pid_list = sorted(alloc_pid_list.items(),
                          key=operator.itemgetter(1), reverse=True)
    print_count = 0
    if alloc_count > 0:
        print("\nNotes: Below shows per-pid allocation counts")
        print("%11s : %10s %s" % ("ALLOC_COUNT", "PID", "FUNCTION"))
    for (func_addr, pid), count in sorted_alloc_pid_list:
        print("%11d : %10d %s" % (count, pid, get_function_name(func_addr)))
        print_count = print_count + 1
        if not options.all and print_count > 9:
            if len(sorted_alloc_pid_list) > 10:
                print("\n%15s %d %s" % (
                        "... < skiped ",
                        len(sorted_alloc_pid_list) - 10,
                        " items > ..."))
            break


def show_pte_flags(options):
    _PAGE_BIT_PRESENT   =0
    _PAGE_BIT_RW        =1
    _PAGE_BIT_USER      =2
    _PAGE_BIT_PWT       =3
    _PAGE_BIT_PCD       =4
    _PAGE_BIT_ACCESSED  =5
    _PAGE_BIT_DIRTY     =6
    _PAGE_BIT_PSE       =7
    _PAGE_BIT_PAT       =7
    _PAGE_BIT_GLOBAL    =8
    _PAGE_BIT_UNUSED1   =9
    _PAGE_BIT_IOMAP     =10
    _PAGE_BIT_HIDDEN    =11
    _PAGE_BIT_PAT_LARGE =12
    _PAGE_BIT_SPECIAL   =_PAGE_BIT_UNUSED1
    _PAGE_BIT_CPA_TEST  =_PAGE_BIT_UNUSED1
    _PAGE_BIT_SPLITTING =_PAGE_BIT_UNUSED1
    _PAGE_BIT_SOFTDIRTY =_PAGE_BIT_HIDDEN
    _PAGE_BIT_NX        =   63

    pte_flags_dict = {
        (1 << _PAGE_BIT_PRESENT) : "_PAGE_PRESENT",
        (1 << _PAGE_BIT_RW) : "_PAGE_RW",
        (1 << _PAGE_BIT_USER) : "_PAGE_USER",
        (1 << _PAGE_BIT_PWT) : "_PAGE_PWT",
        (1 << _PAGE_BIT_PCD) : "_PAGE_PCD",
        (1 << _PAGE_BIT_ACCESSED) : "_PAGE_ACCESSED",
        (1 << _PAGE_BIT_DIRTY) : "_PAGE_DIRTY",
        (1 << _PAGE_BIT_PSE) : "_PAGE_PSE",
        (1 << _PAGE_BIT_GLOBAL) : "_PAGE_GLOBAL",
        (1 << _PAGE_BIT_UNUSED1) : "_PAGE_UNUSED1",
        (1 << _PAGE_BIT_IOMAP) : "_PAGE_IOMAP",
        (1 << _PAGE_BIT_PAT) : "_PAGE_PAT",
        (1 << _PAGE_BIT_PAT_LARGE) : "_PAGE_PAT_LARGE",
        (1 << _PAGE_BIT_SPECIAL) : "_PAGE_SPECIAL",
        (1 << _PAGE_BIT_CPA_TEST) : "_PAGE_CPA_TEST",
        (1 << _PAGE_BIT_SPLITTING) : "_PAGE_SPLITTING",
        (1 << _PAGE_BIT_SOFTDIRTY) : "_PAGE_SOFTDIRTY",
    }

    pte_flags = int(options.pte_flags, 16)

    for val in pte_flags_dict:
        if val & pte_flags == val:
            print("%20s : 0x%x" % (pte_flags_dict[val], val))


MM_SWAPENTS = 2

def get_swap_usage(options, task):
    if options.swap_full_show:
        swap_usage = get_swap_from_vma(options, task)
    else:
        swap_usage = get_swap_from_mm(options, task)

    return swap_usage


def hstate_vma(vma):
    inode = vma.vm_file.f_inode
    hstate = inode.i_sb.s_fs_info.hstate
    return hstate


def huge_page_shift(h):
    return h.order + page_shift


def huge_page_order(h):
    return h.order


def vma_hugecache_offset(h, vma, address):
    return ((address - vma.vm_start) >> huge_page_shift(h)) + \
                (vma.vm_pgoff >> huge_page_order(h))


def linear_hugepage_index(vma, address):
    return vma_hugecache_offset(hstate(vma(vma), vma, address))


def linear_page_index(vma, address):
    if (vma.vm_flags & VM_HUGETLB) != 0:
        return linear_hugepage_index(vma, address)

    pgoff = (address - vma.vm_start) / page_size
    pgoff = pgoff + vma.vm_pgoff
    return pgoff


swap_entry_dict = {}
swap_task_dict = {}

def get_shmem_partial_swap_usage(mapping, start, end, task):
    global swap_entry_dict
    global swap_task_dict

    swapped = 0
    if member_offset("struct address_space", "i_pages") >= 0:
        SWAP_ENTRY_MASK = 0x1
        xa_head = mapping.i_pages.xa_head
        if xa_head == 0x0:
            return 0

        pages_list = exec_crash_command("tree -t xarray -N 0x%x" % \
                                        (xa_head)).splitlines()
    elif member_offset("struct address_space", "page_tree") >= 0:
        SWAP_ENTRY_MASK = 0x2
        pages_list = exec_crash_command(
                        "tree -t radix -r address_space.page_tree 0x%x" % \
                        (mapping)).splitlines()
    else:
        print("shmem_partial_swap_usage() is not available in this kernel")
        return 0

    for page_str in pages_list:
        page_addr = int(page_str, 16)
        if (page_addr & SWAP_ENTRY_MASK) == SWAP_ENTRY_MASK:
            swapped = swapped + 1
            task_list = []
            swap_entry_count = 0
            if (page_addr in swap_entry_dict):
                swap_entry_count = swap_entry_dict[page_addr]
                task_list = swap_task_dict[page_addr]

            if (task not in task_list):
                task_list.append(task)
            swap_entry_dict[page_addr] = swap_entry_count + 1
            swap_task_dict[page_addr] = task_list

    return swapped * page_size


shm_swap_task_dict = {}

def get_shmem_swap_usage(vma, task):
    global shm_swap_task_dict

    inode = vma.vm_file.f_inode
    shmi_offset = member_offset("struct shmem_inode_info", "vfs_inode")
    info = readSU("struct shmem_inode_info", inode - shmi_offset)
    mapping = inode.i_mapping

    swapped = info.swapped
    if swapped == 0:
        return 0

    if vma.vm_pgoff == 0 and (vma.vm_end - vma.vm_start >= inode.i_size):
        # shmem task list to divide it later
        task_list = []
        if (info in shm_swap_task_dict):
            task_list = shm_swap_task_dict[info]
        task_list.append(task)
        shm_swap_task_dict[info] = task_list

        return swapped << page_shift

    return get_shmem_partial_swap_usage(mapping,
                                        linear_page_index(vma, vma.vm_start),
                                        linear_page_index(vma, vma.vm_end),
                                        task)


def get_swap_from_vma(options, task):
    if task.mm == 0 or task.mm.mmap == 0:
        return 0

    shmem_aops = readSymbol("shmem_aops")
    swap_usage = 0
    vma = task.mm.mmap
    while vma != 0:
        if vma.vm_file != 0 and vma.vm_file.f_mapping.a_ops == shmem_aops:
            shmem_swapped = get_shmem_swap_usage(vma, task)
            if (not shmem_swapped or (vma.vm_flags & VM_SHARED) or
                not (vma.vm_flags & VM_WRITE)):
                swap_usage = swap_usage + shmem_swapped
            else:
                pass

        vma = vma.vm_next

    return swap_usage


def get_swap_from_mm(options, task):
    mm = task.mm
    if mm == 0 or mm == None:
        return 0
    if member_offset("struct mm_struct", "rss_stat") < 0:
        return 0 # Not available. May need to find another way.

    swap_usage = 0
    try:
        swap_usage = mm.rss_stat.count[MM_SWAPENTS].counter
        if swap_usage < 0:
            swap_usage = mm.rss_stat.count[1].counter
    except:
        swap_usage = mm.rss_stat[MM_SWAPENTS].count
        if swap_usage < 0:
            swap_usage = mm.rss_stat[1].count

    return swap_usage * page_size


def show_swap_usage(options):
    global swap_entry_dict
    global shm_swap_task_dict

    swap_entry_dict = {}
    # check_global_symbols()
    all_tasks = exec_crash_command("ps -G").splitlines()
    swap_usage_dict = {}
    for task in all_tasks[1:]:
        words = task.split()
        pid = words[0]
        task_addr = words[3]
        if words[0] == '>':
            pid = words[1]
            task_addr = words[4]

        if pid == '0':
            continue

        task_struct = readSU("struct task_struct", int(task_addr, 16))

        swap_usage = get_swap_usage(options, task_struct)
        if swap_usage > 0:
            swap_usage_dict[task_struct] = swap_usage


    shmem_swaplist = readSymbol("shmem_swaplist")
    task_struct = readSymbol("init_task")
    task_struct.comm = "<SHMEM>"
    for info in readSUListFromHead(shmem_swaplist, "swaplist",
                                   "struct shmem_inode_info",
                                   maxel=1000000):
        swap_usage = info.swapped * page_size
        if (task_struct in swap_usage_dict):
            swap_usage = swap_usage_dict[task_struct] + swap_usage
        swap_usage_dict[task_struct] = swap_usage


    if len(swap_usage_dict) == 0:
        print("No processes are using swap")
        return

    # divide swapped page by number of processes shared
    sorted_swap_entry_list = sorted(swap_entry_dict.items(),
                                    key=operator.itemgetter(0), reverse=False)
    sorted_swap_entry_dict = {}
    for key, value in sorted_swap_entry_list:
        sorted_swap_entry_dict[key] = value

    for swap_entry in sorted_swap_entry_dict:
        task_list = swap_task_dict[swap_entry]
        shared_count = len(task_list)
        bytes_per_task = page_size / shared_count
        remove_bytes_from_task = page_size - bytes_per_task

        if options.details:
            print("swap_entry = 0x%x : tasks(count=%d) = " % \
                  (swap_entry, len(task_list)), end="")

        task_print = False

        for task in task_list:
            if options.details:
                if task_print == False:
                    print("%d " % (task.pid))
                    task_print = True
            if (task in swap_usage_dict):
                swap_usage_dict[task] = swap_usage_dict[task] - remove_bytes_from_task
            else:
                print("Missing task 0x%x for entry 0x%x" % (
                    task, swap_entry))

    if options.details:
        print()


    # divide shm swapped memory by number of processes shared
    for shminfo in shm_swap_task_dict:
        task_list = shm_swap_task_dict[shminfo]
        shared_count = len(task_list)
        swapped_size = shminfo.swapped << page_shift
        bytes_per_task = swapped_size / shared_count
        remove_bytes_from_task = swapped_size - bytes_per_task

        if options.details:
            print(shminfo)
            print("swapped %d bytes which was shared by %d tasks" % \
                  (swapped_size, shared_count))
            print("bytes_per_task = %d, remove_bytes_from_task = %d" % \
                  (bytes_per_task, remove_bytes_from_task))

        for task in task_list:
            if (task in swap_usage_dict):
                swap_usage_dict[task] = swap_usage_dict[task] - remove_bytes_from_task
            else:
                print("Missing task 0x%x for shminfo 0x%x" % (
                    task, shminfo))

    if options.details:
        print()


    sorted_usage = sorted(swap_usage_dict.items(),
                          key=operator.itemgetter(1), reverse=True)

    count = 0
    print("%s" % ("=" * 46))
    print("%20s  %7s    %13s" % ("COMM", "PID", "Swap usage"))
    print("%s" % ("-" * 46))
    total_usage = 0
    for task, usage_bytes in sorted_usage:
        total_usage = total_usage + usage_bytes
        if (count > 10 and not options.all):
            continue
        print("%20s (%7d) : %13s" % (task.comm,
                                     task.pid,
                                     get_size_str(usage_bytes)))
#        print("%20s (%7d) : %10s KB" % (task.comm, task.pid, f'{usage_kb:,}'))
        count = count + 1

    if count < len(sorted_usage) - 1:
        print("\t\t<...>")
    print("%s" % ("=" * 46))
    print("Total usage : %32s" % (get_size_str(total_usage)))
#    print("Total usage : %29s KB" % (f'{total_usage:,}'))
    print("\nNotes. this value can be a bit different from the actual swapfile content.")



def pfn_to_section_nr(pfn):
    try:
        pageshift = int(get_machine_symbol("pageshift"))
        section_size_bits = int(get_machine_symbol("section_size_bits"))
        pfn_section_shift = (section_size_bits - pageshift)
        pfn_to_section_nr = pfn >> pfn_section_shift

        return pfn_to_section_nr
    except Exception as e:
        print(e)
        return 0


def section_nr_to_pfn(section_nr):
    """Convert section number to base PFN of that section"""
    try:
        pageshift = int(get_machine_symbol("pageshift"))
        section_size_bits = int(get_machine_symbol("section_size_bits"))
        pfn_section_shift = (section_size_bits - pageshift)
        return section_nr << pfn_section_shift
    except Exception as e:
        return 0


def section_nr_to_root(sec):
    try:
        return int((sec / int(get_machine_symbol("sections_per_root"))))
    except Exception as e:
        print(e)
        return 0


def get_pages_per_section():
    """Get the number of pages in a section"""
    global _pages_per_section

    # Return cached value if available
    if _pages_per_section is not None:
        return _pages_per_section

    try:
        pageshift = int(get_machine_symbol("pageshift"))
        section_size_bits = int(get_machine_symbol("section_size_bits"))
        pfn_section_shift = (section_size_bits - pageshift)
        _pages_per_section = 1 << pfn_section_shift
        return _pages_per_section
    except Exception as e:
        _pages_per_section = 0
        return 0


def section_is_present(mem_section):
    """Check if a section has valid memory"""
    # Simple check - just verify the section object itself is valid
    # Don't try to access its fields as that might hang on invalid sections
    # Let the readSU calls handle detailed validation
    if mem_section is None or mem_section == 0 or mem_section == -1:
        return False
    return True


def __nr_to_section(nr):
    global mem_sections
    global sections_per_root
    global addr_size
    global section_root_mask

    try:
        root = section_nr_to_root(nr)
        if len(mem_sections) <= root:
            return None

        mem_section_addr = mem_sections[root]
        mem_section_array = readSUArray("struct mem_section", mem_section_addr, sections_per_root)
        mem_section = mem_section_array[nr & section_root_mask]
        return mem_section
    except Exception as e:
        return -1


def valid_section(mem_section):
    return mem_section


def valid_section_nr(nr):
    section = __nr_to_section(nr)
    if section == -1:
        return -1
    return valid_section(section)


# page_ext.flags
PAGE_EXT_DEBUG_POISON = 0
PAGE_EXT_DEBUG_GUARD = 1
PAGE_EXT_OWNER = 2
PAGE_EXT_YOUNG = 3
PAGE_EXT_IDLE = 4
PAGE_EXT_OWNER_ALLOCATED = -1


def __pfn_to_section(pfn):
    nr = pfn_to_section_nr(pfn)
    mem_section = __nr_to_section(nr)
    return mem_section


def test_bit(bit_index, flags):
    return (flags >> bit_index) & 1


def page_owner_is_valid(page_owner):
    """Validate that page_owner structure contains reasonable data"""
    global _has_page_owner_pid

    try:
        # Check if page_owner is None or invalid
        if page_owner is None or page_owner == 0 or page_owner == -1:
            return False

        # We MUST be able to read the order field - if we can't, it's invalid
        try:
            order = page_owner.order
            # Check order - should be reasonable (typically < 11, max 20)
            # Only reject clearly invalid values
            if order < 0 or order > 30:
                return False
        except:
            # If we can't read order field, the object is definitely invalid
            return False

        # Cache the member_offset check (only check once)
        if _has_page_owner_pid is None:
            _has_page_owner_pid = member_offset("struct page_owner", "pid") > -1

        # Check pid/tgid if they exist (RHEL8+)
        # Only filter out clearly garbage values like -1869574000
        if _has_page_owner_pid:
            try:
                # Only reject extremely negative or extremely large values
                # Normal range: -1 to 4194304, but be permissive
                # Reject values that are clearly garbage (outside 32-bit int range)
                if page_owner.pid < -1000000 or page_owner.pid > 100000000:
                    return False

                if page_owner.tgid < -1000000 or page_owner.tgid > 100000000:
                    return False

                # Check timestamps - only reject ridiculously large values
                # Allow 0 (not set) and any reasonable timestamp
                if hasattr(page_owner, 'ts_nsec') and page_owner.ts_nsec > 10**19:
                    return False
                if hasattr(page_owner, 'free_ts_nsec') and page_owner.free_ts_nsec > 10**19:
                    return False
            except:
                # If we can't read pid/tgid fields, the object might be invalid
                # Be conservative and reject it
                return False

        return True
    except:
        # If any unexpected error occurs, assume invalid
        return False


def pfn_to_page_owner(pfn):
    global mem_sections
    global page_owner_offset
    global page_ext_size
    global PAGE_EXT_OWNER
    global PAGE_EXT_OWNER_ALLOCATED

    '''
    # Check 'kmem -n' that shows section to pfn
    # crash> help -v | grep max_mem
    # max_mem_section_nr: 271
    '''

    try:
        mem_section = __pfn_to_section(pfn)
        if mem_section == 0:
            return None

        if mem_section == -1:
            return -1

        # Validate that the section has valid memory
        if not section_is_present(mem_section):
            return None

        page_ext = 0
        if member_offset("struct mem_section", "page_cgroup") > -1:
            if mem_section.page_cgroup != 0:
                page_cgroup = mem_section.page_cgroup + pfn
                page_ext = page_cgroup.ext
        else:
            if mem_section.page_ext > 0:
                # Use absolute PFN (as in crash-pageowner reference implementation)
                # This is correct for how the kernel organizes page_ext arrays
                try:
                    page_ext = readSU("struct page_ext",
                                Addr(mem_section.page_ext) + (page_ext_size * pfn))
                except:
                    # Failed to read page_ext - PFN might be in a memory hole
                    return None

        if page_ext == 0 or page_ext == None:
            return None

        # Check PAGE_EXT_OWNER flag - this indicates page_owner is being tracked
        # (As per crash-pageowner reference implementation)
        try:
            if not test_bit(PAGE_EXT_OWNER, page_ext.flags):
                return None
        except:
            # If we can't read flags, skip this page
            return None

        # If it's RHEL8 or above and page_ext is for free, we don't care
        if PAGE_EXT_OWNER_ALLOCATED >= 0:
            try:
                if not test_bit(PAGE_EXT_OWNER_ALLOCATED, page_ext.flags):
                    return None
            except:
                # If we can't read flags, skip this page
                return None

        if member_offset("struct page_ext", "owner") > -1:
            page_owner = page_ext.owner
        else:
            try:
                page_owner = readSU("struct page_owner",
                                Addr(page_ext) + page_owner_offset)
            except:
                # Failed to read page_owner
                return None

        # Validate that the page_owner data looks reasonable
        # Temporarily disabled to debug - checking if this is filtering too much
        # if not page_owner_is_valid(page_owner):
        #     return None

        return page_owner
    except Exception as e:
        # Suppress error messages for expected failures (memory holes, etc.)
        return None


page_owner_dict = {}
alloc_by_dict = {}
alloc_type_dict = {}
alloc_module_dict = {}
nr_free_areas = 11

pool_index_bits = 21
offset_bits = 10
valid_bits = 1
extra_bits = 5

DEPOT_STACK_ALIGN = 4


def extract_bits(number, low_bit, length):
    number = (number >> low_bit)
    number = (number & ((1 << length) - 1))

    return number


def entries_len(entries, size):
    for i in range(size):
        sym_addr = entries[i]
        if sym_addr == 0:
            return i
    return size  # All entries are within range


def make_handle_union(bits_slab, bits_offset, bits_valid, bits_extra):
    # sanity check
    total = bits_slab + bits_offset + bits_valid + bits_extra
    if total > 32:
        raise ValueError(f"Too many bits ({total}), must be <= 32")

    # Bit shifts and masks for each field (little-endian bit layout)
    shift_slab   = 0
    shift_offset = bits_slab
    shift_valid  = bits_slab + bits_offset
    shift_extra  = bits_slab + bits_offset + bits_valid

    mask_slab   = (1 << bits_slab)   - 1 if bits_slab   > 0 else 0
    mask_offset = (1 << bits_offset) - 1 if bits_offset > 0 else 0
    mask_valid  = (1 << bits_valid)  - 1 if bits_valid  > 0 else 0
    mask_extra  = (1 << bits_extra)  - 1 if bits_extra  > 0 else 0

    class HandleUnion:
        def __init__(self, *, slabindex=0, offset=0, valid=0, extra=0, handle=None):
            if handle is not None:
                self.handle = handle & 0xFFFFFFFF
            else:
                self.handle = (
                    ((slabindex & mask_slab)   << shift_slab)   |
                    ((offset    & mask_offset) << shift_offset) |
                    ((valid     & mask_valid)  << shift_valid)  |
                    ((extra     & mask_extra)  << shift_extra)
                ) & 0xFFFFFFFF

        @property
        def slabindex(self):
            return (self.handle >> shift_slab) & mask_slab

        @slabindex.setter
        def slabindex(self, value):
            self.handle = (self.handle & ~(mask_slab << shift_slab)) | ((value & mask_slab) << shift_slab)

        @property
        def offset(self):
            return (self.handle >> shift_offset) & mask_offset

        @offset.setter
        def offset(self, value):
            self.handle = (self.handle & ~(mask_offset << shift_offset)) | ((value & mask_offset) << shift_offset)

        @property
        def valid(self):
            return (self.handle >> shift_valid) & mask_valid

        @valid.setter
        def valid(self, value):
            self.handle = (self.handle & ~(mask_valid << shift_valid)) | ((value & mask_valid) << shift_valid)

        @property
        def extra(self):
            return (self.handle >> shift_extra) & mask_extra

        @extra.setter
        def extra(self, value):
            self.handle = (self.handle & ~(mask_extra << shift_extra)) | ((value & mask_extra) << shift_extra)

    # nice name for debugging
    HandleUnion.__name__ = f"HandleUnion_{bits_slab}_{bits_offset}_{bits_valid}_{bits_extra}"
    return HandleUnion


def get_stack_entries(handle):
    global stack_pools
    global stack_handle_version
    global kernel_start_addr
    global kernel_end_addr
    global modules_start_addr
    global modules_end_addr
    global addr_size

    global pool_index_bits
    global offset_bits
    global valid_bits
    global extra_bits

    entries = []
    entry_len = 0

    handle = handle
    if handle == 0:
        return (entry_len, entries)


    '''
    HandleUnion = make_handle_union(pool_index_bits, offset_bits, valid_bits, extra_bits)
    u = HandleUnion()
    u.handle = handle

    pool_index = u.slabindex
    offset = u.offset << DEPOT_STACK_ALIGN
    valid = 0
    if valid_bits > 0:
        valid = u.valid

    extra = 0
    if extra_bits > 0:
        extra = u.extra
    
    '''
    pool_index = extract_bits(handle, 0, pool_index_bits)
    pool_index -= 1
    if pool_index < 0:
        pool_index = 0

    offset = extract_bits(handle,\
            pool_index_bits,\
            offset_bits)
    offset = offset << DEPOT_STACK_ALIGN

    valid = extract_bits(handle,\
            pool_index_bits + offset_bits,\
            valid_bits)

    if extra_bits > 0:
        extra = extract_bits(handle, \
                pool_index_bits + offset_bits + valid_bits, \
                extra_bits)
    else:
        extra = 0

    try:
        pool = stack_pools[pool_index]
        if pool == None:
            return (entry_len, entries)

        stack_record_addr = pool + offset
        stack_record = readSU("struct stack_record", stack_record_addr)
        entries = []
        stack_record_offset = member_offset("struct stack_record", "entries")

        '''
        print(pool_index)
        print(offset)
        print(valid)
        print(extra)
        print(pool)
        print(offset)
        print(stack_record)
        '''

        for i in range(stack_record.size):
            entry_addr = Addr(stack_record) + stack_record_offset + (i * addr_size)
            func_addr = readULong(entry_addr)
            entries.append(func_addr)
        entry_len = entries_len(entries, stack_record.size)
    except Exception as e:
        #print(e)
        pass

    return (entry_len, entries)


def get_trace_entries(page_owner):
    try:
        if member_offset("struct page_owner", "nr_entries") > -1:
            nr_entries = page_owner.nr_entries
            trace_entries = page_owner.trace_entries
        elif member_offset("struct page_owner", "handle") > -1:
            nr_entries, trace_entries = get_stack_entries(page_owner.handle)
        else:
            nr_entries = 0
            trace_entries = []
    except Exception as e:
        print(e)
        nr_entries = 0
        trace_entries = []

    return (nr_entries, trace_entries)


def save_page_owner(page_owner, nr_entries, trace_entries):
    global alloc_by_dict
    global alloc_type_dict
    global alloc_module_dict
    global nr_free_areas

    by_whom = ""
    mod_name = ""
    by_type = ""

    if member_offset("struct page_owner", "pid") >= 0:
        by_type = "%d (%s)" % (page_owner.pid, page_owner.comm)

    try:
        for i in range(nr_entries):
            trace_entry = trace_entries[i]
            if trace_entry == -1 or trace_entry == minus_one_addr:
                break
            trace_name = ' '.join(get_function_name(trace_entry).split()[2:])
            words = trace_name.split()
            if "[" in words[-1] and mod_name == "":
                mod_name = words[-1][1:-1]

            by_whom = by_whom + ("\n\t  [<%x>] %s" % (trace_entry,\
                      ' '.join(get_function_name(trace_entry).split()[2:])))
    except:
        pass

    size = (2 ** page_owner.order)
    if by_whom != "":
        pages = size
        if by_whom in alloc_by_dict:
            pages = pages + alloc_by_dict[by_whom]

        alloc_by_dict[by_whom] = pages

    if by_type != "":
        pages = size
        if by_type in alloc_type_dict:
            pages = pages + alloc_type_dict[by_type]

        alloc_type_dict[by_type] = pages

    if mod_name != "":
        pages = size
        if mod_name in alloc_module_dict:
            pages = pages + alloc_module_dict[mod_name]

        alloc_module_dict[mod_name] = pages




def show_page_owner(pfn, page_owner, pageblock_order,\
        nr_entries, trace_entries):
    global nr_free_areas

    if member_offset("struct page_owner", "pid") < 0: # RHEL7
        print('Page allocated via order %d, mask 0x%x' %
              (page_owner.order, page_owner.gfp_mask))
        print('PFN %d Block %d' %
              (pfn, pfn >> pageblock_order))
    else: # RHEL8 and above
        print("Page allocated via order %d, mask 0x%x(%s), pid %d, tgid %d (%s), ts %d ns, free_ts %d ns" % \
                (page_owner.order, page_owner.gfp_mask, \
                get_gfp_mask_str(page_owner.gfp_mask), \
                page_owner.pid, page_owner.tgid, page_owner.comm, \
                page_owner.ts_nsec, page_owner.free_ts_nsec))
        print('PFN %d type ... Block %d' %
              (pfn, pfn >> pageblock_order))

    for i in range(nr_entries):
        trace_entry = trace_entries[i]
        if trace_entry == -1 or trace_entry == 0xffffffffffffffff:
            break
        print("  [<%x>] %s" %
              (trace_entry, ' '.join(get_function_name(trace_entry).split()[2:])))
    print("")


def is_aligned(value, align):
    return ((value & (align - 1)) == 0)


mem_sections = []
sections_per_root = 128
section_root_mask = 0
addr_size = 8
page_owner_offset = 0
page_owner_ops = None
page_ext_size = 0
kernel_start_addr = 0x0
kernel_end_addr = 0x0
modules_start_addr = 0x0
modules_end_addr = 0x0

# Cache for performance optimization
_pages_per_section = None
_has_section_mem_map = None
_has_page_ext = None
_has_page_cgroup = None
_has_page_owner_pid = None


def print_page_owner_summary(options, file):
    global alloc_by_dict
    global alloc_type_dict
    global alloc_module_dict

    if options.maxcount > 0:
        n_items = options.maxcount
    else:
        n_items = 10
    n_items = n_items - 1

    if len(alloc_by_dict) > 0:
        print("By call trace", file=file)
        print("=============", file=file)
        sorted_usage = sorted(alloc_by_dict.items(),
                key=operator.itemgetter(1), reverse=options.reverse)

        sum_size = 0
        print_count = 0
        total_count = len(sorted_usage) - 1
        if options.all:
            print_start = 0
            print_end = total_count
        else:
            if options.reverse:
                print_start = 0
                print_end = min(total_count, n_items)
            else:
                print_start = total_count - n_items
                if print_start < 0:
                    print_start = 0
                print_end = total_count

        skip_printed = False

        for by_whom, pages in sorted_usage:
            sum_size = sum_size + pages

            if print_start <= print_count <= print_end:
                print("\n%s : %s" % (get_size_str(pages * page_size), by_whom), file=file)
            else:
                if len(sorted_usage) > n_items:
                    if not skip_printed:
                        print("\n%15s %d %s" % ("... < skipped ",
                                        len(sorted_usage) - n_items,
                                        " items > ..."), file=file)
                    skip_printed = True

            print_count = print_count + 1

        if sum_size > 0:
            print("\nTotal allocated size : %s (%s kB)" % \
                          (get_size_str(sum_size * page_size),
                           '{:,.0f}'.format(sum_size * page_size / 1024)), file=file)


    if len(alloc_module_dict) > 0:
        print("\nBy allocated modules", file=file)
        print(  "====================", file=file)
        sorted_usage = sorted(alloc_module_dict.items(),
                key=operator.itemgetter(1), reverse=options.reverse)

        sum_size = 0
        print_count = 0
        total_count = len(sorted_usage) - 1
        if options.all:
            print_start = 0
            print_end = total_count
        else:
            if options.reverse:
                print_start = 0
                print_end = min(total_count, n_items)
            else:
                print_start = total_count - n_items
                if print_start < 0:
                    print_start = 0
                print_end = total_count

        skip_printed = False
        for mod_name, pages in sorted_usage:
            sum_size = sum_size + pages

            if print_start <= print_count <= print_end:
                print("%10s : %s" % \
                      (get_size_str(pages * page_size), mod_name), file=file)
            else:
                if len(sorted_usage) > n_items:
                    if not skip_printed:
                        print("\n%15s %d %s" % ( "... < skipped ",
                                        len(sorted_usage) - n_items,
                                        " items > ..."), file=file)
                    skip_printed = True

            print_count = print_count + 1

        if sum_size > 0:
            print("\nTotal allocated by modules : %s (%s kB)" % \
                              (get_size_str(sum_size * page_size),
                               '{:,.0f}'.format(sum_size * page_size / 1024)), file=file)


    if len(alloc_type_dict) > 0:
        print("\nBy allocation type", file=file)
        print(  "==================", file=file)
        sorted_usage = sorted(alloc_type_dict.items(),
                key=operator.itemgetter(1), reverse=options.reverse)

        sum_size = 0
        print_count = 0
        total_count = len(sorted_usage) - 1
        if options.all:
            print_start = 0
            print_end = total_count
        else:
            if options.reverse:
                print_start = 0
                print_end = min(total_count, n_items)
            else:
                print_start = total_count - n_items
                if print_start < 0:
                    print_start = 0
                print_end = total_count

        skip_printed = False
        for by_type, pages in sorted_usage:
            sum_size = sum_size + pages

            if print_start <= print_count <= print_end:
                print("%10s : %s" % \
                        (get_size_str(pages * page_size), by_type), file=file)
            else:
                if len(sorted_usage) > n_items:
                    if not skip_printed:
                        print("\n%15s %d %s" % ("... < skipped ",
                                    len(sorted_usage) - n_items,
                                    " items > ..."), file=file)
                    skip_printed = True

            print_count = print_count + 1

    print("\nNotes: Calculation was done with pagesize=%d" % (page_size), file=file)


def get_stack_bits():
    global stack_pools
    global stack_handle_version
    global pool_index_bits
    global offset_bits
    global valid_bits
    global extra_bits
    global addr_size

    addr_size = int(get_machine_symbol("bits")) // 8

    if symbol_exists("stack_pools"):
        stack_pools_addr = sym2addr("stack_pools")
        stack_pools = []
        while True:
            pool_addr = readULong(stack_pools_addr)
            stack_pools_addr = stack_pools_addr + addr_size
            if pool_addr == 0:
                break
            stack_pools.append(pool_addr)

        stack_handle_version = 2

        if member_offset("union handle_parts", "valid_bits") > -1:
            pool_index_bits = 16
            offset_bits = 10
            valid_bits = 1
            extra_bits = 5
        else:
            pool_index_bits = 17
            offset_bits = 10
            valid_bits = 0
            extra_bits = 5
    elif symbol_exists("stack_slabs"):
        stack_pools = readSymbol("stack_slabs")
        stack_handle_version = 1

        pool_index_bits = 21
        offset_bits = 10
        valid_bits = 1
        extra_bits = 0
    else:
        stack_pools = None


import gc


def analyze_page_owner_file(filename, options):
    """Parse a meminfo -od output file and reproduce the same summary analysis."""
    global alloc_by_dict
    global alloc_type_dict
    global alloc_module_dict
    global page_size

    alloc_by_dict = {}
    alloc_type_dict = {}
    alloc_module_dict = {}

    try:
        with open(filename) as f:
            lines = f.readlines()
    except Exception as e:
        print("Error opening file '%s': %s" % (filename, e))
        return

    # Try to recover page_size from the Notes line at the end of the file
    notes_re = re.compile(r'Notes: Calculation was done with pagesize=(\d+)')
    for line in lines:
        m = notes_re.search(line)
        if m:
            page_size = int(m.group(1))
            break

    # "Page allocated via order N, mask 0xHEX(FLAGS), pid PID, tgid TGID (COMM), ..."
    page_re_rhel8 = re.compile(
        r'Page allocated via order (\d+), mask 0x[0-9a-f]+\([^)]*\),'
        r' pid (\d+), tgid \d+ \(([^)]+)\)')
    # "Page allocated via order N, mask 0xHEX"  (RHEL7, no pid)
    page_re_rhel7 = re.compile(r'Page allocated via order (\d+), mask 0x[0-9a-f]+')
    # "  [<ADDR>] FUNCTION_NAME"
    trace_re = re.compile(r'^\s+\[<([0-9a-f]+)>\]\s+(.*)')

    i = 0
    total_entries = 0
    while i < len(lines):
        line = lines[i].rstrip()

        m8 = page_re_rhel8.search(line)
        if m8:
            order = int(m8.group(1))
            by_type = "%d (%s)" % (int(m8.group(2)), m8.group(3))
        elif 'Page allocated via order' in line:
            m7 = page_re_rhel7.search(line)
            if m7:
                order = int(m7.group(1))
                by_type = ""
            else:
                i += 1
                continue
        else:
            i += 1
            continue

        i += 1
        # Skip the PFN line
        if i < len(lines) and lines[i].startswith('PFN'):
            i += 1

        # Collect trace lines and rebuild the by_whom key in the same format
        # that save_page_owner uses: "\n\t  [<HEX>] FUNC"
        by_whom = ""
        mod_name = ""
        while i < len(lines):
            tm = trace_re.match(lines[i])
            if tm:
                addr_str = tm.group(1)
                func = tm.group(2).strip()
                by_whom += "\n\t  [<%s>] %s" % (addr_str, func)
                if mod_name == "":
                    words = func.split()
                    if words and words[-1].startswith("[") and words[-1].endswith("]"):
                        mod_name = words[-1][1:-1]
                i += 1
            else:
                break

        size = 2 ** order

        if by_whom:
            alloc_by_dict[by_whom] = alloc_by_dict.get(by_whom, 0) + size
        if by_type:
            alloc_type_dict[by_type] = alloc_type_dict.get(by_type, 0) + size
        if mod_name:
            alloc_module_dict[mod_name] = alloc_module_dict.get(mod_name, 0) + size

        total_entries += 1

    print("Analyzed %d page allocations from '%s'" % (total_entries, filename))
    print_page_owner_summary(options, sys.stdout)


def show_page_owner_all(options):
    global alloc_by_dict
    global alloc_type_dict
    global alloc_module_dict

    global stack_pools
    global stack_handle_version
    global pool_index_bits
    global offset_bits
    global valid_bits
    global extra_bits
    global mem_sections
    global sections_per_root
    global section_root_mask
    global addr_size
    global page_owner_offset
    global page_owner_ops
    global page_ext_size
    global PAGE_EXT_OWNER
    global PAGE_EXT_OWNER_ALLOCATED
    global nr_free_areas
    global kernel_start_addr
    global kernel_end_addr
    global modules_start_addr
    global modules_end_addr

    page_owner_on = 0
    alloc_by_dict = {}
    alloc_type_dict = {}
    alloc_module_dict = {}

    kernel_start_addr = sym2addr("_stext")
    kernel_end_addr = sym2addr("_etext")
    modules_start_addr = int(get_machine_symbol("modules_vaddr"), 16)
    modules_end_addr = int(get_machine_symbol("modules_end"), 16)
    nr_free_areas = int(get_machine_symbol("nr_free_areas", "help -v"))
    sections_per_root = int(get_machine_symbol("sections_per_root"))
    section_root_mask = sections_per_root - 1
    addr_size = int(get_machine_symbol("bits")) // 8

    try:
        page_ext_flags = EnumInfo("enum page_ext_flags")
        for enum_name in page_ext_flags:
            if enum_name == "PAGE_EXT_OWNER":
                PAGE_EXT_OWNER = page_ext_flags[enum_name]
            elif enum_name == "PAGE_EXT_OWNER_ALLOCATED":
                PAGE_EXT_OWNER_ALLOCATED = page_ext_flags[enum_name]
    except Exception as e:
        print(e)


    try:
        page_owner_ops = readSymbol("page_owner_ops")
    except:
        page_owner_ops = None

    page_owner_offset = 0
    if page_owner_ops != None and \
            member_offset("struct page_ext_operations", "offset") > -1:
        page_owner_offset = page_owner_ops.offset

    try:
        page_owner_inited = readSymbol("page_owner_inited")
        try:
            # RHEL8/9
            page_owner_on = page_owner_inited.key.enabled.counter
        except:
            # RHEL7
            page_owner_on = page_owner_inited.enabled.counter
    except Exception as e:
        pass

    if page_owner_on == 0:
        print("page_owner is not enabled")
        return


    try:
        max_pfn = readSymbol("max_pfn")
        min_low_pfn = readSymbol("min_low_pfn")
    except:
        print("Error to find max_pfn")
        return

    try:
        page_ext_size = readSymbol("page_ext_size")
    except:
        try:
            extra_mem = readSymbol("extra_mem")
            page_ext_size = extra_mem + member_offset("struct po_size_table", "page_ext")
        except:
            page_ext_size = -1 # use old RHEL7 method


    get_stack_bits()

    pfn = min_low_pfn
    max_order = get_max_order()
    pageblock_order = max_order - 1

    # Get mem_section from crash
    if PAGE_EXT_OWNER_ALLOCATED == -1:
        mem_section_addr = sym2addr("mem_section")
        mem_section = readULong(mem_section_addr)
    else:
        mem_section_addr = readSymbol("mem_section")
        mem_section = readULong(mem_section_addr)

    while True:
        if mem_section == 0:
            break
        mem_sections.append(mem_section)
        mem_section_addr += addr_size
        mem_section = readULong(mem_section_addr)


    try:
        tty = open('/dev/tty', 'w')
    except:
        tty = os.fdopen(os.dup(sys.stdout.fileno()), 'w')

    interrupted = False
    try:
        while pfn < max_pfn:
            if tty != None:
                print(f"{pfn:,} out of {max_pfn:,} pages processed."
                            f"({(pfn / max_pfn) * 100:.2f}%)", end="\r", file=tty)

            page_owner = pfn_to_page_owner(pfn)
            if page_owner == -1 or page_owner == 0 or page_owner == None:
                pfn = pfn + 1
                continue

            # Wrap entire page_owner processing in try-except to handle invalid objects
            try:
                # Access page_owner.order - this might fail if page_owner is invalid
                if page_owner.order >= nr_free_areas:
                    pfn = pfn + 1
                    continue

                # Skip tail pages of multi-page allocations
                # Only process the head page (aligned to allocation order)
                if not is_aligned(pfn, 1 << page_owner.order):
                    pfn = pfn + 1
                    continue

                nr_entries, trace_entries = get_trace_entries(page_owner)
                if nr_entries == 0:
                    pfn = pfn + 1
                    continue

                try:
                    save_page_owner(page_owner, nr_entries, trace_entries)

                    if options.details:  # shows raw call trace
                        show_page_owner(pfn, page_owner, pageblock_order,\
                                nr_entries, trace_entries)

                except Exception as e:
                    print(e)

            except Exception:
                # page_owner object is invalid or points to bad memory
                # Skip this PFN and continue
                pass

            pfn = pfn + 1

    except KeyboardInterrupt:
        interrupted = True

    if tty != None:
        print(" " * 70, end="\r", file=tty) # clear the line

    if interrupted:
        total_pfns = max_pfn - min_low_pfn
        processed_pfns = pfn - min_low_pfn
        percent = (processed_pfns * 100.0 / total_pfns) if total_pfns > 0 else 0
        crashcolor.set_color(crashcolor.YELLOW)
        print("\n*** Interrupted by user (Ctrl-C) ***")
        print("Processed %d out of %d pages (%.2f%%) - showing partial results\n" %
              (processed_pfns, total_pfns, percent))
        crashcolor.set_color(crashcolor.RESET)

    print_page_owner_summary(options, tty)

    if tty != None:
        tty.close()


def show_oom_meminfo(op, meminfo_dict):
    global page_size

    print("\n%s" % ('#' * 46))
    print("%-30s %15s" % ("Category", "Size"))
    print("%s" % ('-' * 46))

    sorted_meminfo_dict = sorted(meminfo_dict.items(),
                            key=operator.itemgetter(1), reverse=True)

    for i in range(0, len(sorted_meminfo_dict)):
        try:
            key = sorted_meminfo_dict[i][0]
            val = sorted_meminfo_dict[i][1]
            print("%-30s %15s" % (key, get_size_str(val, True)))
            crashcolor.set_color(crashcolor.RESET)
        except:
            pass
    print("%s" % ('~' * 46))


def show_oom_memory_usage(op, oom_dict, total_usage):
    # Get system's total memory for percentage calculation
    system_meminfo = get_meminfo_dict()
    system_total_mem_kb = system_meminfo.get('MemTotal', 0)
    system_total_mem_bytes = system_total_mem_kb * 1024

    sorted_oom_dict = sorted(oom_dict.items(),
                            key=operator.itemgetter(1), reverse=True)
    min_number = getattr(op, 'oom_top', 10)
    if (op.all):
        min_number = len(sorted_oom_dict)

    print_count = min(len(sorted_oom_dict), min_number)

    # Check if graph mode is enabled
    show_graph = getattr(op, 'graph', False)

    # Calculate optimal column width based on terminal width and longest process name
    initial_terminal_width = get_terminal_width()
    max_widths = get_optimal_max_widths(show_graph)
    max_pname_len = max(len(sorted_oom_dict[i][0]) for i in range(0, print_count)) if print_count > 0 else 20
    pname_width = max(20, min(max_widths['process_name'], max_pname_len + 2))

    # Calculate separator width based on graph mode
    separator_width = pname_width + 15 + 3
    if show_graph:
        separator_width = pname_width + 24 + 15 + 6

    print("=" * separator_width)
    if show_graph:
        format_str = "%-" + str(pname_width) + "s %-24s %15s"
        print(format_str % ("Process_Name", "Usage_Percent", "Usage"))
    else:
        format_str = "%-" + str(pname_width) + "s %15s"
        print(format_str % ("NAME", "Usage"))
    print("-" * separator_width)  # Add separator line between header and data

    for i in range(0, print_count):
        # Check for terminal resize every 10 rows (to avoid excessive system calls)
        if show_graph and i > 0 and i % 10 == 0:
            current_width = get_terminal_width()
            if abs(current_width - initial_terminal_width) > 5:
                # Terminal resized significantly - restart table with new width
                print("=" * separator_width)
                crashcolor.set_color(crashcolor.YELLOW)
                print("\n[Terminal resized - adjusting table width]\n")
                crashcolor.set_color(crashcolor.RESET)

                # Recalculate widths
                initial_terminal_width = current_width
                max_widths = get_optimal_max_widths(show_graph)
                pname_width = max(20, min(max_widths['process_name'], max_pname_len + 1))
                separator_width = pname_width + 24 + 15 + 6

                # Reprint header
                print("=" * separator_width)
                format_str = "%-" + str(pname_width) + "s %-24s %15s"
                print(format_str % ("Process_Name", "Usage_Percent", "Usage"))
                print("-" * separator_width)

        pname = sorted_oom_dict[i][0]
        # Truncate process name to fit column width
        pname = truncate_middle(pname, pname_width)

        mem_usage = sorted_oom_dict[i][1]

        if show_graph:
            # Calculate percentage based on system's total memory
            percentage = (mem_usage * 100.0 / system_total_mem_bytes) if system_total_mem_bytes > 0 else 0
            bar = get_memory_bar(percentage, width=ITEM_BAR_WIDTH)
            format_str = "%-" + str(pname_width) + "s %s %15s"
            print(format_str % (pname, bar, get_size_str(mem_usage, True)))
        else:
            format_str = "%-" + str(pname_width) + "s %15s"
            print(format_str % (pname, get_size_str(mem_usage, True)))
        crashcolor.set_color(crashcolor.RESET)

    if print_count < len(sorted_oom_dict) - 1:
        print("\t<...>")
    print("=" * separator_width)
    print("Total memory usage from processes = %s" % get_size_str(total_usage, True))
    # Show total usage bar graph
    if show_graph and system_total_mem_bytes > 0:
        total_percentage = (total_usage * 100.0 / system_total_mem_bytes)
        print("\tNotes) %.2f percent from total system memory(%s)" %
              (total_percentage, get_size_str(system_total_mem_bytes, True)))
        bar = get_memory_bar(total_percentage, width=TOTAL_BAR_WIDTH)
        print("\t       %s" % bar)
    crashcolor.set_color(crashcolor.RESET)


def get_size(val):
    global page_size

    size = 0
    if val.lower().endswith("kb"):
        size = int(val[:-2]) * 1024
    elif val.lower().endswith("mb"):
        size = int(val[:-2]) * 1024 * 1024
    elif val.lower().endswith("gb"):
        size = int(val[:-2]) * 1024 * 1024 * 1024
    else:
        size = int(val.split('#')[0]) * page_size

    return size


import traceback
import re

def build_process_filter_pattern(filter_str):
    """
    Build regex pattern from filter string.
    Supports:
    - Comma-separated: "java,python,VM" -> regex: (java|python|VM)
    - Direct regex: "java.*" -> regex: java.*
    """
    if not filter_str:
        return None

    try:
        # Check if it's already a regex pattern (contains regex special chars)
        if any(c in filter_str for c in ['.*', '.+', '^', '$', '\\', '[', ']', '(', ')', '|']) and ',' not in filter_str:
            # Treat as direct regex
            return re.compile(filter_str, re.IGNORECASE)
        else:
            # Treat as comma-separated list
            # Split by comma and strip whitespace
            processes = [p.strip() for p in filter_str.split(',')]
            # Build alternation pattern
            pattern = '|'.join(processes)
            return re.compile('(' + pattern + ')', re.IGNORECASE)
    except re.error as e:
        print("Invalid regex pattern: %s" % str(e))
        return None


def extract_invoker_process(line):
    """Extract process name from 'invoked oom-killer' line"""
    # Line format: "... processname invoked oom-killer: ..."
    try:
        parts = line.split("invoked oom-killer:")
        if len(parts) > 0:
            before = parts[0].strip()
            # Get last word before "invoked"
            words = before.split()
            if len(words) > 0:
                return words[-1]
    except:
        pass
    return ""


def show_oom_events(op):
    global page_size

    page_size = 1 << get_page_shift()
    is_first_oom = True
    oom_event_counter = 0

    # Initialize process filter
    process_filter_pattern = None
    process_filter = getattr(op, 'process_filter', "")
    if process_filter:
        process_filter_pattern = build_process_filter_pattern(process_filter)
        if process_filter_pattern is None:
            print("Invalid filter pattern: %s" % process_filter)
            return

    # Get count limit and skip count
    oom_count = getattr(op, 'oom_count', 0)
    oom_skip = getattr(op, 'oom_skip', 0)

    try:
        result_lines = exec_crash_command('log').splitlines()
        oom_invoked = False
        oom_meminfo = False
        oom_cgroup_stats = False
        is_first_meminfo = True
        oom_ps_started = False
        rss_index = -1
        pid_index = -1
        pname_index = -1
        oom_dict = {}
        meminfo_dict = {}
        cgroup_dict = {}
        total_usage = 0
        oom_display_counter = 0  # Counter for displayed events
        skip_message_shown = False  # Track if we've shown the skip message
        in_displayed_event = False  # Track if we're in an event that should be displayed
        for line in result_lines:
            if "invoked oom-killer:" in line:
                oom_event_counter += 1

                # Check if we should skip this event
                should_skip_event = oom_skip > 0 and oom_event_counter <= oom_skip
                if should_skip_event:
                    in_displayed_event = False
                    continue

                # Check if we've hit the display count limit
                if oom_count > 0 and oom_display_counter >= oom_count:
                    in_displayed_event = False
                    break

                # Check process filter
                if process_filter_pattern:
                    invoker = extract_invoker_process(line)
                    if not process_filter_pattern.search(invoker):
                        # Skip this OOM event - wrong process
                        in_displayed_event = False
                        continue

                oom_invoked = True
                in_displayed_event = True
                oom_display_counter += 1

                # Show skip message before the first displayed event
                if not skip_message_shown and oom_skip > 0:
                    crashcolor.set_color(crashcolor.YELLOW)
                    print("\n... < skipped %d OOM event%s > ...\n" %
                          (oom_skip, "s" if oom_skip > 1 else ""))
                    crashcolor.set_color(crashcolor.RESET)
                    skip_message_shown = True

                if not is_first_oom:
                    print()

                crashcolor.set_color(crashcolor.RED)
                print(line)
                crashcolor.set_color(crashcolor.RESET)
                is_first_oom = False
                continue

            if "Out of memory: Kill" in line or "Killed process" in line:
                # Only show if we're in a displayed OOM event
                if in_displayed_event:
                    crashcolor.set_color(crashcolor.GREEN)
                    print(line)
                    crashcolor.set_color(crashcolor.RESET)
                continue


            time_str = line.split(']')[0]
            if time_str.startswith("["):
                time_str_len = len(time_str)
                if not is_first_meminfo and time_str_len != 0:
                    oom_meminfo = False
                line = line[time_str_len + 1:]

            if oom_invoked:
                if "Mem-Info:" in line:
                    oom_meminfo = True
                    is_first_meminfo = True
                    continue
                elif "memory: usage" in line:
                    cgroup_dict["memory"] = line
                    continue
                elif "swap: usage" in line:
                    cgroup_dict["swap"] = line
                    continue
                elif "Memory cgroup stats for" in line:
                    line = line[line.find(" stats for ") + 11:]
                    oom_cgroup_stats = True
                    if ': ' in line:
                        cgroup_dict["cgroup"] = line.split(':')[0]
                        line = line[line.find(':') + 1:]
                    else:
                        cgroup_dict["cgroup"] = line[:-1]
                        continue


            if oom_meminfo:
                is_first_meminfo = False
                #words = line.split()
                #for entry in words:
                #    key_val = entry.split(':')
                #    meminfo_dict[key_val[0]] = get_size(key_val[1])
                #continue
                if " hugepages_total" in line:
                    line = line[line.find("hugepages_total="):]
                    words = line.split()
                    for entry in words:
                        key_val = entry.split('=')
                        meminfo_dict[key_val[0]] = get_size(key_val[1])
                    continue
                elif " total pagecache pages" in line:
                    words = line.split()
                    meminfo_dict["Pagecaches"] = get_size(words[0])
                    continue
                else:
                    try:
                        words = line.split()
                        for word in words:
                            key_val = word.split(':')
                            meminfo_dict[key_val[0]] = get_size(key_val[1])
                        continue
                    except: # Ignore messed log
                        pass


            if oom_invoked and "uid" in line and "total_vm" in line:
                oom_ps_started = True
                oom_meminfo = False
                oom_cgroup_stats = False
                line = line.replace("[", "")
                line = line.replace("]", "")
                words = line.split()
                for i in range(0, len(words)):
                    if words[i] == "rss":
                        rss_index = i
                    elif words[i] == "pid":
                        pid_index = i
                    elif words[i] == "name":
                        pname_index = i

                continue

            if oom_cgroup_stats:
                try:
                    words = line.split()
                    if ':' in words[0]:
                        for word in words:
                            key_val = word.split(':')
                            meminfo_dict[key_val[0]] = get_size(key_val[1])
                    else:
                        if words[1].isdigit():
                            meminfo_dict[words[0]] = get_size(words[1])
                        else:
                            oom_cgroup_stats = False
                except:
                    pass


            if not oom_ps_started:
                continue

            if "[" not in line: #end of oom_ps
                if len(cgroup_dict) > 0:
                    print("CGroup : " + cgroup_dict["cgroup"])
                    cgroup_dict.pop("cgroup")
                    for key in cgroup_dict:
                        print("  " + cgroup_dict[key])

                show_oom_memory_usage(op, oom_dict, total_usage)
                if op.details:
                    show_oom_meminfo(op, meminfo_dict)
                oom_invoked = False
                oom_meminfo = False
                oom_cgroup_stats = False
                oom_ps_started = False
                rss_index = -1
                pid_index = -1
                pname_index = -1
                oom_dict = {}
                meminfo_dict = {}
                cgroup_dict = {}
                total_usage = 0
                continue

            try:
                line = line.replace("[", "")
                line = line.replace("]", "")
                words = line.split()
                if len(words) <= pname_index:
                    continue
                pid = words[pid_index]
                rss = int(words[rss_index]) * page_size
                total_usage = total_usage + rss
                pname = words[pname_index]
                if op.all:
                    pname = pname + (" (%s)" % pid)
                if pname in oom_dict:
                    rss = rss + oom_dict[pname]
                oom_dict[pname] = rss
            except:
                pass
    except Exception as e:
        print(e)
        traceback.print_exc()
        pass


def show_overall_memory(options):
    """
    Show overall memory usage breakdown with bar graphs combining kmem -i and meminfo data
    """
    # Check if there are any OOM events in the log first
    # If found, automatically display OOM analysis with graphs
    try:
        result_lines = exec_crash_command('log').splitlines()

        # Count total OOM events
        total_oom_events = sum(1 for line in result_lines if "invoked oom-killer:" in line)

        if total_oom_events > 0:
            # Create a copy of options with graph enabled for OOM display
            oom_options = copy.copy(options)
            oom_options.graph = True

            # Show only the last OOM event
            oom_options.oom_count = 1
            oom_options.oom_skip = total_oom_events - 1

            # Display separator and OOM analysis
            print("\n")
            crashcolor.set_color(crashcolor.YELLOW)
            print("=" * 80)
            if total_oom_events > 1:
                print("OOM EVENTS DETECTED - %d events found, skipping first %d, showing last one" %
                      (total_oom_events, total_oom_events - 1))
            else:
                print("OOM EVENTS DETECTED - Displaying OOM Analysis (meminfo -Og)")
            print("=" * 80)
            crashcolor.set_color(crashcolor.RESET)
            print()

            # Call show_oom_events with graph mode enabled
            show_oom_events(oom_options)
    except Exception as e:
        # Silently ignore errors in OOM detection to not break --overall display
        pass

    crashcolor.set_color(crashcolor.BLUE)
    print("\n" + "=" * 80)
    print("OVERALL MEMORY USAGE BREAKDOWN")
    print("=" * 80)
    crashcolor.set_color(crashcolor.RESET)

    # Use existing working function to get memory info
    meminfo = get_meminfo_dict()

    # Storage for memory categories
    mem_categories = {}

    # Get total memory
    total_mem_kb = meminfo.get('MemTotal', 0)

    if total_mem_kb == 0:
        crashcolor.set_color(crashcolor.RED)
        print("Error: Could not determine total system memory")
        crashcolor.set_color(crashcolor.RESET)
        return

    # Extract memory categories from meminfo dict
    if 'MemFree' in meminfo and meminfo['MemFree'] > 0:
        mem_categories['Free'] = meminfo['MemFree']

    if 'Buffers' in meminfo and meminfo['Buffers'] > 0:
        mem_categories['Buffers'] = meminfo['Buffers']

    if 'Cached' in meminfo and meminfo['Cached'] > 0:
        mem_categories['Cached'] = meminfo['Cached']

    if 'Slab' in meminfo and meminfo['Slab'] > 0:
        mem_categories['Slab'] = meminfo['Slab']

    # Calculate HugePages total allocated (not just used)
    if 'HugePages_Total' in meminfo and 'Hugepagesize' in meminfo:
        huge_total = meminfo['HugePages_Total']
        huge_pagesize_kb = meminfo['Hugepagesize']
        if huge_total > 0:
            # Total allocated huge pages in KB
            hugepages_total_kb = huge_total * huge_pagesize_kb
            if hugepages_total_kb > 0:
                mem_categories['HugePages'] = hugepages_total_kb

    # Get user-space memory usage using the safe ps -G approach
    # (same pattern as existing meminfo code lines 1188-1211)
    user_space_kb = 0
    try:
        ps_output = exec_crash_command("ps -G")
        result_lines = ps_output.splitlines()

        for line in result_lines[1:]:  # Skip header
            # Handle '>' marker for current task
            if line.startswith('>'):
                line = line.replace('>', ' ', 1)

            words = line.split()
            if len(words) < 8:
                continue

            # Check if first field is PID (numeric)
            if not words[0].isdigit():
                continue

            try:
                # RSS is in column 7 (0-indexed)
                rss_kb = int(words[7])
                user_space_kb += rss_kb
            except (ValueError, IndexError):
                continue

    except Exception as e:
        crashcolor.set_color(crashcolor.YELLOW)
        print("Warning: Could not calculate user-space memory from ps -G")
        print("Error: %s" % str(e))
        crashcolor.set_color(crashcolor.RESET)

    # Store user-space in categories
    if user_space_kb > 0:
        mem_categories['User-Space'] = user_space_kb

    # Calculate kernel space (everything else)
    accounted_kb = sum(mem_categories.values())
    kernel_other_kb = total_mem_kb - accounted_kb

    if kernel_other_kb > 0:
        mem_categories['Kernel-Other'] = kernel_other_kb
    elif kernel_other_kb < 0:
        # Negative value indicates double-counting or error
        crashcolor.set_color(crashcolor.YELLOW)
        print("\nWarning: Memory accounting shows negative Kernel-Other")
        print("This may indicate overlapping categories or parsing errors")
        crashcolor.set_color(crashcolor.RESET)

    # Sort categories by size (descending)
    sorted_categories = sorted(mem_categories.items(), key=lambda x: x[1], reverse=True)

    # Display header
    print("\nTotal System Memory: %s\n" % get_size_str(total_mem_kb * 1024))

    # Column headers - optimized for 80-column terminals
    header_format = "%-15s %11s %8s  %s"
    print(header_format % ("Category", "Size", "Percent", "Usage Bar"))
    print("-" * 80)

    # Display each category with bar graph
    for category, size_kb in sorted_categories:
        percentage = (size_kb * 100.0 / total_mem_kb) if total_mem_kb > 0 else 0
        size_str = get_size_str(size_kb * 1024)
        bar = get_memory_bar(percentage, TOTAL_BAR_WIDTH)

        # Color coding
        if category == 'User-Space':
            crashcolor.set_color(crashcolor.BLUE | crashcolor.BOLD)
        elif category == 'Slab':
            crashcolor.set_color(crashcolor.GREEN)
        elif category == 'HugePages':
            crashcolor.set_color(crashcolor.YELLOW)
        elif category == 'Free':
            crashcolor.set_color(crashcolor.RESET)
        else:
            crashcolor.set_color(crashcolor.CYAN)

        print("%-15s %11s %7.2f%%  %s" % (category, size_str, percentage, bar))
        crashcolor.set_color(crashcolor.RESET)

    print("-" * 80)

    # Summary
    print("\nMemory Accounting:")
    print("  Total Accounted: %s (%.2f%%)" %
          (get_size_str(accounted_kb * 1024),
           (accounted_kb * 100.0 / total_mem_kb) if total_mem_kb > 0 else 0))

    # Additional details
    crashcolor.set_color(crashcolor.BLUE)
    print("\nKey Categories:")
    crashcolor.set_color(crashcolor.RESET)

    category_descriptions = {
        'User-Space': 'Application/process memory (RSS from all tasks)',
        'Slab': 'Kernel slab allocator cache',
        'HugePages': 'Huge pages allocated (total)',
        'Cached': 'Page cache (file-backed pages)',
        'Buffers': 'Buffer cache',
        'Free': 'Available free memory',
        'Kernel-Other': 'Kernel memory (page tables, stacks, vmalloc, etc.)'
    }

    for category, size_kb in sorted_categories:
        if category in category_descriptions:
            print("  %-15s : %s" % (category, category_descriptions[category]))

    # Show HugePages allocation vs actual usage breakdown
    if 'HugePages_Total' in meminfo and 'Hugepagesize' in meminfo:
        hp_total = meminfo.get('HugePages_Total', 0)
        hp_free = meminfo.get('HugePages_Free', 0)
        hp_rsvd = meminfo.get('HugePages_Rsvd', 0)
        hp_surp = meminfo.get('HugePages_Surp', 0)
        hp_size_kb = meminfo.get('Hugepagesize', 0)

        if hp_total > 0:
            hp_used = hp_total - hp_free

            # Calculate sizes in KB
            hp_total_kb = hp_total * hp_size_kb
            hp_used_kb = hp_used * hp_size_kb
            hp_free_kb = hp_free * hp_size_kb
            hp_rsvd_kb = hp_rsvd * hp_size_kb
            hp_surp_kb = hp_surp * hp_size_kb

            # Calculate percentages
            used_percent = (hp_used * 100.0 / hp_total) if hp_total > 0 else 0
            free_percent = (hp_free * 100.0 / hp_total) if hp_total > 0 else 0

            crashcolor.set_color(crashcolor.BLUE)
            print("\n" + "=" * 80)
            print("HUGEPAGES ALLOCATION vs USAGE")
            print("=" * 80)
            crashcolor.set_color(crashcolor.RESET)

            # Bar graph showing used vs free with gradual shading
            # Use the same get_memory_bar() function as meminfo -g
            bar_width = 60
            bar = get_memory_bar(used_percent, bar_width)

            print("\nUtilization:")
            print(bar)

            # Legend (showing only darkest and lightest)
            print("  ", end='')
            crashcolor.set_color(crashcolor.RED | crashcolor.BOLD)
            print("█", end='')
            crashcolor.set_color(crashcolor.RESET)
            print(" Used: %s (%.2f%%)    " % (get_size_str(hp_used_kb * 1024), used_percent), end='')
            crashcolor.set_color(crashcolor.GREEN)
            print("░", end='')
            crashcolor.set_color(crashcolor.RESET)
            print(" Free: %s (%.2f%%)" % (get_size_str(hp_free_kb * 1024), free_percent))

            # Total allocated (right after Used/Free line)
            print("  Total Allocated: %s (%d pages)" % (get_size_str(hp_total_kb * 1024), hp_total))

            # Page size info
            print("\nHugePage Size: %s" % get_size_str(hp_size_kb * 1024))

            # Reserved and Surplus (if any)
            if hp_rsvd > 0:
                print("Reserved: %d pages (%s)" % (hp_rsvd, get_size_str(hp_rsvd_kb * 1024)))
            if hp_surp > 0:
                print("Surplus: %d pages (%s)" % (hp_surp, get_size_str(hp_surp_kb * 1024)))

    crashcolor.set_color(crashcolor.RESET)
    print("\n" + "=" * 80)


def meminfo():
    global debug_mode

    sys.setrecursionlimit(10000000)

    op = OptionParser()
    op.add_option("-a", "--all", dest="all", default=0,
                  action="store_true",
                  help="Show all the output")
    op.add_option("-b", "--budyinfo", dest="buddyinfo", default=0,
                  action="store_true",
                  help="Show /proc/buddyinfo like output")
    op.add_option("-c", "--compact", dest="compact", default=0,
                  action="store_true",
                  help="Show compact data for other options")
    op.add_option("-d", "--details", dest="details", default=0,
                  action="store_true",
                  help="Show detailed output")
    op.add_option("--debug", dest="debug", default=0,
                  action="store_true",
                  help="Show debug output")
    op.add_option("-e", "--error", dest="error_code", default="",
                  action="store",
                  type="string",
                  help="Interpret page_fault error code")
    op.add_option("-f", "--tlb", dest="tlb_list", default="",
                  action="store",
                  type="string",
                  help="Shows tlb list (csd). example) meminfo -f 0xffffade6b68037e0 -d")
    op.add_option("-F", "--pte_flags", dest="pte_flags", default="",
                  action="store",
                  type="string",
                  help="Shows the meaning of pte flags")
    op.add_option("-G", "--gfp_mask", dest="gfp_mask", default="",
                  action="store",
                  type="string",
                  help="Interpret gfp_mask value")
    op.add_option("-g", "--graph", dest="graph", default=0,
                  action="store_true",
                  help="Show bar chart for memory usage visualization")
    op.add_option("-i", "--meminfo", dest="meminfo", default=0,
                  action="store_true",
                  help="Show /proc/meminfo-like output")
    op.add_option("-l", "--longer", dest="longer", default=0,
                  action="store_true",
                  help="Show more data than normal")
    op.add_option("-m", "--numa", dest="numa", default=0,
                  action="store_true",
                  help="Show NUMA info")
    op.add_option("--maxcount", dest="maxcount", default=0,
                  action="store", type="int",
                  help="Check only maxcount")
    op.add_option("--memory_limit", dest="memory_limit", default=0,
                  action="store", type="int",
                  help="Limit call trace storage to reduce memory usage (default: 0, no limit)")
    op.add_option("-n", "--nogroup", dest="nogroup", default=0,
                  action="store_true",
                  help="Show data in individual tasks")
    op.add_option("-o", "--page_owner", dest="page_owner", default=0,
                  action="store_true",
                  help="Show page_owner details")
    op.add_option("-O", "--OOM", dest="OOM", default=0,
                  action="store_true",
                  help="Analyse OOM messages in log")
    op.add_option("--overall", dest="overall", default=0,
                  action="store_true",
                  help="Show overall memory usage breakdown with bar graphs")
    op.add_option("--oom-summary", dest="oom_summary", default=0,
                  action="store_true",
                  help="Show OOM summary dashboard with pattern analysis")
    op.add_option("--process-filter", dest="process_filter", default="",
                  action="store", type="string",
                  help="Filter OOM events by process name (comma-separated or regex)")
    op.add_option("--oom-count", dest="oom_count", default=0,
                  action="store", type="int",
                  help="Limit number of OOM events to display")
    op.add_option("--oom-top", dest="oom_top", default=10,
                  action="store", type="int",
                  help="Show top N memory consumers (default: 10)")
    op.add_option("-P", "--pss", dest="memusage_pss", default=0,
                  action="store_true",
                  help="Show memory usages(pss) by tasks")
    op.add_option("-p", "--percpu", dest="percpu", default="",
                  action="store", type="string",
                  help="Convert percpu address into virtual address")
    op.add_option("--pager", dest="pager", default=2000,
                  action="store", type="int",
                  help="Show progress per specified term. default=2000")
    op.add_option("--progress", dest="progress", default=0,
                  action="store_true",
                  help="Show progress results while handling operation")
    op.add_option("--reverse", dest="reverse", default=0,
                  action="store_true",
                  help="Show results in reverse order")
    op.add_option("-s", "--slabtop", dest="slabtop", default=0,
                  action="store_true",
                  help="Show slabtop-like output")
    op.add_option("-S", "--slabdetail", dest="slabdetail", default="",
                  action="store", type="string",
                  help="Show details of a slab")
    op.add_option("--shared", dest="account_shared", default=0,
                  action="store_true",
                  help="Account for shared memory in OOM analysis to prevent double-counting")
    op.add_option("--corrupt", dest="corrupt", default="",
                  action="store", type="string",
                  help="Check SLAB corruption. Format: <kmem_cache_addr|slab_name>[:<cpu_num>]")
    op.add_option("-t", "--type", dest="percpu_type", default="",
                  action="store", type="string",
                  help="Specify percpu type : u8, u16, u32, u64, s8, s16, s32, s64, int")
    op.add_option("-u", "--memusage", dest="memusage", default=0,
                  action="store_true",
                  help="Show memory usages by tasks")
    op.add_option("-U", "--user_alloc", dest="user_alloc", default="",
                  action="store", type="string",
                  help="Show slub_debug=U usage")
    op.add_option("-v", "--vm", dest="vmshow", default=0,
                  action="store_true",
                  help="Show 'vm' output with more details")
    op.add_option("-w", "--swap", dest="swapshow", default=0,
                  action="store_true",
                  help="Show swap usage")
    op.add_option("-W", "--swap_full", dest="swap_full_show", default=0,
                  action="store_true",
                  help="Show swap usage in detail")


    (o, args) = op.parse_args()

    debug_mode = o.debug

    if (o.pte_flags != ""):
        show_pte_flags(o)
        sys.exit(0)

    if (o.buddyinfo):
        show_buddyinfo(o)
        sys.exit(0)

    if (o.slabtop):
        show_slabtop(o)
        sys.exit(0)

    if (o.slabdetail != ""):
        show_slabdetail(o)
        sys.exit(0)

    if (o.corrupt != ""):
        check_slab_corruption(o)
        sys.exit(0)

    if (o.meminfo):
        print(get_meminfo())
        sys.exit(0)

    if (o.overall):
        show_overall_memory(o)
        sys.exit(0)

    if (o.percpu):
        show_percpu(o)
        sys.exit(0)


    if (o.vmshow):
        if o.all:
            show_all_vm(o)
        else:
            show_vm(o, -1)
        sys.exit(0)


    if (o.error_code != ""):
        show_error_code(o)
        sys.exit(0)

    if (o.gfp_mask != ""):
        show_gfp_mask(o)
        sys.exit(0)

    if (o.numa):
        show_numa_info(o)
        sys.exit(0)

    if (o.tlb_list != ""):
        show_tlb_csd_list(o)
        sys.exit(0)

    if (o.user_alloc != ""):
        if (o.user_alloc == "*"):
            show_slub_debug_user_all(o)
        else:
            show_slub_debug_user(o)
        sys.exit(0)


    if (o.page_owner):
        if args:
            analyze_page_owner_file(args[0], o)
        else:
            show_page_owner_all(o)
        sys.exit(0)

    if (o.OOM):
        show_oom_events(o)
        sys.exit(0)

    if (o.swapshow or o.swap_full_show):
        show_swap_usage(o)
        sys.exit(0)

    show_tasks_memusage(o)


if ( __name__ == '__main__'):
    meminfo()
