"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *

from LinuxDump import Tasks
from LinuxDump import percpu

import sys
import operator

import crashcolor


page_size = 4096
page_shift = 12

VM_HUGETLB = 0x00400000

VM_WRITE = 0x00000002
VM_SHARED = 0x00000008

first_ksymbol = 0

stack_pools = None
stack_handle_version = 0

def check_global_symbols():
    global first_ksymbol

    try:
        first_ksymbol = int(get_machine_symbol("kvbase").split()[0], 16)
    except:
        pass

    return


machine_symbols = {}
minus_one_addr = 0

def get_machine_symbol(symbol):
    global machine_symbols
    global minus_one_addr
    global page_size

    try:
        if len(machine_symbols) == 0:
            help_s_out = exec_crash_command("help -m")
            lines = help_s_out.splitlines()
            for line in lines:
                words = line.split(":")
                key = words[0].strip()
                value = words[1].strip()
                machine_symbols[key] = value
                if key == "bits":
                    minus_one_addr = (1 << int(value)) - 1
                if key == "pagesize":
                    page_size = int(value)

        if symbol in machine_symbols:
            return machine_symbols[symbol]

    except Exception as e:
        pass

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
    pagecache = pagecache - min(pagecache / 2, wmark_low)
    available = available + pagecache

    available = available + global_page_state(NR_SLAB_RECLAIMABLE) - \
            min(global_page_state(NR_SLAB_RECLAIMABLE) / 2, wmark_low)

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
                   sysctl_overcommit_ratio / 100)

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
    page_unit = page_size / 1024
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
        meminfo['Percpu'] = int(pcpu_nr_populated * pcpu_nr_units * page_unit / 1024)

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


def show_tasks_memusage(options):
    mem_usage_dict = {}
    if options.memusage_pss:
        print("Experimental stage for Pss")
        print("It will take quite sometime to gather Pss based memory usage")

    if (options.nogroup):
        crash_command = "ps"
    else:
        crash_command = "ps -G"

    result = exec_crash_command(crash_command)
    result_lines = result.splitlines(True)
    total_rss = 0
    for i in range(1, len(result_lines)):
        if (result_lines[i].find('>') == 0):
            result_lines[i] = result_lines[i].replace('>', ' ', 1)
        result_line = result_lines[i].split()
        if (len(result_line) < 9):
            continue
        pid = result_line[0]
        if options.all:
            pname = "%s (%s)" % (result_line[8], pid)
        else:
            pname = result_line[8]
        rss = int(result_line[7])
        if options.memusage_pss:
            rss = get_pss_for_task(result_line[3])
        total_rss = total_rss + rss
        if (pname in mem_usage_dict):
            rss = mem_usage_dict[pname] + rss

        if rss != 0:
            mem_usage_dict[pname] = rss
#            print("%s %.2f" % (pname, mem_usage_dict[pname]))
#            break

    sorted_usage = sorted(mem_usage_dict.items(),
                          key=operator.itemgetter(1), reverse=True)

    print("=" * 70)
    print("%24s          %-s" % (" [ RSS usage ]", "[ Process name ]"))
    print("=" * 70)
    min_number = 10
    if (options.all):
        min_number = len(sorted_usage) - 1

    print_count = min(len(sorted_usage) - 1, min_number)

    for i in range(0, print_count):
        print("%14s (%10.2f KiB)   %-s" %
                (get_size_str(sorted_usage[i][1] * 1024, True),
                 sorted_usage[i][1],
                 sorted_usage[i][0]))
        crashcolor.set_color(crashcolor.RESET)

    if print_count < len(sorted_usage) - 1:
        print("\t<...>")
    print("=" * 70)
    crashcolor.set_color(crashcolor.BLUE)
    print("Total memory usage from user-space = %s" %
          (get_size_str(total_rss * 1024)))
    crashcolor.set_color(crashcolor.RESET)


def show_slabtop(options):
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
            total_used = (int(result_line[1]) * int(result_line[3])) / 1024
        else:
            total_used = int(result_line[4]) * int(result_line[5])
        slab_list[result_line[0]] = total_used

    sorted_slabtop = sorted(slab_list.items(),
                            key=operator.itemgetter(1), reverse=True)
    min_number = 10
    if (options.all):
        min_number = len(sorted_slabtop) - 1

    print("=" * 70)
    print("%-18s %-29s %12s %8s" %
          ("kmem_cache", "NAME", "TOTAL", "OBJSIZE"))
    print("=" * 70)

    print_count = min(len(sorted_slabtop) - 1, min_number)

    for i in range(0, print_count):
        kmem_cache = readSU("struct kmem_cache",
                            int(sorted_slabtop[i][0], 16))
        obj_size = 0
        if (member_offset('struct kmem_cache', 'buffer_size') >= 0):
            obj_size = kmem_cache.buffer_size
        elif (member_offset('struct kmem_cache', 'object_size') >= 0):
            obj_size = kmem_cache.object_size

        print("0x%16s %-29s %12s %8d" %
                (sorted_slabtop[i][0],
                 kmem_cache.name,
                 get_size_str(sorted_slabtop[i][1] * 1024, True),
                 obj_size))

        crashcolor.set_color(crashcolor.RESET)

    if print_count < len(sorted_slabtop) - 1:
        print("\t<...>")
    print("=" * 70)


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


def show_slabs_in_node(kc_node):
    print(kc_node)
    if member_offset("struct kmem_cache_node", "partial") >= 0:
        count = 0
        print("PARTIAL:")
        for page in readSUListFromHead(kc_node.partial,
                                        "lru",
                                        "struct page",
                                        maxel=1000000):
            objects = (page.objects & 0x7fff)
            inuse = (page.inuse & 0xffff)
            nr_objects = objects - inuse
            count = count + nr_objects
            print(page, end="")
            print("  %d - %d = %d" % (objects, inuse, nr_objects))

        print("FULL:")
        for page in readSUListFromHead(kc_node.full,
                                        "lru",
                                        "struct page",
                                        maxel=1000000):
            count = count + 1
            print(page)

        print("PARTIAL = %d" % kc_node.nr_partial)
        print("SLABS = %d" % kc_node.nr_slabs.counter)
        print("TOTAL = %d" % kc_node.total_objects.counter)
        print(count)


def show_slabdetail(options):
    lines = exec_crash_command("kmem -s %s" % options.slabdetail)
    if len(lines) == 0:
        return

    words = lines.splitlines()[1].split()
    kmem_cache = readSU("struct kmem_cache", int(words[0], 16))

    if kmem_cache.offset >= kmem_cache.object_size:
        offset = kmem_cache.offset + getSizeOf("long")
    else:
        offset = kmem_cache.inuse

    if (kmem_cache.flags & SLAB_RED_ZONE) == SLAB_RED_ZONE:
        offset = offset + kmem_cache.red_left_pad
        offset = offset + (kmem_cache.inuse - kmem_cache.object_size)

    # Extracting the data in the way the kernel get for slabinfo
    try:
        nr_blks, numa_meminfo = get_numa_meminfo()
        nr_blks, node_numbers = get_node_numbers(nr_blks)

        if numa_meminfo == None and node_numbers == None:
            print("No NUMA information available")
            return

        for node in range(0, nr_blks):
            n = kmem_cache.node[node]
            if n == None:
                continue

            show_slabs_in_node(n)

        return
    except Exception as e:
        print(e)
        return
    # end of it

    lines = exec_crash_command("kmem -S %s" % options.slabdetail).splitlines()
    full_mode = False
    partial_mode = False
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

        if not full_mode and not partial_mode:
            continue

        words = line.split()
        if len(words) < 5 or words[0] == "SLAB":
            continue

        if full_mode:
            show_full_slab(options, kmem_cache, int(words[1], 16),
                           int(words[0], 16), offset)
        elif partial_mode:
            show_partial_slab(options, kmem_cache,
                              int(words[0], 16), offset)



'''
    result = exec_crash_command("kmem -S %s" % options.slabdetail)
    result_lines = result.splitlines(True)
    slab_list = {}
    result_len = len(result_lines)
    objsize = 0
    content_count = {}
    blue_color = crashcolor.get_color(crashcolor.BLUE)
    red_color = crashcolor.get_color(crashcolor.RED)
    reset_color = crashcolor.get_color(crashcolor.RESET)
    print("CACHE             OBJSIZE  ALLOCATED     TOTAL  SLABS  SSIZE  NAME")
    for i in range(1, result_len - 1):
        if result_lines[i].startswith("kmem: "): # error message
            continue
        result_line = result_lines[i].split()
        if objsize == 0:
            objsize = int(result_line[1])
        print(result_lines[i], end="")
        if result_line[0].startswith("["):
            content = exec_crash_command("rd 0x%s %d" %
                                         (result_line[0][1:-1],
                                          objsize / sys_info.pointersize))
            content_lines = content.splitlines(True)
            for line in content_lines:
                words = line.split()
                output_string = words[0]
                for cnt_pos in range(1, 3):
                    word = words[cnt_pos]
                    if word not in content_count:
                        content_count[word] = 1
                    else:
                        content_count[word] = content_count[word] + 1

                    if options.details == False:
                        continue

                    if content_count[word] > 10:
                        output_string = output_string + blue_color +\
                                        " " + word + reset_color
                    elif content_count[word] > 20:
                        output_string = output_string + red_color +\
                                        " " + word + reset_color
                    else:
                        output_string = output_string + " " + word

                if len(words) > 3:
                    output_string = output_string + " " + line[line.index(words[3]):]
                print("\t%s" % output_string, end="")


    sorted_content = sorted(content_count.items(),
                            key=operator.itemgetter(1), reverse=True)
    min_number = 10
    print("\n\t%s%s%s" % (blue_color, "Mostly appeared contents", reset_color))
    print("\t%s" % ("-" * 40))
    for i in range(0, min(len(sorted_content) - 1, min_number)):
        ascii_str = exec_crash_command("ascii %s" % sorted_content[i][0])
        print("\t%s %5d %s" % (sorted_content[i][0], sorted_content[i][1],
                               ascii_str[ascii_str.index(":") + 2:]), end="")
'''


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

    for i in range(0, 3):
        print(result_lines[i])
    print("%10s %s" % ("", result_lines[3]))

    for i in range(4, total_lines):
        words = result_lines[i].split()
        size = int(words[2], 16) - int(words[1], 16)

        size_str = get_size_str(size, True)

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

alloc_func_list = {}
alloc_pid_list = {}
alloc_count = 0

free_func_list = {}
free_pid_list = {}
free_count = 0

def read_a_track(options, kmem_cache, obj_addr, offset, alloc_item=True):
    global alloc_func_list
    global alloc_pid_list
    global alloc_count

    global free_func_list
    global free_pid_list
    global free_count

    track_addr = obj_addr + offset
    track = readSU("struct track", track_addr)

    if alloc_item:
        alloc_count = alloc_count + 1
        if track.addr not in alloc_func_list:
            alloc_func_list[track.addr] = 0
        alloc_func_list[track.addr] = alloc_func_list[track.addr] + 1
    else:
        free_count = free_count + 1
        if track.addr not in free_func_list:
            free_func_list[track.addr] = 0
        free_func_list[track.addr] = free_func_list[track.addr] + 1

    if options.details:
        if alloc_item:
            if (track.addr, track.pid) not in alloc_pid_list:
                alloc_pid_list[(track.addr, track.pid)] = 0
            alloc_pid_list[(track.addr, track.pid)] =\
                            alloc_pid_list[(track.addr, track.pid)] + 1
        else:
            if (track.addr, track.pid) not in free_pid_list:
                free_pid_list[(track.addr, track.pid)] = 0
            free_pid_list[(track.addr, track.pid)] =\
                            free_pid_list[(track.addr, track.pid)] + 1

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

    if ((kmem_cache.flags & SLAB_STORE_USER) == SLAB_STORE_USER):
        t_line = t_line + blue_str + ("%8s" % "track at") + reset_str + "|"
        g_line = g_line + "-" * 8 + "+"
        d_line = d_line + blue_str + ("%8d" % offset) + reset_str + "|"

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

    for idx in range(0, total_slab):
        obj_addr = addr + kmem_cache.size * idx
        read_a_track(options, kmem_cache, obj_addr, offset, alloc_item)


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


def show_slub_debug_user(options):
    global alloc_func_list
    global alloc_count

    lines = exec_crash_command("kmem -s %s" % options.user_alloc)
    if len(lines) == 0:
        return
    words = lines.splitlines()[1].split()
    kmem_cache = readSU("struct kmem_cache", int(words[0], 16))

    if kmem_cache.offset >= kmem_cache.object_size:
        offset = kmem_cache.offset + getSizeOf("long")
    else:
        offset = kmem_cache.inuse

    if (kmem_cache.flags & SLAB_RED_ZONE) == SLAB_RED_ZONE:
        offset = offset + kmem_cache.red_left_pad
        offset = offset + (kmem_cache.inuse - kmem_cache.object_size)

    print_slab_layout(kmem_cache, offset)

    if ((kmem_cache.flags & SLAB_STORE_USER) != SLAB_STORE_USER):
        print("Please use 'slub_deubg=U' to collect alloc tracking")
        return

    lines = exec_crash_command("kmem -S %s" % options.user_alloc).splitlines()
    full_mode = False
    partial_mode = False
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

        if full_mode:
            show_alloc_track(options, kmem_cache, int(words[1], 16),
                    int(words[0], 16), offset)
        elif partial_mode:
            show_partial_alloc_track(options, kmem_cache,
                    int(words[0], 16), offset)


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

    if options.details:
        show_alloc_pid_list(options)


def get_function_name(addr):
    if addr == 0:
        return None
    sym_name = exec_crash_command("sym 0x%x" % (addr))
    words = sym_name.split()
    if len(words) == 5:
        sym_name = sym_name[:sym_name.find(words[3])]
    if sym_name.find(" /") > 0:
        sym_name = sym_name[:sym_name.find(" /")] # Don't require source code info

    sym_name = sym_name.strip()
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

    swap_usage = mm.rss_stat.count[MM_SWAPENTS].counter
    if swap_usage < 0:
        swap_usage = mm.rss_stat.count[1].counter

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
    print("%20s  %7s    %10s" % ("COMM", "PID", "SIZE"))
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
    except:
        return 0


def section_nr_to_root(sec):
    try:
        return int((sec / int(get_machine_symbol("sections_per_root"))))
    except Exception as e:
        print(e)
        return 0


def __nr_to_section(nr):
    try:
        root = section_nr_to_root(nr)
        mem_section_addr = readULong(sym2addr("mem_section"))
        if mem_section_addr == 0:
            print("no mem_section")
            return
        sections_per_root = int(get_machine_symbol("sections_per_root"))
        section_root_mask = sections_per_root - 1


        addr_size = int(int(get_machine_symbol("bits")) / 8)
        mem_section_addr = mem_section_addr + (root * addr_size)
        mem_section_addr = readULong(mem_section_addr)
        mem_section_array = readSUArray("struct mem_section", mem_section_addr, addr_size)
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


def pfn_to_page_owner(pfn, page_ext_size, page_owner_ops):
    try:
        nr = pfn_to_section_nr(pfn)
        mem_section = valid_section_nr(nr)
        if mem_section == 0:
            return None

        if mem_section == -1:
            return -1

        if member_offset("struct mem_section", "page_cgroup") > -1:
            page_cgroup = mem_section.page_cgroup + pfn
            page_ext = page_cgroup.ext
        else:
            page_ext = mem_section.page_ext

        if page_ext == 0:
            return None

        #if (page_ext.flags & (1 << PAGE_EXT_OWNER)) == 0:
        #    return None
        page_owner_offset = 0
        if page_owner_ops != None:
            page_owner_offset = page_owner_ops.offset

        if member_offset("struct page_ext", "owner") > -1:
            page_owner = page_ext.owner
        else:
            page_owner = readSU("struct page_owner", 
                            Addr(page_ext) + (page_ext_size * pfn) + \
                                    page_owner_offset)

        return page_owner
    except Exception as e:
        print(e)
        return None


page_owner_dict = {}

pool_index_bits = 21
offset_bits = 10
valid_bits = 1
extra_bits = 0

DEPOT_STACK_ALIGN = 4


def extract_bits(number, low_bit, length):
    number = (number >> low_bit)
    number = (number & ((1 << length) - 1))

    return number


def get_stack_entries(page_owner):
    global stack_pools
    global stack_handle_version

    handle = page_owner.handle

    pool_index = extract_bits(handle, 0, pool_index_bits)

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

    entries = []
    try:
        pool = stack_pools[pool_index]
        if pool == None:
            return entries

        stack_record = readSU("struct stack_record", pool + offset)

        for i in range(stack_record.size):
            entries.append(stack_record.entries[i])
    except:
        pass

    return entries


def save_page_owner(page_owner):
    global page_owner_dict
    global minus_one_addr

    alloc_func = minus_one_addr # 0xffffffffffffffff

    if member_offset("struct page_owner", "nr_entries") > -1:
        nr_entries = page_owner.nr_entries
        trace_entries = page_owner.trace_entries
    else:
        trace_entries = get_stack_entries(page_owner)
        nr_entries = len(trace_entries)

    for i in range(nr_entries):
        alloc_func = trace_entries[nr_entries - i - 1]
        if alloc_func != minus_one_addr: # skip invalid kernel symbol : 0xffffffffffffffff
            break

    if alloc_func == minus_one_addr:
        return

    if alloc_func not in page_owner_dict:
        size = 0
        page_owner_list = []
    else:
       page_owner_entry = page_owner_dict[alloc_func]
       size = page_owner_entry["total_size"]
       page_owner_list = page_owner_entry["page_owner_list"]

    size = size + (2 ** page_owner.order) * page_size
    page_owner_list.append(page_owner)
    page_owner_dict[alloc_func] = { "total_size" : size,
                                    "page_owner_list" : page_owner_list }


def show_page_owner(pfn, page_owner, pageblock_order):
    global page_owner_dict

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

    if member_offset("struct page_owner", "nr_entries") > -1:
        nr_entries = page_owner.nr_entries
        trace_entries = page_owner.trace_entries
    else:
        trace_entries = get_stack_entries(page_owner)
        nr_entries = len(trace_entries)

    for i in range(nr_entries):
        trace_entry = trace_entries[i]
        print("  [<%x>] %s" %
              (trace_entry, ' '.join(get_function_name(trace_entry).split()[2:])))
    print("")


def is_aligned(value, align):
    return ((value & (align - 1)) == 0)


def show_page_owner_all(options):
    global page_owner_dict
    global stack_pools
    global stack_handle_version
    global pool_index_bits
    global offset_bits
    global valid_bits
    global extra_bits

    page_owner_on = 0

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

    try:
        page_owner_ops = readSymbol("page_owner_ops")
    except:
        page_owner_ops = None


    if symbol_exists("stack_pools"):
        stack_pools = readSymbol("stack_pools")
        stack_handle_version = 2

        pool_index_bits = 16
        offset_bits = 10
        valid_bits = 1
        extra_bits = 5
    elif symbol_exists("stack_slabs"):
        stack_pools = readSymbol("stack_slabs")
        stack_handle_version = 1

        pool_index_bits = 21
        offset_bits = 10
        valid_bits = 1
    else:
        stack_pools = None


    pfn = min_low_pfn
    max_order = get_max_order()
    pageblock_order = max_order - 1
    while pfn < max_pfn:
        page_owner = pfn_to_page_owner(pfn, page_ext_size, page_owner_ops)
        pfn = pfn + 1
        if page_owner == -1:
            continue
        if page_owner != None:
            #if not is_aligned(pfn, 1 << page_owner.order):
            #    continue
            save_page_owner(page_owner)
            pfn = pfn + (2 ** page_owner.order) - 1

            if options.all and options.details: # shows raw call trace
                show_page_owner(pfn, page_owner, pageblock_order)


    page_usage_dict = {}
    for alloc_func in page_owner_dict:
        page_usage_dict[alloc_func] = page_owner_dict[alloc_func]["total_size"]


    sorted_usage = sorted(page_usage_dict.items(),
                          key=operator.itemgetter(1), reverse=not options.all)

    print_count = 0
    sum_size = 0
    for alloc_func, total_size in sorted_usage:
        sum_size = sum_size + total_size

        print("%10s : %s" % (get_size_str(total_size), get_function_name(alloc_func)))
        print_count = print_count + 1
        if not options.all and print_count > 9:
            if len(sorted_usage) > 10:
                print("\n%15s %d %s" % (
                        "... < skiped ",
                        len(sorted_usage) - 10,
                        " items > ..."))
                sum_size = -1
                break

    if sum_size > 0:
        print("\nTotal allocated size : %s" % (get_size_str(sum_size)))


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
    sorted_oom_dict = sorted(oom_dict.items(),
                            key=operator.itemgetter(1), reverse=True)
    min_number = 10
    if (op.all):
        min_number = len(sorted_oom_dict)

    print("=" * 58)
    print("%-42s %15s" % ("NAME", "Usage"))
    print("=" * 58)

    print_count = min(len(sorted_oom_dict), min_number)

    for i in range(0, print_count):
        pname = sorted_oom_dict[i][0]

        mem_usage = sorted_oom_dict[i][1]
        print("%-42s %15s" % (pname, get_size_str(mem_usage, True)))
        crashcolor.set_color(crashcolor.RESET)

    if print_count < len(sorted_oom_dict) - 1:
        print("\t<...>")
    print("=" * 58)
    print("Total memory usage from processes = %s" % get_size_str(total_usage, True))
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


def show_oom_events(op):
    global page_size

    page_size = 1 << get_page_shift()
    is_first_oom = True
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
        for line in result_lines:
            if "invoked oom-killer:" in line:
                oom_invoked = True
                if not is_first_oom:
                    print()

                crashcolor.set_color(crashcolor.RED)
                print(line)
                crashcolor.set_color(crashcolor.RESET)
                is_first_oom = False
                continue

            if "Out of memory: Killed process" in line:
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
    except Exception as e:
        print(e)
        pass




def meminfo():
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
    op.add_option("-g", "--gfp_mask", dest="gfp_mask", default="",
                  action="store",
                  type="string",
                  help="Interpret gfp_mask value")
    op.add_option("-i", "--meminfo", dest="meminfo", default=0,
                  action="store_true",
                  help="Show /proc/meminfo-like output")
    op.add_option("-l", "--longer", dest="longer", default=0,
                  action="store_true",
                  help="Show more data than normal")
    op.add_option("-m", "--numa", dest="numa", default=0,
                  action="store_true",
                  help="Show NUMA info")
    op.add_option("-n", "--nogroup", dest="nogroup", default=0,
                  action="store_true",
                  help="Show data in individual tasks")
    op.add_option("-o", "--page_owner", dest="page_owner", default=0,
                  action="store_true",
                  help="Show page_owner details")
    op.add_option("-O", "--OOM", dest="OOM", default=0,
                  action="store_true",
                  help="Analyse OOM messages in log")
    op.add_option("-P", "--pss", dest="memusage_pss", default=0,
                  action="store_true",
                  help="Show memory usages(pss) by tasks")
    op.add_option("-p", "--percpu", dest="percpu", default="",
                  action="store", type="string",
                  help="Convert percpu address into virtual address")
    op.add_option("-s", "--slabtop", dest="slabtop", default=0,
                  action="store_true",
                  help="Show slabtop-like output")
    op.add_option("-S", "--slabdetail", dest="slabdetail", default="",
                  action="store", type="string",
                  help="Show details of a slab")
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

    if (o.meminfo):
        print(get_meminfo())
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
