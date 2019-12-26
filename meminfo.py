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


def show_numa_info(options):
    try:
        numa_meminfo = readSymbol("numa_meminfo")
        nr_blks = numa_meminfo.nr_blks

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
            numa_memblk = numa_meminfo.blk[idx]
            if numa_memblk.nid in node_cpus:
                print("node %d cpus: " % (numa_memblk.nid), end="")
                cpu_list = node_cpus[numa_memblk.nid]
                for cpu in range(0, len(cpu_list)):
                    print(" %d" % cpu_list[cpu], end="")
                print("")
            print("node %d : 0x%016x - 0x%016x" % (numa_memblk.nid, numa_memblk.start, numa_memblk.end))
            print("node %d size : %d MB" % (numa_memblk.nid, (numa_memblk.end - numa_memblk.start) / (1024 * 1024)))

        if nr_blks <= 1:
            return
        numa_distance = readSymbol("numa_distance")
        numa_distance_cnt = readSymbol("numa_distance_cnt")
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
        print("No NUMA information available")



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
    dmval = [0, 0, 0, 0]
    shift_val = [2, 11, 12, 20]
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
    vm_stat = readSymbol("vm_stat")

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
        wmark_low = wmark_low + zone.watermark[WMARK_LOW]

    zone_state_item = EnumInfo("enum zone_stat_item")
    NR_FREE_PAGES = zone_state_item.NR_FREE_PAGES
    NR_SLAB_RECLAIMABLE = zone_state_item.NR_SLAB_RECLAIMABLE
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
    totalram_pages = readSymbol("totalram_pages")
    sysctl_overcommit_ratio = readSymbol("sysctl_overcommit_ratio")
    total_swap_pages = readSymbol("total_swap_pages")
    allowed = 0
    if sysctl_overcommit_kbytes > 0:
        allowed = sysctl_overcommit_kbytes >> (get_page_shift() - 10)
    else:
        allowed = ((totalram_pages - hugetlb_total_pages()) *\
                   sysctl_overcommit_ratio / 100)

    allowed += total_swap_pages

    return round(allowed)


def vm_committed_as():
    vm_committed_as = readSymbol("vm_committed_as")
    return vm_committed_as.count

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
            meminfo["Active(anon)"] = int(words[1])
            meminfo["Active"] = meminfo["Active"] + meminfo["Active(anon)"]
        elif words[0] == "NR_INACTIVE_ANON:":
            meminfo["Inactive(anon)"] = int(words[1])
            meminfo["Inactive"] = meminfo["Inactive"] + meminfo["Inactive(anon)"]
        elif words[0] == "NR_ACTIVE_FILE:":
            meminfo["Active(file)"] = int(words[1])
            meminfo["Active"] = meminfo["Active"] + meminfo["Active(file)"]
        elif words[0] == "NR_INACTIVE_FILE:":
            meminfo["Inactive(file)"] = int(words[1])
            meminfo["Inactive"] = meminfo["Inactive"] + meminfo["Inactive(file)"]
        elif words[0] == "NR_UNEVICTABLE:":
            meminfo["Unevictable"] = int(words[1])
        elif words[0] == "NR_MLOCK:":
            meminfo["Mlocked"] = int(words[1])
        elif words[0] == "NR_FILE_DIRTY:":
            meminfo["Dirty"] = int(words[1])
        elif words[0] == "NR_WRITEBACK:":
            meminfo["Writeback"] = int(words[1])
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
                get_entry_in_dict(meminfo, "VmallocChunk", " kB\n") +\
                get_entry_in_dict(meminfo, "HardwareCorrupted", " kB\n") +\
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
        size_str = "%d GiB" % (size / (1024*1024*1024))
        if coloring == True:
            crashcolor.set_color(crashcolor.RED)
    elif size > (1024 * 1024): # MiB
        size_str = "%d MiB" % (size / (1024*1024))
        if coloring == True:
            crashcolor.set_color(crashcolor.MAGENTA)
    elif size > (1024): # KiB
        size_str = "%d KiB" % (size / (1024))
        if coloring == True:
            crashcolor.set_color(crashcolor.GREEN)
    else:
        size_str = "%d B" % (size)

    return size_str


def show_tasks_memusage(options):
    mem_usage_dict = {}
    if (options.nogroup):
        crash_command = "ps"
    else:
        crash_command = "ps -G"

    result = exec_crash_command(crash_command)
    result_lines = result.splitlines(True)
    total_rss = 0
    for i in range(1, len(result_lines) - 1):
        if (result_lines[i].find('>') == 0):
            result_lines[i] = result_lines[i].replace('>', ' ', 1)
        result_line = result_lines[i].split()
        if (len(result_line) < 9):
            continue
        pname = result_line[8]
        rss = result_line[7]
        total_rss = total_rss + int(rss)
        if (pname in mem_usage_dict):
            rss = mem_usage_dict[pname] + int(rss)

        mem_usage_dict[pname] = int(rss)


    sorted_usage = sorted(mem_usage_dict.items(),
                          key=operator.itemgetter(1), reverse=True)

    print("=" * 70)
    print("%24s          %-s" % (" [ RSS usage ]", "[ Process name ]"))
    print("=" * 70)
    min_number = 10
    if (options.all):
        min_number = len(sorted_usage) - 1

    for i in range(0, min(len(sorted_usage) - 1, min_number)):
        print("%14s (%10s KiB)   %-s" %
                (get_size_str(int(sorted_usage[i][1]) * 1024, True),
                 sorted_usage[i][1],
                 sorted_usage[i][0]))
        crashcolor.set_color(crashcolor.RESET)

    print("=" * 70)
    crashcolor.set_color(crashcolor.BLUE)
    print("Total memory usage from user-space = %.2f GiB" %
          (total_rss/1048576))
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
        total_used = int(result_line[4]) * int(result_line[5])
        slab_list[result_line[0]] = total_used

    sorted_slabtop = sorted(slab_list.items(),
                            key=operator.itemgetter(1), reverse=True)
    min_number = 10
    if (options.all):
        min_number = len(sorted_slabtop) - 1

    print("=" * 68)
    print("%-18s %-29s %11s %7s" %
          ("kmem_cache", "NAME", "TOTAL", "OBJSIZE"))
    print("=" * 68)
    for i in range(0, min(len(sorted_slabtop) - 1, min_number)):
        kmem_cache = readSU("struct kmem_cache",
                            int(sorted_slabtop[i][0], 16))
        obj_size = 0
        if (member_offset('struct kmem_cache', 'buffer_size') >= 0):
            obj_size = kmem_cache.buffer_size
        elif (member_offset('struct kmem_cache', 'object_size') >= 0):
            obj_size = kmem_cache.object_size

        print("0x%16s %-29s %9s K %7d" %
                (sorted_slabtop[i][0],
                 kmem_cache.name,
                 sorted_slabtop[i][1],
                 obj_size))

    print("=" * 68)


def show_slabdetail(options):
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
            if page_data._count.counter == 1:
                private_mem_pages = private_mem_pages + 1
            else:
                shared_mem_pages = shared_mem_pages + 1

    return [private_mem_pages, shared_mem_pages]


def show_vm(options):
    private_mem_pages = 0
    shared_mem_pages = 0

    result_str = exec_crash_command("vm")
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
        if options.details:
            pages_list = show_vm_details(options, words)
            private_mem_pages = private_mem_pages + pages_list[0]
            shared_mem_pages = shared_mem_pages + pages_list[1]
            print(", P: %d, S: %d" % (pages_list[0], pages_list[1]), end="")
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



def meminfo():
    op = OptionParser()
    op.add_option("-u", "--memusage", dest="memusage", default=0,
                  action="store_true",
                  help="Show memory usages by tasks")
    op.add_option("-n", "--nogroup", dest="nogroup", default=0,
                  action="store_true",
                  help="Show data in individual tasks")
    op.add_option("-a", "--all", dest="all", default=0,
                  action="store_true",
                  help="Show all the output")
    op.add_option("-s", "--slabtop", dest="slabtop", default=0,
                  action="store_true",
                  help="Show slabtop-like output")
    op.add_option("-S", "--slabdetail", dest="slabdetail", default="",
                  action="store", type="string",
                  help="Show details of a slab")
    op.add_option("-i", "--meminfo", dest="meminfo", default=0,
                  action="store_true",
                  help="Show /proc/meminfo-like output")
    op.add_option("-p", "--percpu", dest="percpu", default="",
                  action="store", type="string",
                  help="Convert percpu address into virtual address")
    op.add_option("-t", "--type", dest="percpu_type", default="",
                  action="store", type="string",
                  help="Specify percpu type : u8, u16, u32, u64, s8, s16, s32, s64, int")
    op.add_option("-d", "--details", dest="details", default=0,
                  action="store_true",
                  help="Show detailed output")
    op.add_option("-v", "--vm", dest="vmshow", default=0,
                  action="store_true",
                  help="Show 'vm' output with more details")
    op.add_option("-e", "--error", dest="error_code", default="",
                  action="store",
                  type="string",
                  help="Interpret page_fault error code")
    op.add_option("-m", "--numa", dest="numa", default=0,
                  action="store_true",
                  help="Show NUMA info")

    (o, args) = op.parse_args()

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
        show_vm(o)
        sys.exit(0)


    if (o.error_code != ""):
        show_error_code(o)
        sys.exit(0)

    if (o.numa):
        show_numa_info(o)
        sys.exit(0)

    show_tasks_memusage(o)


if ( __name__ == '__main__'):
    meminfo()
