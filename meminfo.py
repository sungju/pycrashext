"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *

from LinuxDump import Tasks

import sys
import operator

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

    print("%40s %25s" % ("[ Process name ] ", " [ RSS usage ] "))
    print("=" * 70)
    min_number = 10
    if (options.all):
        min_number = len(sorted_usage) - 1

    for i in range(0, min(len(sorted_usage) - 1, min_number)):
        print("%40s %20s KiB" %
                (sorted_usage[i][0], sorted_usage[i][1]))

    print("=" * 70)
    print("Total memory usage from user-space = %.2f GiB" %
          (total_rss/1048576))


def show_slabtop(options):
    result = exec_crash_command("kmem -s")
    result_lines = result.splitlines(True)
    slab_list = {}
    for i in range(1, len(result_lines) -1):
        result_line = result_lines[i].split()
        if (len(result_line) < 7):
            continue
        result_line[6] = result_line[6].replace("k", "")
        total_used = int(result_line[5]) * int(result_line[6])
        slab_list[result_line[0]] = total_used

    sorted_slabtop = sorted(slab_list.items(),
                            key=operator.itemgetter(1), reverse=True)
    min_number = 10
    if (options.all):
        min_number = len(sorted_slabtop) - 1

    print("=" * 68)
    print("%-18s %-30s %10s %7s" %
          ("kmem_cache", "NAME", "TOTAL", "OBJSIZE"))
    print("=" * 68)
    for i in range(0, min(len(sorted_slabtop) - 1, min_number)):
        kmem_cache = readSU("struct kmem_cache",
                            int(sorted_slabtop[i][0], 16))

        print("0x%16s %-30s %9sK %7d" %
                (sorted_slabtop[i][0],
                 kmem_cache.name,
                 sorted_slabtop[i][1],
                 kmem_cache.buffer_size))

    print("=" * 68)


def meminfo():
    op = OptionParser()
    op.add_option("--memusage", dest="memusage", default=0,
                  action="store_true",
                  help="Show memory usages by tasks")
    op.add_option("--nogroup", dest="nogroup", default=0,
                  action="store_true",
                  help="Show data in individual tasks")
    op.add_option("--all", dest="all", default=0,
                  action="store_true",
                  help="Show all the output")
    op.add_option("--slabtop", dest="slabtop", default=0,
                  action="store_true",
                  help="Show slabtop-like output")

    (o, args) = op.parse_args()

    if (o.memusage):
        show_tasks_memusage(o)

    if (o.slabtop):
        show_slabtop(o)

if ( __name__ == '__main__'):
    meminfo()
