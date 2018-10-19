"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *

from LinuxDump import Tasks

import sys
import operator

import crashcolor
import pstree
import crashhelper
from datetime import datetime, timedelta

'''
/*
 * A security context consists of an authenticated user
 * identity, a role, a type and a MLS range.
 */
struct context {
    u32 user;
    u32 role;
    u32 type;
    u32 len;        /* length of string in bytes */
    struct mls_range range;
    char *str;  /* string representation if context cannot be mapped. */
};


#define SIDTAB_HASH_BITS 7
#define SIDTAB_HASH_BUCKETS (1 << SIDTAB_HASH_BITS)
#define SIDTAB_HASH_MASK (SIDTAB_HASH_BUCKETS-1)

#define SIDTAB_SIZE SIDTAB_HASH_BUCKETS


    SIDTAB_SIZE == 128
'''

SIDTAB_SIZE=128


def get_sidtab_node_detail(sidtab_node, isprint):
    result = "%s" % (exec_crash_command("struct sidtab_node 0x%x" % sidtab_node))
    if isprint:
        print(result)

    return result


def get_sidtab_info(total_only, print_detail, is_print):
    result = ""
    total_count = 0
    entry_count = 0

    sidtab = readSymbol("sidtab")
    if sidtab == None or sidtab == 0:
        result = "No sidtab symbol found"
        if is_print:
            print(result)
        return result

    for sidtab_node in sidtab.htable:
        count = 0
        if entry_count >= SIDTAB_SIZE:
            break
        entry_count = entry_count + 1

        sidtab_node_orig = sidtab_node
        while sidtab_node != None and sidtab_node != 0:
            if print_detail:
                result = result + get_sidtab_node_detail(sidtab_node, is_print) + "\n"

            sidtab_node = sidtab_node.next
            count = count + 1
        total_count = total_count + count
        if not total_only:
            entry_str = "struct sidtab_node 0x%x has %d entries" % (sidtab_node_orig, count)
            if is_print:
                print(entry_str)
            result = result + entry_str + "\n"

    result_str = "Total sidtab_node entries = %d" % (total_count)
    if is_print:
        print(result_str)
    result  = result + result_str + "\n"

    return result

def seinfo():
    op = OptionParser()
    op.add_option("--sidtab", dest="sidtab", default=0,
                  action="store_true",
                  help="Shows sidtab information")
    op.add_option("--total", dest="total", default=0,
                  action="store_true",
                  help="Show total")
    op.add_option("--detail", dest="detail", default=0,
                  action="store_true",
                  help="Show details")

    (o, args) = op.parse_args()

    if (o.sidtab):
        get_sidtab_info(o.total, o.detail, True)
        sys.exit(0)


if ( __name__ == '__main__'):
    seinfo()
