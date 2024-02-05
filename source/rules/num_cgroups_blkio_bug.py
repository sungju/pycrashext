"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *

from LinuxDump import Tasks

import sys
import ntpath
import operator
import math

import crashhelper
import meminfo


def description():
    return "Checking hung tasks"


def add_rule(sysinfo):
    return True


def get_total_physical_mem_kb():
    try:
        if symbol_exists("totalram_pages"):
            totalram_pages = readSymbol("totalram_pages")
        elif symbol_exists("_totalram_pages"):
            totalram_pages = readSymbol("_totalram_pages").counter
        else:
            totalram_pages = 0
    except:
        totalram_pages = 0

    return totalram_pages * 4


def run_rule(sysinfo):
    try:
        pcpu_nr_populated = readSymbol("pcpu_nr_populated")
        pcpu_nr_units = readSymbol("pcpu_nr_units")
        total_used_kb = pcpu_nr_populated * pcpu_nr_units * 4
        total_physical_mem_kb = get_total_physical_mem_kb()

        result_dict = {}
        result_dict["TITLE"] = "num_cgroups bug detected by %s" % \
                                ntpath.basename(__file__)
        result_dict["MSG"] = "(pcpu_nr_populated * pcpu_nr_units) * " \
                "page\n\t%s (%d %%) out of %s" % \
                (meminfo.get_size_str(total_used_kb * 1024), \
                 (total_used_kb / total_physical_mem_kb) * 100, \
                 meminfo.get_size_str(total_physical_mem_kb * 1024))
        result_dict["KCS_TITLE"] = "The num_cgroups for blkio in cgroups keeps increasing"
        result_dict["KCS_URL"] = "https://access.redhat.com/solutions/7014337"
        result_dict["RESOLUTION"] = "Please upgrade kernel as specified in the KCS"

        return [result_dict]
    except Exception as e:
        print(e)
        return None



def num_cgroups_blkio_bug():
    import pprint
    pp = pprint.PrettyPrinter(indent=0, width=180)
    pp.pprint(run_rule(None))


if ( __name__ == '__main__'):
    num_cgroups_blkio_bug()
