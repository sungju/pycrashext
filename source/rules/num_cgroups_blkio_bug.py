"""
 Written by Daniel Sungju Kwon
"""
import sys
import ntpath
import operator
import math

import rules_helper as rh


def is_major():
    return True


def description():
    return "Checking num_cgroups bug"


def add_rule(sysinfo):
    if sysinfo is None or "RELEASE" not in sysinfo:
        return True
    
    release = sysinfo["RELEASE"]
    if ("el8" or "el9") in release:
        return True

    return False


def get_total_physical_mem_kb():
    try:
        if rh.is_symbol_exists("totalram_pages"):
            totalram_pages = rh.get_symbol("totalram_pages")
        elif rh.is_symbol_exists("_totalram_pages"):
            totalram_pages = rh.get_symbol("_totalram_pages").counter
        else:
            totalram_pages = 0
    except:
        totalram_pages = 0

    return totalram_pages * 4


BUG_CONSIDER_PERCENT = 50 # Not scientific number, but 50% sounds reasonable

def run_rule(basic_data):
    try:
        pcpu_nr_populated = rh.get_symbol("pcpu_nr_populated")
        pcpu_nr_units = rh.get_symbol("pcpu_nr_units")
        total_used_kb = pcpu_nr_populated * pcpu_nr_units * 4
        total_physical_mem_kb = get_total_physical_mem_kb()
        used_percent = (total_used_kb / total_physical_mem_kb) * 100

        if used_percent < BUG_CONSIDER_PERCENT:
            return None

        result_dict = {}
        result_dict["TITLE"] = "num_cgroups bug detected by %s" % \
                                ntpath.basename(__file__)
        result_dict["MSG"] = "(pcpu_nr_populated * pcpu_nr_units) * " \
                "page\n\t%s (%d %%) out of %s" % \
                (rh.get_size_str(total_used_kb * 1024), \
                 used_percent, \
                 rh.get_size_str(total_physical_mem_kb * 1024))
        result_dict["KCS_TITLE"] = "The num_cgroups for blkio in cgroups keeps increasing"
        result_dict["KCS_URL"] = "https://access.redhat.com/solutions/7014337"
        result_dict["RESOLUTION"] = "Please upgrade kernel as specified in the KCS"
        result_dict["KERNELS"] = {
                "kernel-5.14.0-362.8.1.el9_3",
                "kernel-5.14.0-284.40.1.el9_2",
                "kernel-4.18.0-513.5.1.el8_9",
                "kernel-4.18.0-477.21.1.el8_8",
                "kernel-4.18.0-372.70.1.el8_6",
                "kernel-4.18.0-372.70.1.el8_6" }

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
