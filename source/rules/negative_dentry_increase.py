"""
 Written by Daniel Sungju Kwon
"""
import sys
import ntpath
import operator
import math

import rules_helper as rh


def get_dentry_objsize():
    """
    Parse 'kmem -S dentry' output to get dentry slab object size.
    Returns the objsize in bytes, or None on failure.
    """
    try:
        result_lines = rh.get_data(None, "kmem -S dentry").splitlines()
        header_found = False
        for line in result_lines:
            words = line.split()
            if not words:
                continue
            if words[0] == "CACHE":
                header_found = True
                continue
            if header_found and len(words) >= 2:
                try:
                    objsize = int(words[1])
                    if objsize > 0:
                        return objsize
                except ValueError:
                    continue
    except Exception:
        pass
    return None


def get_system_total_memory_kb():
    """
    Get total system memory in kB from meminfo or totalram_pages fallback.
    """
    try:
        import meminfo as mi
        mem_info = mi.get_meminfo()
        total = mem_info.get('MemTotal', 0)
        if total > 0:
            return total
    except Exception:
        pass
    try:
        import meminfo as mi
        totalram_pages = rh.get_symbol("totalram_pages")
        page_size = 1 << mi.get_page_shift()
        return (int(totalram_pages) * page_size) // 1024
    except Exception:
        pass
    return 0


def is_major():
    return True


def description():
    return "Checking negative dentry increase bug"


def add_rule(sysinfo):
    if sysinfo is None or "RELEASE" not in sysinfo:
        return True

    release = sysinfo["RELEASE"]
    if ("el7" in release or "el8" in release or "el9" in release):
        return True

    return False


NEGATIVE_DENTRY_PERCENT_THRESHOLD = 50
NEGATIVE_DENTRY_MEMORY_PERCENT_THRESHOLD = 33


def run_rule(basic_data):
    try:
        dentry_stat = rh.get_symbol("dentry_stat")
        nr_dentry   = int(dentry_stat.nr_dentry)
        nr_unused   = int(dentry_stat.nr_unused)
        age_limit   = int(dentry_stat.age_limit)
        want_pages  = int(dentry_stat.want_pages)
        nr_negative = int(dentry_stat.nr_negative)
        dummy       = int(dentry_stat.dummy)

        if nr_dentry == 0:
            return None

        negative_percent = (nr_negative / nr_dentry) * 100

        if negative_percent < NEGATIVE_DENTRY_PERCENT_THRESHOLD:
            return None

        sys_mem_pct  = None
        memory_info  = ""

        objsize = get_dentry_objsize()
        if objsize is not None and objsize > 0:
            memory_bytes = nr_negative * objsize
            system_total_kb    = get_system_total_memory_kb()
            system_total_bytes = system_total_kb * 1024

            mem_line = "\n  Estimated memory consumed by negative dentries: %s" \
                       " (%d bytes/dentry x %d dentries)" % \
                       (rh.get_size_str(memory_bytes), objsize, nr_negative)

            if system_total_bytes > 0:
                sys_mem_pct = (memory_bytes / system_total_bytes) * 100
                mem_line += "\n  System total memory                          : %s" % \
                            rh.get_size_str(system_total_bytes)
                mem_line += "\n  Negative dentries as %% of system memory      : %.2f%%" % \
                            sys_mem_pct

            memory_info = mem_line

        # Requires BOTH high dentry % AND significant memory pressure
        if sys_mem_pct is not None and sys_mem_pct < NEGATIVE_DENTRY_MEMORY_PERCENT_THRESHOLD:
            return None

        result_dict = {}
        result_dict["TITLE"] = "Negative dentry increase bug detected by %s" % \
                                ntpath.basename(__file__)
        result_dict["MSG"] = \
            "Negative dentry leak detected (%.1f%% of total dentries)%s\n\n" \
            "dentry_stat:\n" \
            "  nr_dentry   : %d\n" \
            "  nr_unused   : %d\n" \
            "  age_limit   : %d\n" \
            "  want_pages  : %d\n" \
            "  nr_negative : %d (%.1f%% of nr_dentry)\n" \
            "  dummy       : %d\n\n" \
            "This indicates a negative dentry leak issue." % \
            (negative_percent, memory_info,
             nr_dentry, nr_unused, age_limit,
             want_pages, nr_negative, negative_percent, dummy)
        result_dict["KCS_TITLE"] = "Negative dentry increase causing memory pressure"
        result_dict["KCS_URL"]   = "https://access.redhat.com/solutions/7086240"
        result_dict["RESOLUTION"] = "Please upgrade kernel as specified in the KCS"
        result_dict["KERNELS"] = {
            "kernel-5.14.0-503.11.1.el9_5",
            "kernel-5.14.0-427.40.1.el9_4",
            "kernel-5.14.0-284.90.1.el9_2",
            "kernel-4.18.0-553.22.1.el8_10",
            "kernel-4.18.0-477.75.1.el8_8",
        }

        return [result_dict]
    except Exception as e:
        print(e)
        return None


def negative_dentry_increase():
    import pprint
    pp = pprint.PrettyPrinter(indent=0, width=180)
    pp.pprint(run_rule(None))


if __name__ == '__main__':
    negative_dentry_increase()
