"""
autocheck rule: on an OOM, a module's code has allocated a large share of
memory (vmalloc areas and slab caches it created).

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import ntpath
import re

import modinfo
import rules_helper as rh

SHARE = 0.05        # of total RAM


def is_major():
    return True


def description():
    return "Checking, on an OOM, for modules holding a large share of memory"


def add_rule(sysinfo):
    return True


def total_ram_bytes():
    """TOTAL MEM from 'kmem -i', in bytes; 0 when it can't be read."""
    for line in rh.get_data(None, "kmem -i").splitlines():
        m = re.match(r'^\s*TOTAL MEM\s+(\d+)', line)
        if m:
            return int(m.group(1)) * rh.get_page_size()
    return 0


def run_rule(basic_data):
    try:
        log_str = basic_data.get("log_str", "") if basic_data else ""
        if not re.search(r'Out of memory|oom-kill|invoked oom-killer', log_str):
            return None
        total = total_ram_bytes()
        if total == 0:
            return None
        ranges = modinfo.code_ranges()
        areas = modinfo.module_areas()
        vmalloc = modinfo.vmalloc_by_module(ranges, areas)
        slabs = modinfo.slab_caches_by_module(ranges, areas)
        heavy = []
        for name in set(vmalloc) | set(slabs):
            vbytes = sum(size for _, size in vmalloc.get(name, []))
            sbytes = sum((modinfo.cache_usage(addr) or (0, 0, 0))[2]
                         for addr, _ in slabs.get(name, []))
            if vbytes + sbytes >= total * SHARE:
                heavy.append((vbytes + sbytes, name, vbytes, sbytes))
        if not heavy:
            return None
        heavy.sort(reverse=True)

        lines = ["%-20s %10s  (%.1f%% of %s: vmalloc %s, slab %s)" % (
                     name, rh.get_size_str(both), 100.0 * both / total,
                     rh.get_size_str(total), rh.get_size_str(vbytes), rh.get_size_str(sbytes))
                 for both, name, vbytes, sbytes in heavy]
        result_dict = {}
        result_dict["TITLE"] = "modules holding over %d%% of memory at an OOM, detected by %s" % (
            int(SHARE * 100), ntpath.basename(__file__))
        result_dict["MSG"] = "\n".join(lines + ["", "'modinfo --mem <module>' shows the"
                                                " allocating functions and caches."])
        result_dict["KCS_TITLE"] = "Red Hat support for third-party kernel modules"
        result_dict["KCS_URL"] = "https://access.redhat.com/third-party-software-support"
        result_dict["RESOLUTION"] = "Check with the module's vendor whether this much memory" \
                                    " is expected, or a leak; compare with the same" \
                                    " module's usage on a healthy system."
        result_dict["KERNELS"] = ["Depends on the module"]
        return [result_dict]
    except Exception as e:
        print(e)
        return None


if (__name__ == '__main__'):
    import pprint
    pprint.PrettyPrinter(indent=0, width=180).pprint(run_rule(None))
