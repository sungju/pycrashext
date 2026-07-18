"""
autocheck rule: detects NFS delegation panic.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import sys
import ntpath
import operator
import math

import rules_helper as rh


def is_major():
    return True


def description():
    return "NFS delegation kernel panic in kmem_cache_alloc_trace or __slab_free"


def add_rule(sysinfo):
    if sysinfo is None or "RELEASE" not in sysinfo:
        return True

    release = sysinfo["RELEASE"]
    # Applies to RHEL 8.10 and RHEL 9.7
    if ("el8_10" in release) or ("el9" in release):
        return True

    return False


def run_rule(basic_data):
    try:
        if basic_data == None:
            log_string = rh.get_data(basic_data, "log")
        else:
            log_string = basic_data["log_str"]

        # Check for primary signature: kmem_cache_alloc_trace panic with NFS delegation
        pos_kmem_cache_alloc = log_string.find("kmem_cache_alloc_trace+0x")
        pos_nfs_set_delegation = log_string.find("nfs_inode_set_delegation")
        pos_nfs_check_deleg = log_string.find("nfs4_opendata_check_deleg")

        # Check for alternative signature: __slab_free BUG with kfree_rcu_work
        pos_slab_free = log_string.find("__slab_free+0x")
        pos_slub_bug = log_string.find("kernel BUG at mm/slub.c:380")
        pos_kfree_rcu = log_string.find("kfree_rcu_work")

        # Check if either signature matches
        primary_match = (pos_kmem_cache_alloc >= 0 and
                        (pos_nfs_set_delegation >= 0 or pos_nfs_check_deleg >= 0))

        alternative_match = (pos_slab_free >= 0 and
                            pos_slub_bug >= 0 and
                            pos_kfree_rcu >= 0)

        if not (primary_match or alternative_match):
            return None

        # Find the beginning of the panic message
        if primary_match:
            pos_start = log_string.rfind('[', 0, pos_kmem_cache_alloc)
        else:
            pos_start = log_string.rfind('[', 0, pos_slub_bug)

        result_dict = {}
        result_dict["TITLE"] = "NFS delegation panic detected by %s" % \
                                ntpath.basename(__file__)
        result_dict["MSG"] = log_string[pos_start:]
        result_dict["KCS_TITLE"] = "A kernel panic is triggered in kmem_cache_alloc_trace() while executing nfs_inode_set_delegation(), or panics with 'kernel BUG at mm/slub.c:380!'"
        result_dict["KCS_URL"] = "https://access.redhat.com/solutions/7134523"
        result_dict["RESOLUTION"] = "RHEL 8: Upgrade to kernel-4.18.0-553.97.1.el8_10 or later (RHSA-2026:1142). RHEL 9: Bug report opened for RHEL 9.7. Workaround: Disable NFSv4 delegations on the server."
        result_dict["KERNELS"] = { "kernel-4.18.0-553.97.1.el8_10" }

        return [result_dict]
    except Exception as e:
        print(e)
        return None



def nfs_delegation_panic():
    import pprint
    pp = pprint.PrettyPrinter(indent=0, width=180)
    pp.pprint(run_rule(None))


if ( __name__ == '__main__'):
    nfs_delegation_panic()
