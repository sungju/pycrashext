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
    return "Checking delay in nft_rbtree_walk()."


def add_rule(sysinfo):
    if sysinfo is None or "RELEASE" not in sysinfo:
        return True
    
    release = sysinfo["RELEASE"]
    if ("el8") in release:
        return True

    return False


def run_rule(basic_data):
    try:
        result_bt_list = basic_data["bt_a"]
        found_bug_str = ""
        for one_bt_str in result_bt_list:
            if ("split_swap_cluster") in one_bt_str:
                found_bug_str = "PID: " + one_bt_str
                break

        if found_bug_str == "":
            return None

        result_dict = {}
        result_dict["TITLE"] = "Possible split_swap_cluster() crash bug detected by %s" % \
                                ntpath.basename(__file__)
        result_dict["MSG"] = "Below process was crashed in split_swap_cluster():\n\n%s" % \
                found_bug_str
        result_dict["KCS_TITLE"] = "RHEL8: Kernel panics in split_swap_cluster() routine"
        result_dict["KCS_URL"] = "https://access.redhat.com/solutions/5830301"
        result_dict["RESOLUTION"] = "Please upgrade kernel as specified in the KCS"
        result_dict["KERNELS"] = { "kernel-4.18.0-305.el8",
                                  "kernel-4.18.0-193.100.1.el8_2" }

        return [result_dict]
    except Exception as e:
        print(e)
        return None



def check_issue():
    import pprint
    pp = pprint.PrettyPrinter(indent=0, width=180)
    pp.pprint(run_rule(None))


if ( __name__ == '__main__'):
    check_issue()
