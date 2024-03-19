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
            if ("nft_rbtree_walk") in one_bt_str:
                found_bug_str = "PID: " + one_bt_str
                break

        if found_bug_str == "":
            return None

        result_dict = {}
        result_dict["TITLE"] = "Possible nft_rbtree_walk() delay detected by %s" % \
                                ntpath.basename(__file__)
        result_dict["MSG"] = "Below process was running in nft_rbtree_walk():\n\n%s" % \
                found_bug_str
        result_dict["KCS_TITLE"] = "RHEL 8.9: Long nftables command "\
                "runtime with large ruleset and IP sets"
        result_dict["KCS_URL"] = "https://access.redhat.com/solutions/7058369"
        result_dict["RESOLUTION"] = "Please check KCS for the resolution"

        return [result_dict]
    except Exception as e:
        print(e)
        return None



def nft_rbtree_walk_delay():
    import pprint
    pp = pprint.PrettyPrinter(indent=0, width=180)
    pp.pprint(run_rule(None))


if ( __name__ == '__main__'):
    nft_rbtree_walk_delay()
