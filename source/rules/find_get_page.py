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


def is_major():
    return True


def description():
    return "Checking find_get_page() bug in the system"


def add_rule(sysinfo):
    if sysinfo is None or "RELEASE" not in sysinfo:
        return True

    if sysinfo["RELEASE"].startswith("2.6.32-696.20.1.el6"):
        return True

    return False

def run_rule(basic_data):
    if basic_data == None:
        result = exec_crash_command("log")
    else:
        result = basic_data["log_str"]

    idx = result.find("find_get_page+0x")
    if idx == -1:
        return None

    result_dict = {}
    result_dict["TITLE"] = "find_get_page() softlockup BZ detected by %s" % \
                            ntpath.basename(__file__)
    startidx = max(idx - 380, 0)
    endidx = min(idx + 800, len(result))
    result_dict["MSG"] = result[startidx:endidx]
    result_dict["KCS_TITLE"] = "softlockup in find_get_pages after installing kernel-2.6.32-696.23.1"
    result_dict["KCS_URL"] = "https://access.redhat.com/solutions/3390081"
    result_dict["RESOLUTION"] = "Upgrade kernel to kernel-2.6.32-754.el6 or later version"

    return [result_dict]

def find_get_page():
    run_rule(None)

if ( __name__ == '__main__'):
    find_get_page()
