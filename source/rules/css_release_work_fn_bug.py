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
    return "RHEL 8.4: kernel crashed due to list_del corruption with LIST_POISON2"


def add_rule(sysinfo):
    if sysinfo is None or "RELEASE" not in sysinfo:
        return True
    
    release = sysinfo["RELEASE"]
    if ("el8") in release:
        return True

    return False


def run_rule(basic_data):
    try:
        if basic_data == None:
            log_string = exec_crash_command("log")
        else:
            log_string = basic_data["log_str"]
        pos_list_corruption = log_string.find("list_del corruption,")
        pos_css_release_work_fn = log_string.find("css_release_work_fn+0x")

        if pos_list_corruption < 0 or pos_css_release_work_fn < 0:
            return None

        pos_list_corruption = log_string.rfind('[', 0, pos_list_corruption)

        result_dict = {}
        result_dict["TITLE"] = "list_del corruption bug detected by %s" % \
                                ntpath.basename(__file__)
        result_dict["MSG"] = log_string[pos_list_corruption:]
        result_dict["KCS_TITLE"] = "RHEL 8.4: kernel crashed due to list_del corruption with LIST_POISON2"
        result_dict["KCS_URL"] = "https://access.redhat.com/solutions/6094611"
        result_dict["RESOLUTION"] = "Please upgrade kernel as specified in the KCS"

        return [result_dict]
    except Exception as e:
        print(e)
        return None



def css_release_work_fn_bug():
    import pprint
    pp = pprint.PrettyPrinter(indent=0, width=180)
    pp.pprint(run_rule(None))


if ( __name__ == '__main__'):
    css_release_work_fn_bug()
