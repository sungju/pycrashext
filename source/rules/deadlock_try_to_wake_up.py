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
    return "Checking deadlock bug between update_blocked_averages() and try_to_wake_up()."


def add_rule(sysinfo):
    if sysinfo is None or "RELEASE" not in sysinfo:
        return True
    
    release = sysinfo["RELEASE"]
    if ("el8") in release:
        return True

    return False


def run_rule(sysinfo, log_str):
    try:
        result_bt_list = exec_crash_command("bt -a").split("PID:")
        found_bug_str = ""
        for one_bt_str in result_bt_list:
            if ("try_to_wake_up" or "update_blocked_averages") in one_bt_str:
                found_bug_str = "PID: " + one_bt_str
                break

        if found_bug_str == "":
            return None

        result_dict = {}
        result_dict["TITLE"] = "deadlock in runqueue bug detected by %s" % \
                                ntpath.basename(__file__)
        result_dict["MSG"] = "Below process was in deadlock:\n\n%s" % \
                found_bug_str
        result_dict["KCS_TITLE"] = "Deadlock scenario on CPU runqueue lock" \
                " between update_blocked_averages() and try_to_wake_up()."
        result_dict["KCS_URL"] = "https://access.redhat.com/solutions/6963258"
        result_dict["RESOLUTION"] = "Please upgrade kernel as specified in the KCS"

        return [result_dict]
    except Exception as e:
        print(e)
        return None



def deadlock_try_to_wake_up():
    import pprint
    pp = pprint.PrettyPrinter(indent=0, width=180)
    pp.pprint(run_rule(None, None))


if ( __name__ == '__main__'):
    deadlock_try_to_wake_up()
