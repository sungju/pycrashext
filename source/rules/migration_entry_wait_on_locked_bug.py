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
    return "RHEL 8.8: hung_task_timeout_secs at migration_entry_wait_on_locked"


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
            log_string = rh.get_data(basic_data, "log")
        else:
            log_string = basic_data["log_str"]
        migration_entry_wait_on_locked = log_string.find("migration_entry_wait_on_locked+0x")
        hung_task_msg = log_string.rfind("INFO: task ")

        if hung_task_msg < 0 or migration_entry_wait_on_locked < 0:
            return None

        hung_task_msg = log_string.rfind('[', 0, hung_task_msg)

        result_dict = {}
        result_dict["TITLE"] = "system hang in migration_entry_wait_on_locked()"\
                               " bug\n\tdetected by %s" % \
                                ntpath.basename(__file__)
        result_dict["MSG"] = log_string[hung_task_msg:]
        result_dict["KCS_TITLE"] = "RHEL 8.8: hung_task_timeout_secs at " \
                                    "migration_entry_wait_on_locked"
        result_dict["KCS_URL"] = "https://access.redhat.com/solutions/7014646"
        result_dict["RESOLUTION"] = "Please upgrade kernel as specified in the KCS"
        result_dict["KERNELS"] = { "kernel-4.18.0-477.13.1.el8_8",
                                  "kernel-4.18.0-372.96.1.el8_6.x86_64" }

        return [result_dict]
    except Exception as e:
        print(e)
        return None



def migration_entry_wait_on_locked_bug():
    import pprint
    pp = pprint.PrettyPrinter(indent=0, width=180)
    pp.pprint(run_rule(None))


if ( __name__ == '__main__'):
    migration_entry_wait_on_locked_bug()
