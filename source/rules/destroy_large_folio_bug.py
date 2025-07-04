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
    return "RHEL 9.6: list corruption detected during large folio migration"


def add_rule(sysinfo):
    if sysinfo is None or "RELEASE" not in sysinfo:
        return True

    release = sysinfo["RELEASE"]
    if ("el9") in release:
        return True

    return False


def run_rule(basic_data):
    try:
        if basic_data == None:
            log_string = rh.get_data(basic_data, "log")
        else:
            log_string = basic_data["log_str"]

        large_rmappable_string = log_string.find("deferred_split_folio+0x")
        if large_rmappable_string < 0:
            large_rmappable_string = log_string.find("__folio_undo_large_rmappable+0x")
        large_rmappable_string = log_string.find("deferred_split_folio+0x")
        list_corruption_string = log_string.find("kernel BUG at lib/list_debug")

        if list_corruption_string < 0 or large_rmappable_string < 0:
            return None

        crash_msg = log_string.rfind('[', 0, list_corruption_string)

        result_dict = {}
        result_dict["TITLE"] = "crashed with list corruption during large folio migration"\
                               " bug\n\tdetected by %s" % \
                                ntpath.basename(__file__)
        result_dict["MSG"] = log_string[crash_msg:]
        result_dict["KCS_TITLE"] = "Kernel panic with list corruption detected during large folio migration"
        result_dict["KCS_URL"] = "https://access.redhat.com/solutions/7121871"
        result_dict["RESOLUTION"] = "Please upgrade kernel as specified in the KCS"
        result_dict["KERNELS"] = { "kernel-5.14.0-570.22.1.el9_6", }

        return [result_dict]
    except Exception as e:
        print(e)
        return None



def destroy_large_folio_bug():
    import pprint
    pp = pprint.PrettyPrinter(indent=0, width=180)
    pp.pprint(run_rule(None))


if ( __name__ == '__main__'):
    destroy_large_folio_bug()
