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
    return "RHEL 8: kernel crashed due to refcount_t overflow in mem_cgroup_id_get_online"


def add_rule(sysinfo):
    if sysinfo is None or "RELEASE" not in sysinfo:
        return True

    release = sysinfo["RELEASE"]
    if ("el8") in release:
        return True

    return False


def run_rule(basic_data):
    try:
        if basic_data is None:
            log_string = rh.get_data(basic_data, "log")
        else:
            log_string = basic_data["log_str"]

        # Primary detection: refcount_t overflow at mem_cgroup_id_get_online
        pos_refcount_overflow = log_string.find("refcount_t overflow at mem_cgroup_id_get_online")

        # Secondary detection: general protection fault in memcg_flush_lruvec_page_state
        pos_gpf_memcg = log_string.find("general protection fault")
        pos_memcg_flush = log_string.find("memcg_flush_lruvec_page_state")

        primary_match = pos_refcount_overflow >= 0
        secondary_match = pos_gpf_memcg >= 0 and pos_memcg_flush >= 0

        if not primary_match and not secondary_match:
            return None

        # Additional validation for primary: check for refcount_error_report in RIP or call trace
        pos_refcount_error = log_string.find("refcount_error_report")
        pos_ex_handler = log_string.find("ex_handler_refcount")

        if primary_match and pos_refcount_error < 0 and pos_ex_handler < 0:
            return None

        if primary_match:
            start_pos = log_string.rfind('[', 0, pos_refcount_overflow)
            if start_pos < 0:
                start_pos = pos_refcount_overflow
        else:
            start_pos = log_string.rfind('[', 0, pos_gpf_memcg)
            if start_pos < 0:
                start_pos = pos_gpf_memcg

        # Find where this panic/oops block ends - look for end trace marker first
        end_trace_pos = log_string.find('---[ end trace', start_pos)
        if end_trace_pos >= 0:
            # Found end trace marker, include the entire line
            end_pos = log_string.find('\n', end_trace_pos)
            if end_pos >= 0:
                end_pos += 1  # Include the newline
            else:
                end_pos = len(log_string)
        else:
            # No end trace marker, look for next kernel message
            end_pos = log_string.find('\n[', start_pos + 1)
            if end_pos >= 0:
                end_pos += 1  # Include the newline
            else:
                end_pos = len(log_string)

        result_dict = {}
        result_dict["TITLE"] = "refcount_t overflow bug detected by %s" % \
                                ntpath.basename(__file__)
        result_dict["MSG"] = log_string[start_pos:end_pos]
        result_dict["KCS_TITLE"] = "RHEL 8: kernel crashed due to refcount_t overflow " \
                                   "in mem_cgroup_id_get_online"
        result_dict["KCS_URL"] = "https://access.redhat.com/solutions/7014133"
        result_dict["RESOLUTION"] = "Please upgrade kernel as specified in the KCS"
        result_dict["KERNELS"] = {
            "kernel-4.18.0-305.103.1.el8_4",
            "kernel-4.18.0-372.70.1.el8_6",
            "kernel-4.18.0-477.27.1.el8_8",
            "kernel-4.18.0-513.5.1.el8_9",
        }

        return [result_dict]
    except Exception as e:
        print(e)
        return None


def refcount_overflow():
    import pprint
    pp = pprint.PrettyPrinter(indent=0, width=180)
    pp.pprint(run_rule(None))


if (__name__ == '__main__'):
    refcount_overflow()
