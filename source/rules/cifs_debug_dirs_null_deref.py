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
    return "RHEL 9: NULL pointer dereference in cifs_debug_dirs_proc_show when reading /proc/fs/cifs/open_dirs"


def add_rule(sysinfo):
    if sysinfo is None or "RELEASE" not in sysinfo:
        return True

    release = sysinfo["RELEASE"]
    # Applies to RHEL 9.6 and 9.7
    if ("el9") in release:
        return True

    return False


def run_rule(basic_data):
    try:
        if basic_data is None:
            log_string = rh.get_data(basic_data, "log")
        else:
            log_string = basic_data["log_str"]

        # Primary signature: cifs_debug_dirs_proc_show in call trace
        pos_cifs_debug = log_string.find("cifs_debug_dirs_proc_show")

        # Check for NULL pointer dereference indicators
        # x86_64: "BUG: kernel NULL pointer dereference"
        # aarch64: "Unable to handle kernel NULL pointer dereference"
        # Also check for CR2: 0000000000000000 (x86_64 specific)
        pos_null_deref = log_string.find("BUG: kernel NULL pointer dereference")
        if pos_null_deref < 0:
            pos_null_deref = log_string.find("Unable to handle kernel NULL pointer dereference")
        pos_cr2_null = log_string.find("CR2: 0000000000000000")

        # Check for _raw_spin_lock in RIP (typical crash location)
        pos_raw_spin_lock = log_string.find("_raw_spin_lock+0x")

        # Must have cifs_debug_dirs_proc_show and at least one NULL deref indicator
        has_cifs_debug = pos_cifs_debug >= 0
        has_null_deref = pos_null_deref >= 0 or pos_cr2_null >= 0
        has_spin_lock = pos_raw_spin_lock >= 0

        if not (has_cifs_debug and has_null_deref):
            return None

        # Find the beginning of the panic message
        # Search backward for the start of a kernel message (newline + '[')
        # to ensure we capture the complete panic context from the beginning
        if pos_null_deref >= 0:
            start_pos = log_string.rfind('\n[', 0, pos_null_deref)
        elif pos_cr2_null >= 0:
            start_pos = log_string.rfind('\n[', 0, pos_cr2_null)
        else:
            start_pos = log_string.rfind('\n[', 0, pos_cifs_debug)

        if start_pos < 0:
            start_pos = 0
        else:
            start_pos += 1  # Skip the newline to start at '['

        # Find end of panic trace
        # The kernel panic trace ends with '---[ end trace' marker
        # We need to capture everything including:
        # - Initial BUG/NULL pointer dereference message
        # - Register dump (RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, R8-R15)
        # - RIP information (exception RIP)
        # - Complete Call Trace with all stack frames
        # - Modules linked in section
        # - CR2 register value
        # - End trace marker
        end_trace_pos = log_string.find('---[ end trace', start_pos)
        if end_trace_pos >= 0:
            # Find the end of the line containing the end marker
            end_pos = log_string.find('\n', end_trace_pos)
            if end_pos >= 0:
                end_pos += 1  # Include the newline

                # Capture any additional panic-related context after the end marker
                # (sometimes CR2 or other info appears after the end trace line)
                for _ in range(10):  # Check up to 10 lines ahead
                    next_line_end = log_string.find('\n', end_pos)
                    if next_line_end < 0:
                        break
                    next_line = log_string[end_pos:next_line_end]
                    # Include lines that are still part of the panic context
                    if (next_line.strip() and
                        (next_line.lstrip().startswith('[') and
                         ('CR2:' in next_line or 'Kernel panic' in next_line or
                          'RIP:' in next_line or 'RSP:' in next_line))):
                        end_pos = next_line_end + 1
                    else:
                        break
            else:
                end_pos = len(log_string)
        else:
            # No end trace marker found - capture a large chunk to ensure
            # we get all the diagnostic context (Call Trace, registers, modules)
            # Look for the next unrelated kernel message or capture up to 10000 chars
            next_msg_pos = log_string.find('\n[', start_pos + 1)
            if next_msg_pos >= 0:
                # Check if the next message is far enough away to likely be unrelated
                # If it's close, it might still be part of the panic trace
                if next_msg_pos - start_pos > 500:
                    end_pos = next_msg_pos + 1
                else:
                    # Keep searching for a more distant message
                    temp_pos = next_msg_pos
                    while temp_pos >= 0 and temp_pos - start_pos < 5000:
                        temp_pos = log_string.find('\n[', temp_pos + 1)
                    end_pos = temp_pos + 1 if temp_pos >= 0 else min(len(log_string), start_pos + 10000)
            else:
                # No next message found - capture up to 10000 chars to ensure complete context
                end_pos = min(len(log_string), start_pos + 10000)

        result_dict = {}
        result_dict["TITLE"] = "CIFS cifs_debug_dirs_proc_show NULL pointer dereference detected by %s" % \
                                ntpath.basename(__file__)
        result_dict["MSG"] = log_string[start_pos:end_pos]
        result_dict["KCS_TITLE"] = "RHEL 9: NULL pointer dereference in cifs_debug_dirs_proc_show() " \
                                   "when sos report runs on system with CIFS mounts"
        result_dict["KCS_URL"] = "https://access.redhat.com/solutions/7135230"
        result_dict["RESOLUTION"] = "RHEL 9.7: Upgrade to kernel-5.14.0-611.24.1.el9_7 or later (RHSA-2026:1764). " \
                                   "RHEL 9.6: Upgrade to kernel-5.14.0-570.79.1.el9_6 or later (RHSA-2026:1765). " \
                                   "Workaround: Avoid running 'sos report' or reading /proc/fs/cifs/open_dirs when CIFS mounts are active."
        result_dict["KERNELS"] = {
            "kernel-5.14.0-611.24.1.el9_7",
            "kernel-5.14.0-570.79.1.el9_6"
        }

        return [result_dict]
    except Exception as e:
        print(e)
        return None



def cifs_debug_dirs_null_deref():
    import pprint
    pp = pprint.PrettyPrinter(indent=0, width=180)
    pp.pprint(run_rule(None))


if (__name__ == '__main__'):
    cifs_debug_dirs_null_deref()
