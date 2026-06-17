"""
 Written by Daniel Sungju Kwon
"""
import sys
import ntpath

import rules_helper as rh


def is_major():
    return True


def description():
    return "Checking vmtoolsd deadlock due to frozen filesystem"


def add_rule(sysinfo):
    if sysinfo is None or "RELEASE" not in sysinfo:
        return True

    release = sysinfo["RELEASE"]
    if ("el7" in release or "el8" in release or "el9" in release):
        return True

    return False


# Stack frames that confirm the frozen-filesystem write deadlock
_FROZEN_FRAMES  = ("__sb_start_write", "percpu_rwsem_wait", "__percpu_down_read")
_WRITE_FRAMES   = ("vfs_write", "ksys_write")


def _pid_from_ps_line(line):
    """Extract PID from a 'ps -m' [UN] line."""
    try:
        idx = line.find("PID:")
        if idx < 0:
            return None
        return line[idx + 4:].split()[0]
    except Exception:
        return None


def _check_vmtoolsd_deadlock(basic_data):
    """
    Return a list of (pid, bt_snippet) for every vmtoolsd thread that is
    blocked in __sb_start_write (frozen-filesystem write deadlock).
    """
    hits = []
    try:
        ps_output = rh.get_data(basic_data, "ps -m")
    except Exception:
        return hits

    for line in ps_output.splitlines():
        # Only UN-state vmtoolsd threads
        if "[UN]" not in line or "vmtoolsd" not in line:
            continue
        pid = _pid_from_ps_line(line)
        if not pid:
            continue

        try:
            bt = rh.get_data(basic_data, "bt %s" % pid)
        except Exception:
            continue

        has_frozen = any(f in bt for f in _FROZEN_FRAMES)
        has_write  = any(f in bt for f in _WRITE_FRAMES)

        if has_frozen and has_write:
            hits.append((pid, bt))

    return hits


def run_rule(basic_data):
    hits = _check_vmtoolsd_deadlock(basic_data)
    if not hits:
        return None

    pid_list  = [pid for pid, _ in hits]
    bt_sample = hits[-1][1]   # show the last (longest-running) backtrace

    msg = (
        "vmtoolsd (PID %s) is blocked in vfs_write waiting on a frozen\n"
        "superblock write-lock (__sb_start_write / percpu_rwsem_wait).\n\n"
        "This is a self-deadlock: vmtoolsd froze the filesystem for a\n"
        "VMware snapshot quiescing operation, then tried to write its own\n"
        "log file (/var/log/vmware-vmsvc-root.log) to that same frozen\n"
        "filesystem — causing it to wait indefinitely for itself.\n\n"
        "Affected vmtoolsd PID(s): %s\n\n"
        "Backtrace:\n%s"
    ) % (pid_list[0], ", ".join(pid_list), bt_sample)

    resolution = (
        "Add the following to /etc/vmware-tools/tools.conf and restart the VM:\n\n"
        "  [vmbackup]\n"
        "  ignoreFrozenFileSystems=true\n\n"
        "  [logging]\n"
        "  vmsvc.level = none\n\n"
        "  ignoreFrozenFileSystems=true  — skip filesystems that are already\n"
        "    frozen during the quiescing operation.\n"
        "  vmsvc.level = none  — disable vmtoolsd log-file writes that trigger\n"
        "    the deadlock."
    )

    result_dict = {}
    result_dict["TITLE"]      = "vmtoolsd frozen-filesystem deadlock detected by %s" % \
                                 ntpath.basename(__file__)
    result_dict["MSG"]        = msg
    result_dict["KCS_TITLE"]  = "A deadlock-like hang occurring during the snapshot " \
                                 "operation by vmtoolsd for backup purposes"
    result_dict["KCS_URL"]    = "https://access.redhat.com/solutions/7089292"
    result_dict["RESOLUTION"] = resolution

    return [result_dict]


def vmtoolsd_frozen_fs_deadlock():
    import pprint
    pp = pprint.PrettyPrinter(indent=0, width=180)
    pp.pprint(run_rule(None))


if __name__ == '__main__':
    vmtoolsd_frozen_fs_deadlock()
