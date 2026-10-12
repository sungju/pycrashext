"""
Filesystem freezes: which tasks wait behind a frozen filesystem, which task
is freezing or thawing one, and what the logs say about the agents that
freeze filesystems for snapshots and backups (VMware Tools, qemu-guest-agent,
the Hyper-V VSS daemon).

A quiesced snapshot freezes every filesystem (FIFREEZE) and thaws it when
the snapshot is taken.  If the thaw never comes, every writer blocks in
sb_start_write and the hung-task watchdog reports them, which looks like a
storage stall but is not one.

Used by pycrashext 'fsinfo --frozen' on a vmcore and by isos 'freezeinfo'
on a sosreport; an identical copy lives in pycrashext and in isos
(source/fsfreeze.py).  Also runs on saved logs (messages, dmesg,
vmcore-dmesg.txt, vmware-vmsvc logs):
    python3 fsfreeze.py <log file>...

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import datetime
import re
import sys

# ---------------------------------------------------------------------------
# Stack frames
# ---------------------------------------------------------------------------

# Out of line in RHEL7/8 (fs/super.c), where it is the whole answer; inline
# from RHEL9, where only the percpu-rwsem frames below it remain.
SB_WAIT_FRAMES = frozenset(("__sb_start_write", "sb_start_write",
                            "sb_start_pagefault", "sb_start_intwrite"))
# The reader slow path of a percpu rwsem, and the RHEL7 rwsem it sits on.
# The same path serves cgroup_threadgroup_rwsem, cpus_read_lock and the
# memory-hotplug lock, so on RHEL9 it is a freeze wait only when the frame
# right after it is a function that takes freeze protection itself.
PERCPU_WAIT_FRAMES = frozenset(("percpu_rwsem_wait", "__percpu_down_read",
                                "percpu_down_read", "rwsem_down_read_failed",
                                "call_rwsem_down_read_failed",
                                "rwsem_down_read_slowpath", "down_read",
                                "__down_read"))
# Functions that call sb_start_write/pagefault/intwrite or file_start_write
# inline: the frame right above the wait when the wait is a freeze.
DIRECT_CALLERS = frozenset((
    "mnt_want_write", "mnt_want_write_file", "vfs_write", "__vfs_write",
    "vfs_writev", "do_iter_write", "vfs_iter_write", "vfs_fallocate",
    "do_sys_ftruncate", "ksys_ftruncate", "do_ftruncate", "aio_write",
    "io_write", "nfsd_vfs_write", "lo_write_bvec", "do_splice",
    "do_sendfile", "kernel_write", "__kernel_write", "vfs_copy_file_range",
    "vfs_clone_file_range", "ioctl_file_clone", "xfs_file_ioctl",
    "xfs_ioc_swapext", "xfs_trans_alloc", "xfs_trans_alloc_inode",
    "ext4_evict_inode", "__ext4_journal_start_sb", "do_page_mkwrite",
    "__xfs_filemap_fault", "xfs_filemap_fault", "ovl_want_write",
    "do_coredump", "file_remove_privs",
))
FS_LEVEL_CALLERS = frozenset(("xfs_trans_alloc", "xfs_trans_alloc_inode",
                              "ext4_evict_inode", "__ext4_journal_start_sb"))
FREEZER_FRAMES = frozenset(("freeze_super", "thaw_super", "freeze_bdev",
                            "thaw_bdev", "sb_wait_write", "ioctl_fsfreeze",
                            "ioctl_fsthaw", "freeze_filesystems"))
THAW_FRAMES = frozenset(("thaw_super", "thaw_bdev", "ioctl_fsthaw"))

# Processes that freeze filesystems for snapshots and backups (thread-group
# leader comm; xfs_freeze is a script that runs xfs_io).
AGENT_COMMS = {
    "vmtoolsd": "VMware Tools",
    "qemu-ga": "qemu-guest-agent",
    "hv_vss_daemon": "Hyper-V VSS",
    "hypervvssd": "Hyper-V VSS",
    "fsfreeze": "fsfreeze",
    "xfs_freeze": "fsfreeze",
    "xfs_io": "fsfreeze",
}


def frame_name(frame):
    """'mwait.constprop.0+0x1a/0x30' -> 'mwait'."""
    return frame.split("+", 1)[0].split(".", 1)[0]


def _is_direct(name):
    return name in DIRECT_CALLERS or name.endswith("_page_mkwrite") \
        or name.endswith("filemap_fault")


def analyse(frames):
    """
    (kind, detail, where) for a stack, innermost frame first:
      ('freezer', 'freeze'|'thaw', frame)  freezing or thawing a filesystem
      ('waiter', level, caller)            blocked behind a freeze; level is
                                           'write', 'pagefault' or 'fs'
      (None, None, None)                   anything else
    A percpu_down_write is someone else's writer (cgroup, hotplug) unless a
    freezer frame says it is the freeze itself.
    """
    names = [frame_name(f) for f in frames]
    for n in names:
        if n in FREEZER_FRAMES:
            return ("freezer",
                    "thaw" if any(m in THAW_FRAMES for m in names) else "freeze",
                    n)
    if "percpu_down_write" in names:
        return None, None, None
    sb_at = [i for i, n in enumerate(names) if n in SB_WAIT_FRAMES]
    if sb_at:
        i = sb_at[-1] + 1
    else:
        waits = [i for i, n in enumerate(names) if n in PERCPU_WAIT_FRAMES]
        if not waits:
            return None, None, None
        i = waits[0]
        while i < len(names) and names[i] in PERCPU_WAIT_FRAMES:
            i += 1
        if i >= len(names) or not _is_direct(names[i]):
            return None, None, None
    while i < len(names) and (names[i] in PERCPU_WAIT_FRAMES
                              or names[i] in SB_WAIT_FRAMES):
        i += 1
    caller = names[i] if i < len(names) else "?"
    if caller.endswith("_page_mkwrite") or caller.endswith("filemap_fault") \
            or "sb_start_pagefault" in names:
        level = "pagefault"
    elif caller in FS_LEVEL_CALLERS or "sb_start_intwrite" in names:
        level = "fs"
    else:
        level = "write"
    return "waiter", level, caller


def classify(frames):
    """(kind, detail) of analyse(): ('waiter', level), ('freezer',
    'freeze'|'thaw') or (None, None)."""
    return analyse(frames)[:2]


def caller_of(frames):
    """The frame that names the filesystem operation, for display."""
    where = analyse(frames)[2]
    return where or (frame_name(frames[-1]) if frames else "?")


# ---------------------------------------------------------------------------
# Times in log lines
# ---------------------------------------------------------------------------

MONTHS = dict((m, i + 1) for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
     "Nov", "Dec")))
SYSLOG_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})")
ISO_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})")
KTIME_RE = re.compile(r"^\s*(?:<\d+>)?\[\s*(\d+\.\d+)\]")


def line_time(line):
    """
    (kind, seconds) for the line's own timestamp: 'wall' for syslog and
    ISO times (syslog has no year, so differences across New Year are
    wrong), 'boot' for a kernel [seconds] stamp.  None when there is none.
    """
    m = SYSLOG_RE.match(line)
    if m and m.group(1) in MONTHS:
        t = datetime.datetime(2000, MONTHS[m.group(1)], int(m.group(2)),
                              int(m.group(3)), int(m.group(4)), int(m.group(5)))
        return "wall", (t - datetime.datetime(2000, 1, 1)).total_seconds()
    m = KTIME_RE.match(line)
    if m:
        return "boot", float(m.group(1))
    m = ISO_RE.search(line[:40])
    if m:
        t = datetime.datetime(*[int(x) for x in m.groups()])
        return "wall", (t - datetime.datetime(2000, 1, 1)).total_seconds()
    m = re.search(r"kernel:\s*\[\s*(\d+\.\d+)\]", line)
    if m:
        return "boot", float(m.group(1))
    return None


def time_diff(a, b):
    """b - a in seconds when both times are of the same kind and b is not
    earlier (syslog has no year; clocks get stepped), else None."""
    if a is None or b is None or a[0] != b[0] or b[1] < a[1]:
        return None
    return b[1] - a[1]


def duration_text(sec):
    if sec is None:
        return "?"
    sec = int(sec)
    if sec < 120:
        return "%ds" % sec
    if sec < 7200:
        return "%dm" % (sec // 60)
    if sec < 172800:
        return "%.1fh" % (sec / 3600.0)
    return "%dd" % (sec // 86400)


# ---------------------------------------------------------------------------
# Hung-task reports in a log
# ---------------------------------------------------------------------------

HUNG_RE = re.compile(r"INFO: task (.+):(\d+) blocked for more than (\d+) seconds")
TRACE_FRAME_RE = re.compile(
    r"(?:\]\s+|\s)(\?\s+)?([A-Za-z_][\w.]*)\+0x[0-9a-fA-F]+/0x[0-9a-fA-F]+")
TRACE_SEARCH_LINES = 80
# Another report starting: a sysrq or NMI dump, a WARN, a panic.
TRACE_STOP_RE = re.compile(r"sysrq|SysRq|NMI backtrace|cut here|Kernel panic"
                           r"|BUG: |WARNING: ")
# A sched_show_task header of the next task (RHEL7 'comm D addr 0 pid ppid',
# RHEL8/9 'task:comm state:D'); it also opens the report's own trace, so it
# ends a trace only once a 'Call Trace:' was seen.
TASK_HEADER_RE = re.compile(r"task:\S.*\bstate:\S|\s[DRSTZXI]\s+(?:0x)?[0-9a-f]{8,}"
                            r"\s+\d+\s+\d+\s+\d+")
TRACE_MARKERS = ("<TASK>", "<IRQ>", "</IRQ>", "<EOI>", "<NMI>", "</NMI>")


def trace_frames(lines, start):
    """
    Frame names of the call trace that follows lines[start], innermost
    first, without the unreliable '?' frames.  The trace ends at the next
    report, a second 'Call Trace:', '</TASK>', or the first line without a
    frame once frames have started: RHEL7/8 print no end marker.
    """
    frames = []
    started = seen_trace = False
    for follow in lines[start + 1:start + 1 + TRACE_SEARCH_LINES]:
        if HUNG_RE.search(follow) or TRACE_STOP_RE.search(follow) \
                or "</TASK>" in follow:
            break
        if "Call Trace:" in follow:
            if seen_trace:
                break
            seen_trace = True
            continue
        if seen_trace and TASK_HEADER_RE.search(follow):
            break
        found = list(TRACE_FRAME_RE.finditer(follow))
        if found:
            started = True
            frames += [f.group(2) for f in found if not f.group(1)]
            continue
        if any(m in follow for m in TRACE_MARKERS):
            continue
        if started:
            break
    return frames


def hung_reports(lines):
    """
    Hung-task reports with the frames of their call trace and what the
    frames say: [{index, time, comm, pid, secs, frames, kind, level}].
    """
    reports = []
    for index, line in enumerate(lines):
        m = HUNG_RE.search(line)
        if not m:
            continue
        frames = trace_frames(lines, index)
        kind, level = classify(frames)
        reports.append({
            "index": index, "time": line_time(line), "comm": m.group(1),
            "pid": int(m.group(2)), "secs": int(m.group(3)),
            "frames": frames, "kind": kind, "level": level,
        })
    return reports


# ---------------------------------------------------------------------------
# Freeze-agent events in a log
# ---------------------------------------------------------------------------

AGENT_TOKENS = (
    ("VMware Tools", ("vmtoolsd", "vmsvc", "vmbackup", "syncdriver")),
    ("qemu-guest-agent", ("qemu-ga", "guest-fsfreeze", "guest-fsthaw",
                          "fsfreeze hook")),
    ("Hyper-V VSS", ("hv_vss_daemon", "hypervvssd", "vss: op=")),
)
# From the agents' sources:
#   open-vm-tools syncDriverLinux.c: "Freezing using Linux ioctls...",
#     "freezing path '%s'", "successfully froze '%s'", "Thawing fd=%d."
#     (one per filesystem), "Thaw failed", "'%s' appears locked or frozen by
#     another process.  Cannot complete the quiesced snapshot request.";
#     vmbackup: "VMX state changed; thawing filesystems."  Debug-level lines
#     reach the log only with vmsvc.level=debug.
#   qemu-ga: "guest-fsfreeze called", "disabling logging due to filesystem
#     freeze", "logging re-enabled due to filesystem unfreeze", "guest-fsthaw
#     called", "executing fsfreeze hook with arg 'freeze'|'thaw'".
#   hv_vss_daemon: "VSS: op=FREEZE: %s", "VSS: op=THAW: %s",
#     "FREEZE of %s failed" (it then thaws without logging op=THAW).
THAW_WORDS = ("thaw", "unfreez", "re-enabled due to filesystem")
FREEZE_WORDS = ("freez", "froze", "quiesc")
ERROR_WORDS = ("fail", "error", "cannot", "timed out", "timeout", "abort")


def agent_event(line):
    """(agent, 'freeze'|'thaw', is_error) when the line is a freeze-agent
    freeze or thaw message, else None."""
    lower = line.lower()
    for agent, tokens in AGENT_TOKENS:
        if not any(t in lower for t in tokens):
            continue
        if any(w in lower for w in THAW_WORDS):
            kind = "thaw"
        elif any(w in lower for w in FREEZE_WORDS):
            kind = "freeze"
        else:
            return None
        return agent, kind, any(w in lower for w in ERROR_WORDS)
    return None


def freeze_windows(lines):
    """
    Freeze-to-thaw windows per agent, in log order:
    [{agent, start, end, start_time, end_time, events, errors, failed}].
    end is None for a freeze with no later thaw in this log.  Repeated
    freeze messages before the thaw belong to the same window, and repeated
    thaw messages after it (one per filesystem) too.  A failed freeze ends
    its window: the agents thaw what they froze without always logging it.
    """
    windows = []
    open_by_agent = {}
    last_closed = {}

    def close(w, index, line):
        w["end"] = index
        w["end_time"] = line_time(line)
        del open_by_agent[w["agent"]]
        last_closed[w["agent"]] = w

    for index, line in enumerate(lines):
        ev = agent_event(line)
        if not ev:
            continue
        agent, kind, error = ev
        w = open_by_agent.get(agent)
        if kind == "freeze":
            prev = last_closed.get(agent)
            if w is None and error and prev is not None and prev["failed"]:
                # A further error line of the freeze that just failed.
                prev["events"].append(index)
                prev["errors"].append(index)
                prev["end"] = index
                prev["end_time"] = line_time(line)
                continue
            if w is None:
                w = {"agent": agent, "start": index, "end": None,
                     "start_time": line_time(line), "end_time": None,
                     "events": [], "errors": [], "failed": False}
                windows.append(w)
                open_by_agent[agent] = w
                last_closed.pop(agent, None)
            w["events"].append(index)
            if error:
                w["errors"].append(index)
                w["failed"] = True
                close(w, index, line)
            continue
        if w is not None:
            w["events"].append(index)
            close(w, index, line)
        elif agent in last_closed:
            # A further thaw line of the cycle that just ended.
            w = last_closed[agent]
            w["events"].append(index)
            w["end"] = index
            w["end_time"] = line_time(line)
        else:
            # A thaw with no freeze in this log: the freeze is earlier.
            w = {"agent": agent, "start": None, "end": index,
                 "start_time": None, "end_time": line_time(line),
                 "events": [index], "errors": [], "failed": False}
            windows.append(w)
            last_closed[agent] = w
        if error:
            w["errors"].append(index)
    return windows


def window_duration(w):
    return time_diff(w["start_time"], w["end_time"])


def reports_in_window(reports, w):
    """Hung-task reports logged while the window was open (same log)."""
    out = []
    for r in reports:
        after = w["start"] is None or r["index"] > w["start"]
        before = w["end"] is None or r["index"] < w["end"]
        if after and before:
            out.append(r)
    return out


# ---------------------------------------------------------------------------
# Standalone report on saved logs
# ---------------------------------------------------------------------------

def log_report(lines, name="log"):
    out = []
    reports = hung_reports(lines)
    windows = freeze_windows(lines)
    blocked = [r for r in reports if r["kind"] == "waiter"]
    out.append("%s: %d freeze window(s), %d hung-task report(s), %d blocked "
               "by a frozen filesystem" % (name, len(windows), len(reports),
                                           len(blocked)))
    for w in windows:
        if w["failed"]:
            span = "lines %d-%d, freeze FAILED" % (w["start"] + 1, w["end"] + 1)
        elif w["start"] is None:
            span = "thaw at line %d, freeze earlier than this log" % (w["end"] + 1)
        elif w["end"] is None:
            span = "freeze at line %d, NO THAW in this log" % (w["start"] + 1)
        else:
            span = "lines %d-%d, %s" % (w["start"] + 1, w["end"] + 1,
                                        duration_text(window_duration(w)))
        out.append("  %-18s %s%s" % (w["agent"], span,
                                     ", %d error(s)" % len(w["errors"])
                                     if w["errors"] else ""))
    for r in reports:
        out.append("  hung task %s:%d %ds  %s  (line %d)"
                   % (r["comm"], r["pid"], r["secs"],
                      "frozen-fs %s wait in %s" % (r["level"], caller_of(r["frames"]))
                      if r["kind"] == "waiter" else
                      "%s in %s" % ("thawing" if r["level"] == "thaw" else
                                    "freezing", caller_of(r["frames"]))
                      if r["kind"] == "freezer" else "not a freeze wait",
                      r["index"] + 1))
    return "\n".join(out)


if (__name__ == '__main__'):
    if len(sys.argv) < 2:
        print("usage: python3 fsfreeze.py <log file>...")
        sys.exit(1)
    for path in sys.argv[1:]:
        with open(path, errors="replace") as f:
            print(log_report(f.read().splitlines(), path))
