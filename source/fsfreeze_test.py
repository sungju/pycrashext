"""
Checks for the filesystem-freeze frame classification and log analysis.
The agent messages are the strings in open-vm-tools (syncDriverLinux.c,
vmbackup), qemu-ga (qga/main.c, commands-posix.c) and hv_vss_daemon.c.

Run directly: python3 source/fsfreeze_test.py

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from fsfreeze import (classify, caller_of, hung_reports, freeze_windows,
                      agent_event, window_duration, reports_in_window,
                      line_time, time_diff, log_report)

SCHED = ["__schedule", "schedule"]


def check_rhel7_and_rhel8_out_of_line_sb_start_write():
    rhel7 = SCHED + ["rwsem_down_read_failed", "call_rwsem_down_read_failed",
                     "percpu_down_read", "__sb_start_write", "vfs_write",
                     "sys_write"]
    assert classify(rhel7) == ("waiter", "write")
    assert caller_of(rhel7) == "vfs_write"
    rhel8 = SCHED + ["percpu_rwsem_wait", "__percpu_down_read",
                     "__sb_start_write", "ext4_evict_inode", "evict"]
    assert classify(rhel8) == ("waiter", "fs")


def check_rhel9_inline_waits_need_a_direct_caller():
    for caller in ("mnt_want_write", "aio_write", "io_write", "nfsd_vfs_write",
                   "lo_write_bvec", "vfs_copy_file_range", "do_splice"):
        stack = SCHED + ["percpu_rwsem_wait", "__percpu_down_read.constprop.0",
                         caller, "do_syscall_64"]
        assert classify(stack) == ("waiter", "write"), caller
    fault = SCHED + ["percpu_rwsem_wait", "__percpu_down_read",
                     "xfs_filemap_page_mkwrite", "do_page_mkwrite"]
    assert classify(fault) == ("waiter", "pagefault")


def check_other_percpu_rwsem_users_under_a_write_are_not_freezes():
    cgroup_writer = SCHED + ["percpu_rwsem_wait", "percpu_down_write",
                             "cgroup_procs_write_start", "cgroup_procs_write",
                             "kernfs_fop_write_iter", "vfs_write"]
    cpuset = SCHED + ["percpu_rwsem_wait", "__percpu_down_read",
                      "cpus_read_lock", "cpuset_write_resmask",
                      "kernfs_fop_write_iter", "vfs_write"]
    hotplug = SCHED + ["percpu_rwsem_wait", "percpu_down_write",
                       "mem_hotplug_begin", "online_pages", "vfs_write"]
    for stack in (cgroup_writer, cpuset, hotplug):
        assert classify(stack) == (None, None), stack


def check_freezer_beats_waiter_and_tells_thaw_from_freeze():
    freezer = SCHED + ["percpu_rwsem_wait", "percpu_down_write",
                       "sb_wait_write", "freeze_super", "do_vfs_ioctl"]
    assert classify(freezer) == ("freezer", "freeze")
    assert classify(SCHED + ["rwsem_down_write_slowpath", "thaw_super",
                             "do_vfs_ioctl"]) == ("freezer", "thaw")
    assert classify(SCHED + ["io_schedule", "blk_mq_get_tag"]) == (None, None)


MESSAGES = """Oct 12 10:00:00 host vmtoolsd[900]: [vmbackup] SyncDriver: Freezing using Linux ioctls...
Oct 12 10:00:00 host vmtoolsd[900]: [vmbackup] SyncDriver: successfully froze '/' (fd=5).
Oct 12 10:02:01 host kernel: INFO: task java:4321 blocked for more than 120 seconds.
Oct 12 10:02:01 host kernel:      Not tainted 4.18.0-553.el8_10.x86_64 #1
Oct 12 10:02:01 host kernel: task:java            state:D stack:    0 pid: 4321 ppid:     1 flags:0x00000080
Oct 12 10:02:01 host kernel: Call Trace:
Oct 12 10:02:01 host kernel: __schedule+0x2d1/0x830
Oct 12 10:02:01 host kernel: schedule+0x35/0xa0
Oct 12 10:02:01 host kernel: ? xfs_iunlock+0x12/0x40 [xfs]
Oct 12 10:02:01 host kernel: percpu_rwsem_wait+0x1/0x2
Oct 12 10:02:01 host kernel: __percpu_down_read+0x1/0x2
Oct 12 10:02:01 host kernel: __sb_start_write+0x3f/0x60
Oct 12 10:02:01 host kernel: vfs_write+0x15d/0x1b0
Oct 12 10:02:01 host kernel: ksys_write+0x4f/0xb0
Oct 12 10:03:00 host kernel: INFO: task kworker/1:2:77 blocked for more than 120 seconds.
Oct 12 10:03:00 host kernel: Call Trace:
Oct 12 10:03:00 host kernel: __schedule+0x2d1/0x830
Oct 12 10:03:00 host kernel: io_schedule+0x12/0x40
Oct 12 10:30:00 host vmtoolsd[900]: [vmbackup] SyncDriver: Thawing fd=5.
Oct 12 10:30:00 host vmtoolsd[900]: [vmbackup] SyncDriver: Thawing fd=6.
Oct 12 11:00:00 host hypervvssd[33]: VSS: op=FREEZE: succeeded""".splitlines()

RHEL7_TRACE = """[ 1201.1] INFO: task bash:55 blocked for more than 120 seconds.
[ 1201.1] "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
[ 1201.1] bash            D ffff88017fc13680     0    55      1 0x00000080
[ 1201.1] Call Trace:
[ 1201.1]  [<ffffffff8168c169>] schedule+0x29/0x70
[ 1201.1]  [<ffffffff8168d9a5>] rwsem_down_read_failed+0xf5/0x170
[ 1201.1]  [<ffffffff81203f5c>] __sb_start_write+0xdc/0x130
[ 1201.1]  [<ffffffff81200d85>] vfs_write+0x1c5/0x1f0""".splitlines()


def check_hung_reports_and_their_frames():
    reports = hung_reports(MESSAGES)
    assert [(r["comm"], r["kind"]) for r in reports] == \
        [("java", "waiter"), ("kworker/1:2", None)], reports
    assert "xfs_iunlock" not in reports[0]["frames"]      # '?' frame dropped
    r7 = hung_reports(RHEL7_TRACE)[0]
    assert r7["kind"] == "waiter" and r7["time"] == ("boot", 1201.1), r7


def check_a_trace_does_not_absorb_the_next_dump():
    # RHEL7/8 have no </TASK>: a sysrq-w dump after the last report must
    # not lend it frames, in either direction.
    io_hang = """[ 100.0] INFO: task kworker/0:1:9 blocked for more than 120 seconds.
[ 100.0] Call Trace:
[ 100.0]  io_schedule+0x12/0x40
[ 100.0]  blk_mq_get_tag+0x1/0x2
[ 150.0] sysrq: Show Blocked State
[ 150.0] task:dd state:D stack: 0 pid: 9 ppid: 1
[ 150.0] Call Trace:
[ 150.0]  __sb_start_write+0x1/0x2
[ 150.0]  vfs_write+0x1/0x2""".splitlines()
    assert hung_reports(io_hang)[0]["kind"] is None
    waiter = RHEL7_TRACE + """[ 1300.0] java            D ffff88017fc13690     0  4321      1 0x00000080
[ 1300.0] Call Trace:
[ 1300.0]  [<ffffffff81203f00>] freeze_super+0x1/0x2""".splitlines()
    assert hung_reports(waiter)[0]["kind"] == "waiter"


def check_agent_events_from_real_strings():
    assert agent_event(MESSAGES[0]) == ("VMware Tools", "freeze", False)
    assert agent_event(MESSAGES[1])[1] == "freeze"          # "froze"
    assert agent_event(MESSAGES[-2]) == ("VMware Tools", "thaw", False)
    assert agent_event("vmtoolsd[9]: [vmbackup] SyncDriver: '/var' appears "
                       "locked or frozen by another process.  Cannot complete "
                       "the quiesced snapshot request.") == \
        ("VMware Tools", "freeze", True)
    assert agent_event("vmtoolsd: [vmbackup] VMX state changed; thawing "
                       "filesystems.")[1] == "thaw"
    qga = "qemu-ga: info: guest-fsfreeze called"
    assert agent_event(qga)[1] == "freeze"
    assert agent_event("qemu-ga: info: logging re-enabled due to filesystem "
                       "unfreeze")[1] == "thaw"
    assert agent_event("qemu-ga: info: guest-fsthaw called")[1] == "thaw"
    assert agent_event(MESSAGES[-1]) == ("Hyper-V VSS", "freeze", False)
    assert agent_event("hypervvssd: FREEZE of / failed; error:16 Device busy") \
        == ("Hyper-V VSS", "freeze", True)
    assert agent_event("Oct 12 kernel: Freezing user space processes") is None
    assert agent_event("vmtoolsd[9]: [vmsvc] GuestInfo: updated") is None


def check_windows_pair_extend_and_stay_open():
    windows = freeze_windows(MESSAGES)
    assert len(windows) == 2, windows                      # thaw x2 = one
    vmw, hv = windows
    assert (vmw["start"], vmw["end"]) == (0, 19), vmw
    assert window_duration(vmw) == 1800
    assert hv["end"] is None and hv["agent"] == "Hyper-V VSS"
    inside = reports_in_window(hung_reports(MESSAGES), vmw)
    assert [r["comm"] for r in inside] == ["java", "kworker/1:2"]
    only_thaw = freeze_windows(["vmtoolsd: [vmbackup] SyncDriver: Thawing fd=3."])
    assert only_thaw[0]["start"] is None


def check_a_failed_freeze_closes_its_window():
    lines = ["hypervvssd: VSS: op=FREEZE: failed",
             "hypervvssd: FREEZE of / failed; error:16 Device busy",
             "kernel: INFO: task java:1 blocked for more than 120 seconds."]
    windows = freeze_windows(lines)
    assert len(windows) == 1, windows          # both error lines, one freeze
    w = windows[0]
    assert w["failed"] and w["end"] == 1 and len(w["errors"]) == 2, w
    assert reports_in_window(hung_reports(lines), w) == []


def check_times():
    assert line_time("[2026-10-12T10:00:00.123Z] [ message] [vmsvc] x")[0] == "wall"
    assert line_time("plain") is None
    assert line_time("Oct 12 10:00:00 h kernel: [ 5.5] x")[0] == "wall"
    assert line_time("[ 5.5] date 2026-10-12 10:00:00")[0] == "boot"
    assert time_diff(("wall", 100.0), ("wall", 40.0)) is None


def check_log_report_runs():
    text = log_report(MESSAGES, "messages")
    assert "2 freeze window(s)" in text and "NO THAW" in text, text
    assert "frozen-fs write wait in vfs_write" in text, text


if (__name__ == '__main__'):
    checks = [v for k, v in sorted(globals().items()) if k.startswith('check_')]
    for check in checks:
        check()
        print("ok  %s" % check.__name__)
    print("\n%d checks passed" % len(checks))
