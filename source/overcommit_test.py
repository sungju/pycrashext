"""
Checks for the hypervisor overcommit verdict and log timeline.

Run directly: python3 source/overcommit_test.py

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from overcommit import (Signal, HIT, MISS, NA, HOST, SUPPORT, CONTEXT,
                        domain_verdict, overall_verdict, answer_text,
                        analyse_log, classify_rip, category_summary,
                        blind_spots, host_checks, excerpt, log_report,
                        recent)

LOG = """[    0.000000] Hypervisor detected: VMware
[   50.000000] Out of memory: Killed process 1234 (java)
[ 5000.100000] watchdog: BUG: soft lockup - CPU#1 stuck for 23s! [swapper/1:0]
[ 5000.100010] Modules linked in: vmw_balloon
[ 5000.100020] RIP: 0010:native_safe_halt+0xe/0x10
[ 5000.900000] watchdog: BUG: soft lockup - CPU#4 stuck for 22s! [java:4321]
[ 5000.900010] RIP: 0033:0x7f3a2b1c0d00
[ 5001.500000] watchdog: BUG: soft lockup - CPU#7 stuck for 22s! [kworker/7:1:99]
[ 5001.500010] RIP: 0010:[<ffffffff8169a9e6>]  [<ffffffff8169a9e6>] queued_spin_lock_slowpath+0x1d/0x200
[ 5002.000000] hrtimer: interrupt took 4123456 ns
[ 5003.000000] sd 2:0:0:0: [sda] tag#3 timing out command, waited 180s
[ 5010.000000] Kernel panic - not syncing: softlockup: hung tasks""".splitlines()


def check_rip_classification():
    assert classify_rip("RIP: 0033:0x7f3a2b1c0d00") == ("user", "")
    assert classify_rip("RIP: 0010:native_safe_halt+0xe/0x10") == \
        ("idle", "native_safe_halt")
    assert classify_rip("RIP: 0010:[<ffffffff8169a9e6>]  [<ffffffff8169a9e6>] "
                        "default_idle+0x1e/0xc0") == ("idle", "default_idle")
    assert classify_rip("RIP: 0010:queued_spin_lock_slowpath+0x1d/0x200") == \
        ("kernel", "queued_spin_lock_slowpath")
    assert classify_rip("no rip here") is None
    assert classify_rip("RIP: 0010:mwait_idle_with_hints.constprop.0+0x4a/0x90")[0] \
        == "idle"


def check_halt_in_a_normal_task_is_a_spinlock_wait():
    # kvm_wait halts through native_safe_halt: not idle unless swapper.
    lines = ["[ 10.0] watchdog: BUG: soft lockup - CPU#3 stuck for 22s! [java:4321]",
             "[ 10.0] RIP: 0010:native_safe_halt+0xe/0x10"]
    assert analyse_log(lines)["softlockups"][0]["where"] == "kernel"


def check_no_rip_is_unknown_not_idle():
    lines = ["[ 10.0] watchdog: BUG: soft lockup - CPU#0 stuck for 22s! [swapper/0:0]",
             "[ 10.0] Modules linked in: x"]
    assert analyse_log(lines)["softlockups"][0]["where"] == "?"


def check_interleaved_reports_take_their_own_rip():
    lines = [
        "[ 10.0] watchdog: BUG: soft lockup - CPU#0 stuck for 22s! [swapper/0:0]",
        "[ 10.0] watchdog: BUG: soft lockup - CPU#1 stuck for 22s! [swapper/1:0]",
        "[ 10.0] CPU: 1 PID: 0 Comm: swapper/1 Not tainted 4.18.0",
        "[ 10.0] RIP: 0010:__do_softirq+0x80/0x2a0",
        "[ 10.0] CPU: 0 PID: 0 Comm: swapper/0 Not tainted 4.18.0",
        "[ 10.0] RIP: 0010:native_safe_halt+0xe/0x10",
    ]
    where = [(s["cpu"], s["where"]) for s in analyse_log(lines)["softlockups"]]
    assert where == [(0, "idle"), (1, "kernel")], where
    assert [s["rip_index"] for s in analyse_log(lines)["softlockups"]] == [5, 3]


def check_untimed_log_has_nothing_recent():
    log = analyse_log(["watchdog: BUG: soft lockup - CPU#0 stuck for 22s! [a:1]"])
    assert recent(log, log["categories"]["soft lockup"]) == []


def check_softlockups_record_where_the_cpu_was():
    log = analyse_log(LOG)
    where = [(s["cpu"], s["where"]) for s in log["softlockups"]]
    assert where == [(1, "idle"), (4, "user"), (7, "kernel")], where
    assert log["end"] == 5010.0 and log["start"] == 0.0


def check_rip_beats_swapper_comm():
    lines = ["[ 10.0] watchdog: BUG: soft lockup - CPU#0 stuck for 22s! [swapper/0:0]",
             "[ 10.0] RIP: 0010:__do_softirq+0x80/0x2a0"]
    s = analyse_log(lines)["softlockups"][0]
    assert s["where"] == "kernel", s


def check_burst_needs_two_cpus_within_span():
    log = analyse_log(LOG)
    assert len(log["bursts"]) == 1
    assert set(s["cpu"] for s in log["bursts"][0]) == set([1, 4, 7])
    single = analyse_log(LOG[:5])
    assert single["bursts"] == []


def check_recent_window_separates_old_oom():
    log = analyse_log(LOG)
    text = category_summary(log, "memory")
    assert text.startswith("1, 0 in last 10m"), text
    assert "82m before end of log" in text, text
    assert category_summary(log, "soft lockup").startswith("3, last"), \
        category_summary(log, "soft lockup")
    assert category_summary(log, "RCU stall") is None
    assert log["hrtimer_max_ns"] == 4123456


def check_host_hit_decides_and_balloon_confirms():
    signals = [
        Signal("CPU", HOST, "steal", NA, "not exported"),
        Signal("CPU", HOST, "user-mode tick stall", HIT, "CPU1 6.7s"),
        Signal("CPU", SUPPORT, "load", HIT, "4x"),
        Signal("Memory", HOST, "balloon now", HIT, "11 GiB", proof=True),
        Signal("Guest", CONTEXT, "swap", HIT, "80%"),
    ]
    assert domain_verdict(signals, "CPU") == "LIKELY"
    assert domain_verdict(signals, "Memory") == "CONFIRMED"
    assert overall_verdict(["LIKELY", "CONFIRMED"]) == "CONFIRMED"
    assert "user-mode tick stall" in answer_text(signals, "CPU", "LIKELY")


def check_guest_pressure_never_raises_the_verdict():
    signals = [
        Signal("CPU", HOST, "steal", MISS, "0.0%"),
        Signal("Memory", HOST, "balloon now", MISS, "0 pages", proof=True),
        Signal("Guest", CONTEXT, "OOM", HIT, "1"),
        Signal("Guest", CONTEXT, "aged I/O", HIT, "3.4s"),
    ]
    assert domain_verdict(signals, "CPU") == "NO EVIDENCE"
    assert domain_verdict(signals, "Memory") == "NO EVIDENCE"


def check_support_only_is_possible_and_unread_is_unknown():
    signals = [
        Signal("CPU", HOST, "steal", NA, "not exported"),
        Signal("CPU", SUPPORT, "deep runqueue", HIT, "67"),
        Signal("Memory", HOST, "balloon now", NA, "no driver", proof=True),
    ]
    assert domain_verdict(signals, "CPU") == "POSSIBLE"
    assert domain_verdict(signals, "Memory") == "UNKNOWN"
    assert overall_verdict(["POSSIBLE", "UNKNOWN"]) == "POSSIBLE"
    assert overall_verdict(["NO EVIDENCE", "UNKNOWN"]) == "NO EVIDENCE"
    assert overall_verdict(["UNKNOWN", "UNKNOWN"]) == "UNKNOWN"


def check_blind_spots_and_host_checks():
    spots = blind_spots("VMware", False, True, analyse_log(LOG))
    assert any("steal is not exported" in s for s in spots)
    assert any("every vCPU at once" in s for s in spots)
    wrapped = analyse_log(["[ 9000.0] x", "[ 9001.0] y"])
    assert any("overwritten" in s for s in blind_spots("KVM", True, False,
                                                       wrapped))
    assert "CPU Ready" in host_checks("VMware", "Mon Oct 12")[0]
    assert "virsh domstats" in host_checks("KVM", "")[0]
    sos = blind_spots("VMware", True, True, analyse_log(LOG), "sosreport")
    assert not any("clock lag" in s for s in sos)
    assert "vminfo --overcommit" in host_checks("VMware", "", "sosreport")[1]
    assert "isos 'vmware'" in host_checks("VMware", "")[1]
    assert "Hyper-V" in host_checks("Microsoft HyperV", "")[0]
    assert "Hyper-V" in host_checks("Microsoft", "")[0]


def check_excerpt_marks_and_gaps():
    rows = excerpt([str(i) for i in range(20)], set([2, 15]), 1, 1)
    assert rows[0] == ("1", False) and rows[1] == ("2", True)
    assert ("... unrelated log lines ...", False) in rows


def check_log_report_runs():
    text = log_report(LOG)
    assert "soft lockup CPU1" in text and "burst: 3 CPUs" in text, text
    assert "no timestamped lines" in log_report(["plain line"])


if (__name__ == '__main__'):
    checks = [v for k, v in sorted(globals().items()) if k.startswith('check_')]
    for check in checks:
        check()
        print("ok  %s" % check.__name__)
    print("\n%d checks passed" % len(checks))
