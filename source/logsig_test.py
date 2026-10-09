"""
Checks for the kernel log signature catalogue.

Run directly: python3 source/logsig_test.py

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from logsig import scan, reroute, report

LOG = """[    0.000000] Hypervisor detected: VMware
[ 1201.112233] INFO: task kworker/2:1:1234 blocked for more than 120 seconds.
[ 1201.112240] Call Trace:
[ 1321.443322] INFO: task jbd2/dm-0-8:812 blocked for more than 120 seconds.
[ 1400.000001] sd 2:0:0:0: [sda] tag#3 timing out command, waited 180s
[ 1500.123456] Kernel panic - not syncing: hung_task: blocked tasks""".splitlines()


def check_scan_finds_each_signature_once_per_line():
    hits = scan(LOG)
    assert hits["hung_task"] == [2, 4], hits
    assert hits["hypervisor"] == [1]
    assert hits["storage"] == [5]
    assert hits["call_trace"] == [3]
    assert hits["panic"] == [6]
    assert "oom" not in hits


def check_reroute_names_the_condition():
    assert "Branch C" in reroute(LOG, scan(LOG))
    assert reroute(["Kernel panic - not syncing: Out of memory"],
                   scan(["Kernel panic - not syncing: Out of memory"])).endswith("(Branch B)")
    plain = ["Kernel panic - not syncing: Fatal exception"]
    assert reroute(plain, scan(plain)) is None


def check_report_quotes_lines_verbatim():
    text = report(LOG)
    # The first and last matching lines, exactly as the log has them.
    assert LOG[1] in text.splitlines() and LOG[3] in text.splitlines()
    assert "reroute: kernel.hung_task_panic" in text
    assert "hung_task=2" in text.splitlines()[-1]


def check_rcu_and_corruption():
    lines = ["[ 10.0] rcu: INFO: rcu_sched detected stalls on CPUs/tasks:",
             "[ 11.0] list_del corruption. prev->next should be ffff8801, but was dead000000000100",
             "[ 12.0] refcount_t: underflow; use-after-free."]
    hits = scan(lines)
    assert hits["rcu_stall"] == [1]
    assert hits["corruption"] == [2, 3]


def check_empty_log():
    assert "no known signature found" in report(["[ 1.0] Linux version 4.18.0"])


if (__name__ == '__main__'):
    checks = [v for k, v in sorted(globals().items()) if k.startswith('check_')]
    for check in checks:
        check()
        print("ok  %s" % check.__name__)
    print("\n%d checks passed" % len(checks))
