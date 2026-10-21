"""
Checks for the storage status verdicts.

Run directly: python3 source/storstat_test.py

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from storstat import (host_findings, device_findings, queue_findings,
                      nvme_findings, rport_findings, worst, PROBLEMS)


def states(findings):
    return [f[0] for f in findings]


def check_host_in_error_handling():
    f = host_findings("SHOST_RECOVERY", busy=4, failed=4, blocked=0)
    assert states(f) == ["ERROR RECOVERY"], f
    # The handler waits until every busy command has failed.
    f = host_findings("SHOST_RUNNING", busy=5, failed=2, blocked=0)
    assert states(f) == ["ERROR RECOVERY"] and "other 3" in f[0][1], f
    f = host_findings("SHOST_RUNNING", busy=0, failed=0, blocked=0,
                      eh_scheduled=1)
    assert "host reset scheduled" in f[0][1], f
    assert host_findings("SHOST_RUNNING", 30, 0, 0) == []
    assert states(host_findings("SHOST_DEL", 0, 0, 0)) == ["DEVICE OFFLINE"]
    assert states(host_findings("SHOST_RUNNING", 1, 0, 2)) == \
        ["DEVICE BLOCKED"]


def check_device_states_and_counters():
    assert states(device_findings("SDEV_TRANSPORT_OFFLINE")) == \
        ["DEVICE OFFLINE"]
    assert states(device_findings("SDEV_BLOCK")) == ["DEVICE BLOCKED"]
    assert states(device_findings("SDEV_RUNNING", blocked=3)) == \
        ["DEVICE BLOCKED"]
    assert device_findings("SDEV_RUNNING") == []
    f = device_findings("SDEV_RUNNING", ioerr=12, iotmo=None)
    assert states(f) == ["ERRORS SEEN"] and "12 error(s)" in f[0][1], f
    assert "ERRORS SEEN" not in PROBLEMS


def check_request_ages():
    assert queue_findings(0) == []
    assert states(queue_findings(3, oldest=0.2)) == ["BUSY"]
    assert states(queue_findings(3, oldest=7.0, timeout_sec=30)) == \
        ["I/O SLOW"]
    assert states(queue_findings(3, oldest=31.0, timeout_sec=180)) == \
        ["I/O STALLED"]
    # Past a short device timeout is stalled before STALL_SEC.
    f = queue_findings(1, oldest=12.0, timeout_sec=10)
    assert states(f) == ["I/O STALLED"] and "past its 10s" in f[0][1], f
    assert states(queue_findings(2, timedout=1, oldest=1.0)) == \
        ["I/O STALLED"]


def check_timer_restarted_by_the_driver():
    # Dispatched 0.0s ago by the timer, allocated 74s ago: an HBA reset
    # that keeps restarting the timer.
    f = queue_findings(33, oldest=0.0, started_alloc=74.1)
    assert states(f) == ["I/O STALLED"] and "restarted" in f[0][1], f
    assert states(queue_findings(33, oldest=0.0, started_alloc=3.0)) == \
        ["BUSY"]


def check_completions_not_processed():
    # MQ_RQ_COMPLETE for 713s with nothing at the device.
    f = queue_findings(0, held=20, done=20, done_oldest=713.2)
    assert states(f) == ["I/O STALLED"] and "completion" in f[0][1], f
    assert states(queue_findings(0, done=2, done_oldest=6.1)) == ["I/O SLOW"]
    assert queue_findings(0, done=2, done_oldest=0.5) == []


def check_queued_and_stopped():
    f = queue_findings(0, held=4, queued=4, queued_oldest=45.0)
    assert states(f) == ["I/O STALLED"] and "not sent" in f[0][1], f
    # A stopped queue explains the queued requests: one finding.
    f = queue_findings(0, held=4, stopped="quiesced", queued=4,
                       queued_oldest=45.0)
    assert states(f) == ["QUEUE STOPPED"], f
    assert queue_findings(0, stopped="quiesced") == []
    # Requests stuck at the device explain the queued ones behind them.
    f = queue_findings(17, oldest=73.5, queued=4, queued_oldest=73.5)
    assert states(f) == ["I/O STALLED"], f


def check_nvme_and_rports():
    assert states(nvme_findings("NVME_CTRL_RESETTING")) == ["ERROR RECOVERY"]
    assert states(nvme_findings("NVME_CTRL_DEAD")) == ["DEVICE OFFLINE"]
    assert nvme_findings("NVME_CTRL_LIVE") == []
    assert states(rport_findings("FC_PORTSTATE_BLOCKED")) == ["PATH DOWN"]
    assert rport_findings("FC_PORTSTATE_ONLINE") == []


def check_worst():
    assert worst(["BUSY", "I/O SLOW", "ERRORS SEEN"]) == "I/O SLOW"
    assert worst(["I/O STALLED", "ERROR RECOVERY"]) == "ERROR RECOVERY"
    assert worst([]) == "IDLE"


if (__name__ == '__main__'):
    checks = [v for k, v in sorted(globals().items()) if k.startswith('check_')]
    for check in checks:
        check()
        print("ok  %s" % check.__name__)
    print("\n%d checks passed" % len(checks))
