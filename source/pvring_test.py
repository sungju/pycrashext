"""
Checks for the paravirtual I/O ring arithmetic and verdicts.

Run directly: python3 source/pvring_test.py

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from pvring import (virtio_split, pvscsi, vmbus, verdict, worst,
                    is_request_queue, swap16, PROBLEMS)


def check_virtio_indices_wrap_at_16_bits():
    c = virtio_split(avail_idx=3, used_idx=65533, last_used_idx=65533)
    assert c == {"host": 6, "guest": 0, "kick": 0}, c
    c = virtio_split(10, 10, 7, num_added=2)
    assert (c["host"], c["guest"], c["kick"]) == (0, 3, 2)


def check_pvscsi_and_vmbus():
    c = pvscsi(req_prod=110, req_cons=105, cmp_prod=100, cmp_cons=100)
    assert (c["host"], c["not_taken"], c["guest"]) == (10, 5, 0)
    assert pvscsi(2, 2, 1, 0xffffffff)["guest"] == 2          # 32-bit wrap
    c = vmbus(100, 4000, 4096, 50, 50, 4096)
    assert (c["host"], c["guest"]) == (196, 0)


def check_verdicts():
    host = {"host": 12, "guest": 0, "kick": 0}
    assert verdict(host, 47.2)[0] == "HOST STALLED"
    assert verdict(host, 7.0)[0] == "HOST SLOW"
    assert verdict(host, 0.2)[0] == "IN FLIGHT"
    assert verdict(host, None)[0] == "IN FLIGHT"
    assert verdict(host, 99, broken=True)[0] == "BROKEN"
    assert verdict({"host": 0, "guest": 0, "kick": 0})[0] == "IDLE"


def check_guest_is_blamed_only_when_it_holds_everything():
    # A fresh completion beside a request stuck at the host: the host.
    mixed = verdict({"host": 3, "guest": 1, "kick": 0}, 60.0)
    assert mixed[0] == "HOST STALLED" and "also wait" in mixed[1], mixed
    assert verdict({"host": 0, "guest": 4, "kick": 0}, 40.0)[0] == \
        "GUEST NOT PROCESSING"
    assert "poll queue" in verdict({"host": 0, "guest": 1, "kick": 0}, 9.0,
                                   polled=True)[1]
    # Unkicked entries are inside avail, so 'not notified' needs host == kick.
    assert verdict({"host": 2, "guest": 0, "kick": 2}, 9.0)[0] == \
        "GUEST NOT NOTIFIED"
    assert verdict({"host": 5, "guest": 0, "kick": 1}, 9.0)[0] == "HOST SLOW"


def check_receive_queues_are_not_judged():
    assert not is_request_queue("input.0")
    assert not is_request_queue("event")
    assert is_request_queue("req.0") and is_request_queue("output.1")
    assert verdict({"host": 256, "guest": 0, "kick": 0}, 99,
                   request_queue=False)[0] == "n/a"


def check_worst():
    assert worst(["IDLE", "HOST SLOW", "IN FLIGHT"]) == "HOST SLOW"
    assert worst(["GUEST NOT PROCESSING", "HOST STALLED"]) == "HOST STALLED"
    assert worst([]) == "IDLE"
    assert "IN FLIGHT" not in PROBLEMS
    assert swap16(0x1234) == 0x3412


if (__name__ == '__main__'):
    checks = [v for k, v in sorted(globals().items()) if k.startswith('check_')]
    for check in checks:
        check()
        print("ok  %s" % check.__name__)
    print("\n%d checks passed" % len(checks))
