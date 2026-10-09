"""
Checks for preempt_count decoding.

Run directly: python3 source/preemptcount_test.py

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from preemptcount import decode, describe, from_log


def check_fields():
    assert decode(0x00010002) == {"preempt": 2, "softirq_serving": 0, "bh_disabled": 0,
                                  "hardirq": 1, "nmi": 0}
    assert decode(0x00000101)["softirq_serving"] == 1
    assert decode(0x00000200)["bh_disabled"] == 1
    assert decode(0x00100000)["nmi"] == 1
    # x86's inverted PREEMPT_NEED_RESCHED bit is not part of the count.
    assert decode(0x80000000) == decode(0)


def check_describe():
    assert describe(0).endswith("not atomic")
    assert "in a hard interrupt" in describe(0x00010000)
    assert describe(0x1).endswith("atomic context: sleeping here is a bug")


def check_log_formats():
    lines = ["[ 5.0] BUG: scheduling while atomic: swapper/0/0/0x00010002",
             "[ 6.0] preempt_count: 1, expected: 0",
             "[ 7.0] corrupted preempt_count: kworker/1:1/77/0x2",
             "[ 8.0] nothing here"]
    assert [v for _, v in from_log(lines)] == [0x00010002, 0x1, 0x2]


if (__name__ == '__main__'):
    checks = [v for k, v in sorted(globals().items()) if k.startswith('check_')]
    for check in checks:
        check()
        print("ok  %s" % check.__name__)
    print("\n%d checks passed" % len(checks))
