"""
Checks for grouping tasks by where they wait.

Run directly: python3 source/btgroup_test.py

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from btgroup import parse_foreach_bt, wait_key, report

BT = """PID: 812      TASK: ffff8d1a2b3c4000  CPU: 3    COMMAND: "jbd2/dm-0-8"
 #0 [ffffb5d8c3b9fb98] __schedule at ffffffffa7b39a2c
 #1 [ffffb5d8c3b9fc28] schedule at ffffffffa7b3a0e8
 #2 [ffffb5d8c3b9fc38] io_schedule at ffffffffa7b3a1c2
 #3 [ffffb5d8c3b9fc48] blk_mq_get_tag at ffffffffa76f8b11

PID: 1234     TASK: ffff8d1a2b3c8000  CPU: 1    COMMAND: "kworker/1:2"
 #0 [ffffb5d8c3c1fb98] __schedule at ffffffffa7b39a2c
 #1 [ffffb5d8c3c1fc28] schedule at ffffffffa7b3a0e8
 #2 [ffffb5d8c3c1fc38] io_schedule at ffffffffa7b3a1c2
 #3 [ffffb5d8c3c1fc48] blk_mq_get_tag at ffffffffa76f8b11

PID: 2001     TASK: ffff8d1a2b3cc000  CPU: 0    COMMAND: "postgres"
 #0 [ffffb5d8c3d1fb98] __schedule at ffffffffa7b39a2c
 #1 [ffffb5d8c3d1fc28] schedule at ffffffffa7b3a0e8
 #2 [ffffb5d8c3d1fc38] rwsem_down_read_slowpath at ffffffffa7b3c111
 #3 [ffffb5d8c3d1fc48] down_read at ffffffffa7b3c222
"""


def check_parse():
    tasks = parse_foreach_bt(BT)
    assert [t[0] for t in tasks] == [812, 1234, 2001]
    assert tasks[2][1] == "postgres"
    assert tasks[0][2][:2] == ["__schedule", "schedule"]


def check_key_skips_the_scheduler():
    assert wait_key(["__schedule", "schedule", "io_schedule", "blk_mq_get_tag"]) == \
        "io_schedule < blk_mq_get_tag"
    assert wait_key(["__schedule", "schedule"]) == "(scheduler only)"


def check_report():
    text = report(BT)
    lines = text.splitlines()
    assert "    2  io_schedule < blk_mq_get_tag" in "\n".join(lines)
    # The example backtrace is quoted exactly as crash printed it.
    assert ' #2 [ffffb5d8c3b9fc38] io_schedule at ffffffffa7b3a1c2' in lines
    rows = [l.split() for l in lines if l[:5].strip().isdigit()]
    assert rows[0][:5] == ["2", "io_schedule", "<", "blk_mq_get_tag", "812"], rows
    assert rows[1][:5] == ["1", "rwsem_down_read_slowpath", "<", "down_read", "2001"], rows


if (__name__ == '__main__'):
    checks = [v for k, v in sorted(globals().items()) if k.startswith('check_')]
    for check in checks:
        check()
        print("ok  %s" % check.__name__)
    print("\n%d checks passed" % len(checks))
