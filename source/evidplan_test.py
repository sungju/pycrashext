"""
Checks for the 'evidence' plan (evidplan.py).

Run directly: python3 source/evidplan_test.py

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import evidplan
from evidplan import (parse_sys, task_from_dumpfile, parse_exception, fault_address,
                      classify, base_steps, branch_steps, cap, clean, fence_for,
                      pipe_filter, block, render, Step)

SYS = """      KERNEL: /usr/lib/debug/lib/modules/4.18.0-553.el8_10.x86_64/vmlinux
    DUMPFILE: /cores/tasks/886244457/crash/vmcore  [PARTIAL DUMP]
        CPUS: 8
        DATE: Mon Oct 12 01:02:03 UTC 2026
      UPTIME: 10 days, 02:03:04
LOAD AVERAGE: 0.10, 0.20, 0.30
       TASKS: 512
    NODENAME: host1.example.com
     RELEASE: 4.18.0-553.el8_10.x86_64
     MACHINE: x86_64  (2100 Mhz)
       PANIC: "BUG: unable to handle kernel NULL pointer dereference at 0000000000000008"
"""

BT = """PID: 1234     TASK: ffff8c1a2b3c4d00  CPU: 3    COMMAND: "kworker/3:1"
 #0 [ffffa1b2c3d4e000] machine_kexec at ffffffff8a26a1ae
 #1 [ffffa1b2c3d4e058] __crash_kexec at ffffffff8a39d3fa
 #2 [ffffa1b2c3d4e120] crash_kexec at ffffffff8a39e2e1
 #3 [ffffa1b2c3d4e138] oops_end at ffffffff8a22a7c1
 #4 [ffffa1b2c3d4e158] no_context at ffffffff8a27ab1c
 #5 [ffffa1b2c3d4e1b0] __bad_area_nosemaphore at ffffffff8a27ae7c
 #6 [ffffa1b2c3d4e1f8] do_page_fault at ffffffff8a27b9a2
 #7 [ffffa1b2c3d4e230] page_fault at ffffffff8ac0111e
    [exception RIP: foo_bar+21]
    RIP: ffffffffc0a1b2c5  RSP: ffffa1b2c3d4e2e8  RFLAGS: 00010246
    RAX: 0000000000000000  RBX: ffff8c1a2b3c4d00  RCX: 0000000000000000
 #8 [ffffa1b2c3d4e2f0] foo_bar at ffffffffc0a1b2c5 [mydrv]
 #9 [ffffa1b2c3d4e320] process_one_work at ffffffff8a2d3e47
"""


def check_parse_sys():
    f = parse_sys(SYS)
    assert f["RELEASE"] == "4.18.0-553.el8_10.x86_64"
    assert f["LOAD AVERAGE"] == "0.10, 0.20, 0.30"
    assert f["PANIC"].startswith('"BUG: unable to handle')


def check_task_from_dumpfile():
    assert task_from_dumpfile("/cores/tasks/886244457/crash/vmcore  [PARTIAL DUMP]") == \
        ("886244457", "/cores/tasks/886244457/")
    assert task_from_dumpfile("/var/crash/127.0.0.1/vmcore") == (None, None)


def check_parse_exception():
    e = parse_exception(BT)
    assert e["pid"] == "1234" and e["cpu"] == "3" and e["command"] == "kworker/3:1", e
    assert e["func"] == "foo_bar" and e["offset"] == "21", e
    assert e["rip"] == "ffffffffc0a1b2c5", e
    assert e["module"] == "mydrv", e
    none = parse_exception('PID: 0  TASK: ffffffff8b412840  CPU: 0  COMMAND: "swapper/0"\n #0 [x] machine_kexec at ffff\n')
    assert none["func"] == "" and none["rip"] == "" and none["module"] == ""


def check_fault_address():
    assert fault_address("BUG: unable to handle kernel NULL pointer dereference at 0000000000000008") == "0000000000000008"
    assert fault_address("BUG: unable to handle page fault for address: ffff9a3b00000010") == "ffff9a3b00000010"
    assert fault_address("BUG: unable to handle kernel paging request at ffffffffc0ffee00") == "ffffffffc0ffee00"
    assert fault_address("Kernel panic - not syncing: Fatal exception") == ""
    assert evidplan.near_null("0000000000000008") and not evidplan.near_null("ffff9a3b00000010")


def check_classify_oops():
    c = classify(parse_sys(SYS), ["[  10.0] BUG: unable to handle kernel NULL pointer dereference at 0000000000000008"])
    assert c["branches"] == ["A"], c
    assert not c["vm"]


def check_classify_reroute_and_vm():
    log = ["[0.0] Hypervisor detected: VMware",
           "[100.0] INFO: task jbd2/dm-0-8:812 blocked for more than 120 seconds.",
           "[200.0] Kernel panic - not syncing: hung_task: blocked tasks"]
    c = classify({"PANIC": "Kernel panic - not syncing: hung_task: blocked tasks"}, log)
    assert c["branches"] == ["C"], c
    assert c["reroute"] and c["vm"]


def check_classify_counts_log_lines_only():
    c = classify({"PANIC": '"BUG: unable to handle kernel NULL pointer dereference at 0000000000000008"'},
                 ["[1.0] BUG: unable to handle kernel NULL pointer dereference at 0000000000000008"])
    assert c["hits"]["oops"] == [1], c["hits"]
    lost = classify({"PANIC": "Kernel panic - not syncing: hung_task: blocked tasks"}, ["[1.0] wrapped"])
    assert lost["branches"] == ["C"] and lost["hits"]["panic"] == [0] and lost["reroute"], lost


def check_classify_sysrq_adds_hang():
    c = classify({"PANIC": "SysRq : Trigger a crash"}, ["[1.0] sysrq: Trigger a crash"])
    assert c["branches"] == ["C", "D"], c


def check_classify_unknown_runs_a_and_c():
    c = classify({"PANIC": ""}, ["[1.0] nothing interesting"])
    assert c["branches"] == ["A", "C"], c


def check_branch_steps_follow_the_fault():
    c = classify(parse_sys(SYS), ["BUG: unable to handle kernel NULL pointer dereference at 0000000000000008"])
    cmds = [s.cmd for s in branch_steps(c, parse_exception(BT), parse_sys(SYS))]
    assert cmds[:3] == ["edis -r ffffffffc0a1b2c5", "sym ffffffffc0a1b2c5", "modinfo --details mydrv"], cmds
    # A near-NULL fault address is not looked up in the slab.
    assert not any(x.startswith("kmem ") for x in cmds)


def check_branch_steps_hang_on_vm():
    log = ["Hypervisor detected: KVM", "watchdog: BUG: soft lockup - CPU#2 stuck for 22s!",
           "rcu: INFO: rcu_sched detected stalls on CPUs/tasks:"]
    c = classify({"PANIC": "Kernel panic - not syncing: softlockup: hung tasks"}, log)
    cmds = [s.cmd for s in branch_steps(c, parse_exception(""), {})]
    for want in ("bt -a", "runq -m", "hangcheck -g", "lockup -r -d", "rcuinfo -s", "vminfo --overcommit -d"):
        assert want in cmds, (want, cmds)
    assert len(cmds) == len(set(cmds))


def check_base_steps_first_is_sys():
    names = [s.cmd for s in base_steps()]
    assert names[0] == "sys" and "log" in names and "logscan" in names


def check_cap_counts_what_it_leaves_out():
    lines = ["l%d" % i for i in range(1, 101)]
    kept, left = cap(lines, 3, 2)
    assert kept == ["l1", "l2", "l3", "<<< SKIPPED 95 lines >>>", "l99", "l100"] and left == 95
    tail_only, left = cap(lines, 0, 2)
    assert tail_only == ["<<< SKIPPED 98 lines >>>", "l99", "l100"]
    assert cap(lines[:5], 3, 2) == (lines[:5], 0)
    assert cap(lines, 0, 0) == (lines, 0)
    assert cap(lines[:6], 2, 3)[0][2] == "<<< SKIPPED 1 line >>>"


def check_clean_and_fence():
    assert clean("\x1b[1;31mred\x1b[0m\r\n\nx\n\n") == ["red", "", "x"]
    assert fence_for(["a", "~~~~ b"]) == "~~~~~"
    assert fence_for(["a"]) == "~~~"


def check_pipe_filter():
    lines = ["alpha 1", "beta 2", "Alpha 3"]
    assert pipe_filter(lines, "grep -i alpha") == ["alpha 1", "Alpha 3"]
    assert pipe_filter(lines, "grep -v alpha") == ["beta 2", "Alpha 3"]
    assert pipe_filter(lines, "head -n 1") == ["alpha 1"]
    assert pipe_filter(lines, "tail -2") == ["beta 2", "Alpha 3"]
    assert pipe_filter(lines, "wc -l") == ["3"]
    assert pipe_filter(lines, "awk '{print}'") is None
    odd = ["a (x) 1", "b|c 2", "nfs 3"]
    # Basic grep: ( and | are literal, \\| is alternation; -E is extended.
    assert pipe_filter(odd, "grep (x") == ["a (x) 1"]
    assert pipe_filter(odd, "grep b|c") == ["b|c 2"]
    assert pipe_filter(odd, r"grep 'nfs\|b'") == ["b|c 2", "nfs 3"]
    assert pipe_filter(odd, "grep -E 'nfs|b'") == ["b|c 2", "nfs 3"]
    # What cannot be done as the real command would is refused, never guessed.
    for stage in ("grep -c nfs", "grep -A 2 nfs", "tail -n +2", "grep -E '(x'"):
        assert pipe_filter(odd, stage) is None, stage


def check_block_and_render():
    s = Step("bt", "Backtrace of the crashing task")
    b = block(s, "886244457", ["PID: 1", "<<< SKIPPED 5 lines >>>", "#9 x"], 5, "ok", 1.0)
    text = "\n".join(b)
    assert "**Source:** `/cores/tasks/886244457` → `bt`" in text
    assert "~~~\nPID: 1\n<<< SKIPPED 5 lines >>>\n#9 x\n~~~" in text
    c = classify(parse_sys(SYS), ["BUG: unable to handle kernel NULL pointer dereference at 0000000000000008"])
    doc = render({"task": "886244457", "case": "04517832", "host": "h", "kernel": "k",
                  "when": "now", "panic": "BUG"}, c, parse_exception(BT), [b], ["kmem -i: timed out"])
    assert doc.startswith("# VMCORE EVIDENCE — task `886244457`")
    assert "**Case Number:** `04517832`" in doc
    assert "## Summary (derived by `evidence`, not crash output)" in doc
    assert "Fault:** foo_bar+21 [mydrv] in pid 1234 (kworker/3:1) on CPU 3" in doc
    assert "Not collected:** kmem -i: timed out" in doc


def main():
    n = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("check_") and callable(fn):
            fn()
            n += 1
    print("evidplan: %d checks passed" % n)


if __name__ == "__main__":
    main()
