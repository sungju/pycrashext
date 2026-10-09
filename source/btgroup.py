"""
Group tasks by where they wait, from crash's 'foreach ... bt' output.

The top frames of a sleeping task are always the scheduler (__schedule,
schedule, ...), so the group key is the first two frames below them: where
the task actually blocked, e.g. "io_schedule < blk_mq_get_tag" or
"rwsem_down_read_slowpath < down_read". Used by 'hangcheck -g'.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import re

SCHED_FRAMES = {"__schedule", "schedule", "__switch_to", "context_switch",
                "schedule_preempt_disabled", "preempt_schedule_common"}

PID_RE = re.compile(r'^PID:\s*(\d+)\s+TASK:\s*(\S+).*COMMAND:\s*"(.*)"')
FRAME_RE = re.compile(r'^\s*#\d+\s+\[[0-9a-fA-F]+\]\s+(\S+)')


def parse_foreach_bt(text):
    """[(pid, comm, [frame functions], [raw lines])] from 'foreach bt' output."""
    tasks = []
    for line in text.splitlines():
        m = PID_RE.match(line)
        if m:
            tasks.append((int(m.group(1)), m.group(3), [], [line]))
            continue
        if not tasks:
            continue
        tasks[-1][3].append(line)
        f = FRAME_RE.match(line)
        if f:
            tasks[-1][2].append(f.group(1))
    return tasks


def wait_key(frames, depth=2):
    """Where a task waits: the first `depth` frames below the scheduler."""
    rest = [f for f in frames if f not in SCHED_FRAMES]
    return " < ".join(rest[:depth]) if rest else "(scheduler only)"


def group(tasks, depth=2):
    """[(key, [tasks])], largest group first."""
    groups = {}
    for t in tasks:
        groups.setdefault(wait_key(t[2], depth), []).append(t)
    return sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))


def report(text, command="foreach UN bt", examples=3, depth=2):
    """Table of groups (derived), then one raw backtrace per top group."""
    tasks = parse_foreach_bt(text)
    if not tasks:
        return "no tasks in '%s' output" % command
    groups = group(tasks, depth)
    out = ["%d task(s) grouped by where they wait (derived from '%s')" % (len(tasks), command),
           "", "%5s  %-48s %s" % ("COUNT", "WAITING IN", "PIDS")]
    for key, ts in groups:
        pids = " ".join(str(t[0]) for t in ts[:8]) + (" ..." if len(ts) > 8 else "")
        out.append("%5d  %-48s %s" % (len(ts), key, pids))
    for key, ts in groups[:examples]:
        out.append("")
        out.append("== %s: example, 'bt %d' as printed" % (key, ts[0][0]))
        raw = list(ts[0][3])
        while raw and not raw[-1].strip():
            raw.pop()
        out += raw
    return "\n".join(out)
