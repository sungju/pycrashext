"""
Decode a preempt_count value into what it says about the context.

Layout (include/linux/preempt.h): bits 0-7 preempt-disable depth, bits 8-15
softirq (bit 8 set = serving a softirq; the rest, in steps of 2, is the
local_bh_disable() depth), bits 16-19 hardirq nesting, bits 20-23 NMI (one
bit on 4.18 kernels, four on 5.x). Bit 31 on x86 is PREEMPT_NEED_RESCHED,
stored inverted; preempt_count() as the kernel prints it masks it out.

    python3 preemptcount.py 0x00010002 ...

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import re


def decode(value):
    """{field: number} for a preempt_count value."""
    v = value & 0x7fffffff
    soft = (v >> 8) & 0xff
    return {
        "preempt": v & 0xff,
        "softirq_serving": soft & 1,
        "bh_disabled": soft >> 1,
        "hardirq": (v >> 16) & 0xf,
        "nmi": (v >> 20) & 0xf,
    }


def describe(value):
    d = decode(value)
    parts = ["preempt-disable depth %d%s" % (d["preempt"],
             " (preempt_disable or a spinlock held)" if d["preempt"] else "")]
    parts.append("serving a softirq" if d["softirq_serving"] else "not in a softirq")
    if d["bh_disabled"]:
        parts.append("bottom halves disabled (depth %d)" % d["bh_disabled"])
    parts.append("hardirq nesting %d%s" % (d["hardirq"], " (in a hard interrupt)" if d["hardirq"] else ""))
    if d["nmi"]:
        parts.append("in an NMI")
    atomic = d["preempt"] or d["softirq_serving"] or d["bh_disabled"] or d["hardirq"] or d["nmi"]
    return "0x%08x: %s -> %s" % (value, "; ".join(parts),
                                  "atomic context: sleeping here is a bug" if atomic
                                  else "not atomic")


# Where the kernel prints a preempt_count.
LOG_PATTERNS = [
    re.compile(r"BUG: scheduling while atomic: \S+?/\d+/(0x[0-9a-fA-F]+)"),
    re.compile(r"corrupted preempt_count: \S+?/\d+/(0x[0-9a-fA-F]+)"),
    re.compile(r"preempt_count: ([0-9a-fA-F]+),"),
]


def from_log(lines):
    """[(line, value)] for every log line that prints a preempt_count."""
    found = []
    for line in lines:
        for pat in LOG_PATTERNS:
            m = pat.search(line)
            if m:
                found.append((line, int(m.group(1), 16)))
                break
    return found


def report_log(lines, source="log"):
    found = from_log(lines)
    if not found:
        return "no preempt_count in '%s'" % source
    out = []
    for line, value in found:
        out.append(line)
        out.append("  decoded (derived from the line above): " + describe(value))
    return "\n".join(out)


if (__name__ == '__main__'):
    import sys
    if len(sys.argv) < 2:
        sys.stderr.write("usage: preemptcount.py <value>...\n")
        sys.exit(2)
    for a in sys.argv[1:]:
        print(describe(int(a, 0)))
