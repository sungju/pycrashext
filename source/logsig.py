"""
Kernel log signatures: which known messages a log holds, and what each one
points to.

Used by the 'logscan' command on a vmcore's 'log' output, and runnable on
any saved kernel log (dmesg, var/log/messages):
    python3 logsig.py <log file>

Each signature prints its count, the line numbers of its first and last
match, what it points to, and those lines exactly as the log has them, so a
report can quote them and anyone can find them again.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import re

# (key, what it points to, patterns). Order is the order of the report.
SIGNATURES = [
    ("panic", "the panic itself; see the reroute note when a sysctl caused it",
     [r"Kernel panic - not syncing"]),
    ("sysrq", "Branch D: the dump was triggered on purpose (sysrq, NMI); analyse why it was triggered",
     [r"SysRq\s*:\s*Trigger a crash", r"sysrq: Trigger a crash", r"NMI received for unknown reason",
      r"Kernel panic - not syncing: NMI"]),
    ("oops", "Branch A: a kernel fault",
     [r"BUG: unable to handle", r"general protection fault", r"kernel BUG at",
      r"invalid opcode:", r"Oops:", r"divide error:"]),
    ("corruption", "Branch A, use-after-free investigation: a corruption report, not a plain NULL dereference",
     [r"list_del corruption", r"list_add corruption", r"refcount_t: (underflow|overflow|saturated)",
      r"BUG: Bad page state", r"Slab corruption", r"Poison overwritten"]),
    ("stack", "Branch A, stack-overflow steps",
     [r"stack guard page was hit", r"double fault", r"corrupted stack end detected",
      r"Overran stack, or stack corrupted", r"stack-protector: Kernel stack is corrupted"]),
    ("atomic", "Branch A, atomic-context steps",
     [r"scheduling while atomic", r"BUG: sleeping function called from invalid context"]),
    ("init", "Branch E: death of init or the idle task",
     [r"Attempted to kill init", r"Attempted to kill the idle task"]),
    ("oom_cgroup", "Branch B, cgroup-constrained OOM",
     [r"Memory cgroup out of memory"]),
    ("oom_nokill", "Branch B, no killable processes",
     [r"Out of memory and no killable processes"]),
    ("oom", "Branch B: the OOM killer ran",
     [r"invoked oom-killer", r"Out of memory: Kill(ed)? process"]),
    ("softlockup", "Branch C: soft lockup",
     [r"BUG: soft lockup", r"watchdog: BUG: soft lockup"]),
    ("hardlockup", "Branch C: hard lockup",
     [r"hard LOCKUP"]),
    ("hung_task", "Branch C: hung tasks",
     [r"blocked for more than \d+ seconds"]),
    ("rcu_stall", "Branch C, RCU deep-dive",
     [r"rcu.*detected stalls? on CPU", r"rcu_\w+ self-detected stall", r"rcu_\w+ kthread starved",
      r"rcu_tasks.*grace period number", r"rcu: INFO: rcu_\w+ detected"]),
    ("netdev_timeout", "Branch C, network: the named driver is the primary suspect",
     [r"NETDEV WATCHDOG: .*transmit queue \d+ timed out"]),
    ("conntrack_full", "context: explains network drops before the dump; not a crash by itself",
     [r"nf_conntrack: table full, dropping packet"]),
    ("storage", "storage transport failure; filesystem errors that follow are collateral",
     [r"blk_update_request: I/O error", r"I/O error, dev \w+", r"timing out command",
      r"attempting task abort", r"hostbyte=DID_\w+", r"device-mapper: multipath: Failing path"]),
    ("hardware", "hardware evidence (MCE, ECC/EDAC)",
     [r"Machine check", r"mce: \[Hardware Error\]", r"\[Hardware Error\]", r"EDAC .*(CE|UE)"]),
    ("hypervisor", "virtual machine: a VM lockup or hang needs the hypervisor overcommit check",
     [r"Hypervisor detected"]),
    ("call_trace", "stack traces in the log (count only)",
     [r"Call Trace:"]),
]

# A detection sysctl that turned a condition into a panic: analyse the
# condition, not the panic.
REROUTES = [
    (r"Kernel panic - not syncing: softlockup: hung tasks",
     "kernel.softlockup_panic turned a soft lockup into this panic: analyse the lockup (Branch C)"),
    (r"Kernel panic - not syncing: hung_task: blocked tasks",
     "kernel.hung_task_panic turned a hung task into this panic: analyse the hung task (Branch C)"),
    (r"Kernel panic - not syncing: Out of memory",
     "vm.panic_on_oom turned an OOM into this panic: analyse the OOM (Branch B)"),
    (r"Kernel panic - not syncing: (Watchdog detected )?hard LOCKUP",
     "the hard-lockup watchdog panicked: analyse the lockup (Branch C)"),
    (r"Kernel panic - not syncing: sysrq triggered crash",
     "a sysrq crash: analyse why it was triggered (Branch D)"),
]

_COMPILED = [(k, why, [re.compile(p) for p in pats]) for k, why, pats in SIGNATURES]


def scan(lines):
    """{key: [line numbers, 1-based]} for every signature that matches."""
    hits = {}
    for n, line in enumerate(lines, 1):
        for key, _, pats in _COMPILED:
            if any(p.search(line) for p in pats):
                hits.setdefault(key, []).append(n)
    return hits


def reroute(lines, hits):
    """The reroute note for the panic line, or None."""
    for n in hits.get("panic", []):
        for pat, note in REROUTES:
            if re.search(pat, lines[n - 1]):
                return note
    return None


def report(lines, source="log", show_all=False):
    """The logscan report for these log lines."""
    hits = scan(lines)
    out = ["logscan: %d line(s) of '%s' scanned" % (len(lines), source)]
    note = reroute(lines, hits)
    if not hits:
        out.append("no known signature found")
        return "\n".join(out)
    out.append("")
    out.append("%-15s %6s %7s %7s  %s" % ("SIGNATURE", "COUNT", "FIRST", "LAST", "POINTS TO"))
    for key, why, _ in _COMPILED:
        if key in hits:
            ns = hits[key]
            out.append("%-15s %6d %7d %7d  %s" % (key, len(ns), ns[0], ns[-1], why))
    if note:
        out.append("")
        out.append("reroute: " + note)
    for key, why, _ in _COMPILED:
        if key not in hits or key == "call_trace":
            continue
        ns = hits[key]
        shown = ns if show_all else sorted(set([ns[0], ns[-1]]))
        out.append("")
        out.append("== %s: %d line(s); %s at %s line %s" % (
            key, len(ns), "all shown" if show_all or len(ns) <= 2 else "first and last shown",
            source, ", ".join(str(n) for n in shown)))
        for n in shown:
            out.append(lines[n - 1])
    out.append("")
    out.append("LOGSCAN " + " ".join("%s=%d" % (k, len(hits[k])) for k, _, _ in _COMPILED if k in hits))
    return "\n".join(out)


if (__name__ == '__main__'):
    import sys
    if len(sys.argv) != 2:
        sys.stderr.write("usage: logsig.py <kernel log file>\n")
        sys.exit(2)
    with open(sys.argv[1], errors="replace") as f:
        print(report(f.read().splitlines(), source=sys.argv[1]))
