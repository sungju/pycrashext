"""
The plan behind the 'evidence' command, kept free of crash so it can be
tested on saved output.

'evidence' collects, in one crash session, the raw output a vmcore analysis
rests on, so an AI (or an engineer) can write the report from one file
instead of driving crash one command at a time. This module decides what to
run and how to lay it out:

  classify()      which analysis branch(es) the dump calls for, from 'sys'
                  and the kernel log signatures in logsig.py
  base_steps()    what every dump gets
  branch_steps()  what each branch adds, with follow-ups taken from the
                  output already collected (the faulting function, module,
                  address)
  cap()           cuts a long output to its first and last lines with a
                  '<<< SKIPPED N lines >>>' line carrying the true count
  render()        the evidence file: a derived summary, then one block per
                  command, each under its Source line

Run the checks: python3 evidplan_test.py

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import re

import logsig

BRANCH_NAMES = {
    "A": "Panic / Oops",
    "B": "Out of Memory",
    "C": "Hang / Lockup / Stall",
    "D": "Sysrq-triggered crash",
    "E": "Death of init",
}

# logsig keys -> branch
SIG_BRANCH = {
    "oops": "A", "corruption": "A", "stack": "A", "atomic": "A",
    "oom": "B", "oom_cgroup": "B", "oom_nokill": "B",
    "softlockup": "C", "hardlockup": "C", "hung_task": "C", "rcu_stall": "C",
    "netdev_timeout": "C",
    "sysrq": "D",
    "init": "E",
}

# The pycrashext commands 'evidence' runs in-process (crash does not expand
# their aliases for a command run from Python). Anything else is a crash
# command.
PYCRASHEXT = {
    "caseinfo", "sysinfo", "logscan", "autocheck", "edis", "modinfo",
    "preempt", "meminfo", "cginfo", "hangcheck", "lockup", "rcuinfo",
    "netinfo", "devinfo", "vminfo", "kvercmp", "psinfo", "schedinfo",
    "lockinfo", "fsinfo", "cpuinfo", "git", "insights", "pstree", "bh",
}

# Modules beside the commands that are not commands themselves.
HELPERS = {
    "crashhelper", "crashcolor", "evidplan", "logsig", "sysenv", "netutil",
    "kernel_version", "overcommit", "preemptcount", "rules_helper", "regext",
    "reg_all_ext", "cmds_test", "disasm", "get_x86asm", "revs", "screen",
    "ai_send", "btgroup", "fsfreeze", "pvring", "storstat", "lockdecode",
    "__init__",
}


class Step(object):
    """One command to run: what it is for, and how much of it to keep."""

    def __init__(self, cmd, title, head=60, tail=40, why=""):
        self.cmd = cmd
        self.title = title
        self.head = head
        self.tail = tail
        self.why = why

    def __repr__(self):
        return "Step(%r)" % self.cmd


# ------------------------------------------------------------- parsing ---

def parse_sys(text):
    """'sys' output as {FIELD: value}."""
    fields = {}
    for line in text.splitlines():
        m = re.match(r"\s*([A-Z][A-Z ]*[A-Z]):\s?(.*)$", line)
        if m:
            fields[m.group(1).strip()] = m.group(2).strip()
    return fields


def task_from_dumpfile(path):
    """(task_id, task_dir) from a DUMPFILE path such as
    /cores/tasks/886244457/crash/vmcore, the way 'caseinfo' finds the
    case file; (None, None) when the path holds no task."""
    path = (path or "").split()[0] if path else ""
    m = re.search(r"/tasks/(\d+)(/|$)", path)
    if not m:
        return None, None
    return m.group(1), path[:m.end(1)] + "/"


def parse_exception(bt_text):
    """What 'bt' says about the fault: pid, cpu, command, the faulting
    function and offset, its module, and the RIP address. Empty values when
    'bt' shows no exception frame (e.g. a panic() call or a sysrq dump)."""
    out = {"pid": "", "cpu": "", "command": "", "func": "", "offset": "",
           "module": "", "rip": ""}
    m = re.search(r'PID:\s*(\d+)\s+TASK:\s*\S+\s+CPU:\s*(\d+)\s+COMMAND:\s*"([^"]*)"', bt_text)
    if m:
        out["pid"], out["cpu"], out["command"] = m.group(1), m.group(2), m.group(3)
    m = re.search(r"\[exception RIP:\s*([A-Za-z0-9_.$]+)(?:\+(0x[0-9a-fA-F]+|\d+))?", bt_text)
    if m:
        out["func"] = m.group(1)
        out["offset"] = m.group(2) or ""
    m = re.search(r"^\s*RIP:\s*([0-9a-fA-F]{8,16})\b", bt_text, re.M)
    if m:
        out["rip"] = m.group(1)
    if out["func"]:
        # The frame that names the function, or the RIP, with its module.
        for line in bt_text.splitlines():
            fm = re.search(r"\b%s\b.*\[([A-Za-z0-9_]+)\]\s*$" % re.escape(out["func"]), line)
            if fm:
                out["module"] = fm.group(1)
                break
            if out["rip"] and out["rip"] in line:
                mm = re.search(r"\[([A-Za-z0-9_]+)\]\s*$", line)
                if mm and not line.strip().startswith("RIP"):
                    out["module"] = mm.group(1)
                    break
    return out


def fault_address(panic_line):
    """The address a 'BUG: unable to handle ... at <addr>', 'paging request
    at <addr>' or 'page fault for address: <addr>' panic names, or ''."""
    m = re.search(r"(?:\bat|\baddress:?)\s+(?:0x)?([0-9a-fA-F]{8,16})\b", panic_line or "")
    return m.group(1) if m else ""


def near_null(addr):
    try:
        return int(addr, 16) < 0x10000
    except (TypeError, ValueError):
        return True


# ------------------------------------------------------- classification ---

def classify(sys_fields, log_lines):
    """Which branches to run, and why.

    {'branches': ['A', 'C'], 'hits': {...}, 'reroute': str or None,
     'reasons': [str], 'vm': bool}
    """
    panic = sys_fields.get("PANIC", "").strip('"')
    lines = list(log_lines)
    hits = logsig.scan(lines)
    note = logsig.reroute(lines, hits)
    # The 'sys' panic string counts when the log lost the line (a wrapped
    # ring buffer): its signatures are recorded at line 0.
    if panic:
        p_hits = logsig.scan([panic])
        for key in p_hits:
            hits.setdefault(key, [0])
        if not note:
            note = logsig.reroute([panic], p_hits)
    reasons = []
    branches = []

    def add(b, why):
        if b not in branches:
            branches.append(b)
            reasons.append("%s (%s): %s" % (b, BRANCH_NAMES[b], why))

    if note:
        m = re.search(r"\(Branch ([A-E])\)", note)
        if m:
            add(m.group(1), note)
    for key, _, _ in logsig.SIGNATURES:
        b = SIG_BRANCH.get(key)
        if b and key in hits:
            add(b, "log signature '%s' (%d line(s))" % (key, len(hits[key])))
    if re.search(r"sysrq|SysRq", panic):
        add("D", "the panic string names sysrq")
    if "D" in branches:
        add("C", "a sysrq dump is usually taken during a hang")
    if not branches:
        add("A", "no known signature: run Panic / Oops")
        add("C", "no known signature: run Hang / Lockup too")
    branches.sort()
    return {"branches": branches, "hits": hits, "reroute": note,
            "reasons": reasons, "vm": "hypervisor" in hits}


# ---------------------------------------------------------------- steps ---

def base_steps():
    """What every dump gets, in this order."""
    return [
        Step("sys", "System summary", 80, 0),
        Step("caseinfo", "Case number and collection date", 20, 0),
        Step("sysinfo", "What the machine was (platform, release, taint, software)", 140, 20),
        Step("bt", "Backtrace of the crashing task", 70, 40),
        Step("logscan", "Known kernel log signatures", 120, 40),
        Step("log", "Kernel log, last lines", 0, 150),
        Step("mod -t", "Tainted modules", 40, 10),
        Step("kmem -i", "Memory at the crash", 40, 0),
        Step("ps -S", "Task states", 30, 0),
        Step("autocheck", "Known-issue rules (pycrashext)", 60, 20),
    ]


def branch_steps(cls, exc, sys_fields):
    """The steps the branches add. 'exc' is parse_exception() of 'bt'."""
    steps = []
    hits = cls["hits"]
    br = cls["branches"]
    if "A" in br:
        if exc.get("rip"):
            steps.append(Step("edis -r %s" % exc["rip"], "Disassembly up to the faulting instruction", 0, 70,
                              "the instructions and source lines that led to the fault"))
            steps.append(Step("sym %s" % exc["rip"], "Faulting address symbol", 10, 0))
        elif exc.get("func"):
            steps.append(Step("edis -f %s" % exc["func"], "Disassembly of the faulting function", 60, 60))
        if exc.get("module"):
            steps.append(Step("modinfo --details %s" % exc["module"], "Faulting module", 60, 20))
        addr = fault_address(sys_fields.get("PANIC", ""))
        if "corruption" in hits and addr and not near_null(addr):
            steps.append(Step("kmem %s" % addr, "Slab state of the faulting address", 40, 10))
        if "stack" in hits:
            steps.append(Step("bt -v", "Stack overflow check, all tasks", 40, 20))
        if "atomic" in hits:
            steps.append(Step("preempt -l", "preempt_count decoded", 40, 10))
    if "B" in br:
        steps.append(Step("meminfo --oom-summary", "OOM summary", 100, 40))
        steps.append(Step("meminfo --oom-top 10", "Top memory consumers", 40, 0))
        steps.append(Step("meminfo -s", "Slab caches", 40, 0))
        if "oom_cgroup" in hits:
            steps.append(Step("cginfo -m", "Memory by cgroup", 40, 0))
    if "C" in br:
        steps.append(Step("bt -a", "Active task on every CPU", 120, 80))
        steps.append(Step("runq -m", "How long each CPU's task has run", 70, 20))
        steps.append(Step("hangcheck -g", "D-state tasks grouped by where they wait", 120, 40))
        steps.append(Step("lockinfo -a", "Lock owners, waiters, deadlocks and where the wait chains end",
                          150, 60, "who holds what the stuck CPUs and hung tasks wait for"))
        if "softlockup" in hits or "hardlockup" in hits:
            steps.append(Step("lockup -r -d", "Locked-up CPUs, longest first", 80, 40))
        if "rcu_stall" in hits:
            steps.append(Step("rcuinfo -s", "RCU stall messages parsed", 60, 20))
            steps.append(Step("rcuinfo -g", "RCU grace period state", 40, 10))
            steps.append(Step("rcuinfo -t", "Tasks blocking RCU", 40, 20))
        if "netdev_timeout" in hits:
            steps.append(Step("netinfo -i -d", "Network interfaces and drivers", 60, 20))
        if "storage" in hits:
            steps.append(Step("devinfo -s", "Storage status: SCSI hosts, devices, stuck I/O", 60, 20))
            steps.append(Step("devinfo -q", "Block requests queued or in flight", 60, 20))
    if "E" in br:
        steps.append(Step("bt 1", "Backtrace of init", 50, 20))
        steps.append(Step("ps 1", "init task", 10, 0))
    if cls.get("vm") and ("C" in br or "D" in br or not br):
        steps.append(Step("vminfo --overcommit -d", "Hypervisor overcommit check", 80, 20,
                          "mandatory for a hang on a VM"))
    # Never run the same command twice.
    seen, out = set(), []
    for s in steps:
        if s.cmd not in seen:
            seen.add(s.cmd)
            out.append(s)
    return out


# ----------------------------------------------------------- formatting ---

def cap(lines, head, tail):
    """The first 'head' and last 'tail' lines, with one
    '<<< SKIPPED N lines >>>' line for what was left out. head=tail=0 keeps
    everything."""
    lines = list(lines)
    if head <= 0 and tail <= 0:
        return lines, 0
    if len(lines) <= head + tail:
        return lines, 0
    left = len(lines) - head - tail
    word = "line" if left == 1 else "lines"
    return lines[:head] + ["<<< SKIPPED %d %s >>>" % (left, word)] + (lines[-tail:] if tail else []), left


def clean(text):
    """Output as plain lines: no ANSI codes, no carriage returns, no trailing
    blank lines."""
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text or "").replace("\r", "")
    lines = [l.rstrip() for l in text.split("\n")]
    while lines and not lines[-1]:
        lines.pop()
    while lines and not lines[0]:
        lines.pop(0)
    return lines


def fence_for(lines):
    """A tilde fence longer than any tilde run inside the block."""
    longest = 0
    for l in lines:
        m = re.match(r"\s*(~+)", l)
        if m:
            longest = max(longest, len(m.group(1)))
    return "~" * max(3, longest + 1)


def pipe_filter(lines, stage):
    """Apply one '| grep/head/tail/wc' stage, the narrowing the skills
    allow, to output lines. None when the stage is not one this can do the
    way the real command would (the citation is rerun through a real shell
    pipe, so a different result would not match)."""
    words = stage.split()
    if not words:
        return lines
    cmd = words[0]
    if cmd == "grep":
        invert = ignore = extended = False
        args = words[1:]
        while args and args[0].startswith("-") and len(args[0]) > 1:
            flags = args[0][1:]
            if not all(c in "viE" for c in flags):
                return None
            invert = invert or "v" in flags
            ignore = ignore or "i" in flags
            extended = extended or "E" in flags
            args = args[1:]
        if not args:
            return None
        pat = " ".join(args)
        if len(pat) > 1 and pat[0] == pat[-1] and pat[0] in "'\"":
            pat = pat[1:-1]
        if not extended:
            # Basic grep: \| is alternation, a bare ( ) | + ? { } is literal.
            pat = re.sub(r"\\([|()?+{}])", "\x00\\1", pat)
            pat = re.sub(r"([|()?+{}])", r"\\\1", pat)
            pat = re.sub("\x00\\\\(.)", r"\1", pat)
        try:
            rx = re.compile(pat, re.I if ignore else 0)
        except re.error:
            return None
        return [l for l in lines if bool(rx.search(l)) != invert]
    if cmd in ("head", "tail"):
        n = 10
        args = words[1:]
        if args and args[0] == "-n" and len(args) > 1:
            args = args[1:]
        if len(args) > 1 or (args and args[0].startswith("+")):
            return None
        if args:
            try:
                n = abs(int(args[0].lstrip("-")))
            except ValueError:
                return None
        return lines[:n] if cmd == "head" else (lines[-n:] if n else [])
    if cmd == "wc" and words[1:] == ["-l"]:
        return [str(len(lines))]
    return None


def block(step, task, lines, skipped, status, secs):
    """One evidence block: heading, Source line, raw output."""
    src = "/cores/tasks/%s" % task if task else "vmcore"
    out = ["### %s" % step.title, ""]
    out.append("**Source:** `%s` → `%s`" % (src, step.cmd))
    out.append("")
    if status != "ok":
        out.append("> %s (%.0fs)" % (status, secs))
        out.append("")
    if lines:
        f = fence_for(lines)
        out.append(f)
        out.extend(lines)
        out.append(f)
    else:
        out.append("> (no output)")
    if skipped:
        out.append("")
        out.append("> %d line(s) left out at the marker; rerun the command, narrowed "
                   "(`| grep`, `| head -n N`, `| tail -n N`), to see them." % skipped)
    out.append("")
    return out


def render(meta, cls, exc, blocks, failed):
    """The whole evidence file."""
    task = meta.get("task") or "unknown"
    out = ["# VMCORE EVIDENCE — task `%s`" % task, ""]
    out.append("**Case Number:** `%s` · **Host:** `%s` · **Kernel:** `%s` · **Collected:** %s by "
               "pycrashext `evidence`" % (meta.get("case") or "unknown", meta.get("host", ""),
                                          meta.get("kernel", ""), meta.get("when", "")))
    out.append("")
    out.append("Every fenced block below is the output of the crash command on its Source line, "
               "exactly as printed (colour codes removed). A `<<< SKIPPED N lines >>>` line "
               "stands for N real lines left out at that point. Only the Summary is derived.")
    out.append("")
    out.append("## Summary (derived by `evidence`, not crash output)")
    out.append("")
    out.append("- **Panic:** %s" % (meta.get("panic") or "none recorded"))
    out.append("- **Branches:** %s" % ", ".join("%s %s" % (b, BRANCH_NAMES[b]) for b in cls["branches"]))
    for r in cls["reasons"]:
        out.append("  - %s" % r)
    if cls.get("reroute"):
        out.append("- **Reroute:** %s" % cls["reroute"])
    if exc.get("func"):
        out.append("- **Fault:** %s%s%s in pid %s (%s) on CPU %s" % (
            exc["func"], "+" + exc["offset"] if exc.get("offset") else "",
            " [%s]" % exc["module"] if exc.get("module") else "",
            exc.get("pid", "?"), exc.get("command", "?"), exc.get("cpu", "?")))
    out.append("- **Virtual machine:** %s" % ("yes (Hypervisor detected in the log)" if cls.get("vm") else "not seen in the log"))
    if cls["hits"]:
        out.append("- **Log signatures:** %s" % ", ".join(
            ("%s %d" % (k, len(v))) if v != [0] else "%s (sys panic string only)" % k
            for k, v in cls["hits"].items() if k != "call_trace"))
    if failed:
        out.append("- **Not collected:** %s" % "; ".join(failed))
    out.append("")
    out.append("## Evidence")
    out.append("")
    for b in blocks:
        out.extend(b)
    return "\n".join(out).rstrip() + "\n"


def summary_line(path, meta, cls, nblocks, nbytes):
    return "EVIDENCE file=%s task=%s case=%s branches=%s blocks=%d bytes=%d" % (
        path, meta.get("task") or "unknown", meta.get("case") or "unknown",
        ",".join(cls["branches"]), nblocks, nbytes)
