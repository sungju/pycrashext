"""
Hypervisor overcommit verdict: which signals were checked, which fired,
what each one is worth, and what a guest can never see.

Used by 'vminfo --overcommit' on a vmcore and by isos 'vmware' on a
sosreport; an identical copy lives in pycrashext and in isos
(source/overcommit.py).  The kernel-log part also runs on any saved kernel
log (vmcore 'log' output, vmcore-dmesg.txt, dmesg):
    python3 overcommit.py <log file>

Every signal has one of three kinds:
  host     only the hypervisor can produce it: vCPU time stolen, a vCPU tick
           that stopped while the vCPU ran user code or idled, a balloon the
           host inflated.  One HIT decides its domain (LIKELY, or CONFIRMED
           for a balloon, which is a fact rather than an inference).
  support  fits overcommit but has guest-local causes too: load, deep
           runqueues, kernel-mode clock lag, stall bursts, timer messages.
           Raises its domain to POSSIBLE at most.
  context  guest-side pressure (swap, OOM, reclaim, storage queues).  Shown
           so the reader does not have to look for it, never counted.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import re
import sys

HIT, MISS, NA = "HIT", "miss", "n/a"
HOST, SUPPORT, CONTEXT = "host", "support", "context"

# Verdicts from weakest to strongest.  UNKNOWN: no host signal could be read.
RANK = ["NO EVIDENCE", "UNKNOWN", "POSSIBLE", "LIKELY", "CONFIRMED"]

# Log events this close to the end of the log count as "at crash time".
LOG_WINDOW_SEC = 600
# Soft lockups reported within this span on different CPUs form one burst.
BURST_SPAN_SEC = 2.0
# Lines after a soft lockup report searched for its RIP.
RIP_SEARCH_LINES = 60


class Signal(object):
    """One check: what was looked at, what it showed, against what bar."""

    def __init__(self, domain, kind, name, state, value, threshold="",
                 proof=False):
        self.domain = domain
        self.kind = kind
        self.name = name
        self.state = state
        self.value = value
        self.threshold = threshold
        self.proof = proof

    def __repr__(self):
        return "Signal(%s, %s, %s, %s)" % (self.domain, self.kind,
                                           self.name, self.state)


def domain_verdict(signals, domain):
    mine = [s for s in signals if s.domain == domain]
    host = [s for s in mine if s.kind == HOST]
    if any(s.state == HIT and s.proof for s in host):
        return "CONFIRMED"
    if any(s.state == HIT for s in host):
        return "LIKELY"
    if any(s.state == HIT for s in mine if s.kind == SUPPORT):
        return "POSSIBLE"
    if host and all(s.state == NA for s in host):
        return "UNKNOWN"
    return "NO EVIDENCE"


def overall_verdict(verdicts):
    """
    The strongest domain verdict.  UNKNOWN only when no domain could be
    read at all: a CPU that was read and showed nothing must not turn into
    "could not be read" because memory had no balloon driver.
    """
    known = [v for v in verdicts if v != "UNKNOWN"]
    if not known:
        return "UNKNOWN" if verdicts else "NO EVIDENCE"
    return max(known, key=RANK.index)


def hits(signals, domain=None, kind=None):
    return [s for s in signals if s.state == HIT
            and (domain is None or s.domain == domain)
            and (kind is None or s.kind == kind)]


def format_signal(s, name_width=36):
    """The text after the [state] tag: name, value and threshold."""
    text = "%-6s %-*s %s" % (s.domain, name_width, s.name, s.value)
    if s.threshold:
        text += "  (%s)" % s.threshold
    return text


def answer_text(signals, domain, verdict):
    """One line saying why a domain got its verdict."""
    host = hits(signals, domain, HOST)
    support = hits(signals, domain, SUPPORT)
    if verdict in ("CONFIRMED", "LIKELY"):
        return "host-only signal: " + "; ".join(s.name for s in host)
    if verdict == "POSSIBLE":
        return ("no host-only signal; non-specific: "
                + "; ".join(s.name for s in support))
    if verdict == "UNKNOWN":
        return "no host-only signal could be read"
    return "no host-only or supporting signal fired"


# ---------------------------------------------------------------------------
# Kernel log timeline
# ---------------------------------------------------------------------------

TS_RE = re.compile(r"^\s*(?:<\d+>)?\[\s*(\d+\.\d+)\]")
SOFTLOCKUP_RE = re.compile(
    r"soft lockup - CPU#(\d+) stuck for (\d+)s!\s*(?:\[([^\]]*)\])?")
HRTIMER_RE = re.compile(r"hrtimer: interrupt took (\d+) ns")
CS_RE = re.compile(r"RIP:\s*([0-9a-fA-F]{4}):")
# show_regs() header that ties a register dump to its CPU.
CPU_HDR_RE = re.compile(r"\bCPU: (\d+) PID: ")
FUNC_RE = re.compile(r"([A-Za-z_][\w.]*)\+0x[0-9a-fA-F]+/0x")

USER_CS = ("0033", "0023", "002b")
IDLE_FUNCS = frozenset((
    "native_safe_halt", "pv_native_safe_halt", "safe_halt", "default_idle",
    "default_idle_call", "arch_cpu_idle", "mwait_idle", "mwait_idle_with_hints",
    "intel_idle", "intel_idle_irq", "acpi_idle_do_entry", "acpi_safe_halt",
    "acpi_idle_enter", "cpu_idle_poll", "poll_idle", "cpuidle_enter_state",
    "amd_e400_idle", "xen_safe_halt",
))
# kvm_wait (the KVM paravirt spinlock wait) also halts through
# native_safe_halt, so a halt RIP means idle only for the idle task; for
# any other task it is a spinlock wait, a guest-local stall.

# name -> lower-case substrings.  The first three are CPU/timer symptoms,
# the last two guest-side context.
LOG_CATEGORIES = [
    ("soft lockup", ("soft lockup",)),
    ("RCU stall", ("detected stall", "self-detected stall", "kthread starved",
                   "rcu: info: rcu_")),
    ("clock/timer", ("clocksource watchdog", "timekeeping watchdog",
                     "marking clocksource", "hrtimer: interrupt took")),
    ("memory", ("invoked oom-killer", "out of memory:", "oom-kill:",
                "page allocation failure")),
    ("storage", ("blk_update_request: i/o error", "buffer i/o error",
                 "timing out command", "rejecting i/o to offline device",
                 "resetting link", "abort command")),
]
CPU_LOG_CATEGORIES = ("soft lockup", "RCU stall", "clock/timer")


def log_time(line):
    m = TS_RE.match(line)
    return float(m.group(1)) if m else None


def classify_rip(line):
    """('user'|'idle'|'kernel', function) for a 'RIP:' line, else None."""
    if "RIP:" not in line:
        return None
    m = CS_RE.search(line)
    if m and m.group(1).lower() in USER_CS:
        return "user", ""
    m = FUNC_RE.search(line.split("RIP:", 1)[1])
    func = m.group(1) if m else ""
    base = func.split(".", 1)[0]          # mwait_idle_with_hints.constprop.0
    if base in IDLE_FUNCS or base.endswith("safe_halt"):
        return "idle", func
    return "kernel", func


def analyse_log(lines, window=LOG_WINDOW_SEC):
    """
    Time-anchored view of a kernel log.

    end is the last timestamp in the log, the closest thing to the crash
    time the log has.  Each category lists (line index, time) of its
    matches.  Each soft lockup records where the CPU was when the watchdog
    fired: a CPU that idled or ran user code with interrupts enabled cannot
    starve its own watchdog, so that report means the vCPU did not run.
    (On RHEL7 the watchdog is a FIFO-99 kthread that a FIFO-99 user task can
    starve; the stopper-based watchdog of RHEL8 and later cannot be.)

    The RIP is taken from the register dump that follows the report, tied
    to it by the dump's 'CPU: N PID:' header, because reports from several
    CPUs interleave.  'idle' needs both an idle RIP and the idle task (a
    halt RIP in any other task is a paravirt spinlock wait); without a RIP
    the place is '?'.
    """
    result = {
        "lines": lines,
        "start": None,
        "end": None,
        "window": window,
        "categories": dict((name, []) for name, _ in LOG_CATEGORIES),
        "softlockups": [],
        "bursts": [],
        "hrtimer_max_ns": 0,
    }
    last_time = None
    for index, line in enumerate(lines):
        t = log_time(line)
        if t is not None:
            last_time = t
            if result["start"] is None:
                result["start"] = t
        lower = line.lower()
        for name, patterns in LOG_CATEGORIES:
            if any(p in lower for p in patterns):
                result["categories"][name].append((index, last_time))
        m = HRTIMER_RE.search(line)
        if m:
            result["hrtimer_max_ns"] = max(result["hrtimer_max_ns"],
                                           int(m.group(1)))
        m = SOFTLOCKUP_RE.search(line)
        if m:
            cpu = int(m.group(1))
            comm = m.group(3) or ""
            where, func, rip_index = "?", "", None
            header_cpu = None
            crossed = False
            for offset, follow in enumerate(
                    lines[index + 1:index + 1 + RIP_SEARCH_LINES]):
                other = SOFTLOCKUP_RE.search(follow)
                if other:
                    if int(other.group(1)) == cpu:
                        break
                    crossed = True
                    continue
                h = CPU_HDR_RE.search(follow)
                if h:
                    header_cpu = int(h.group(1))
                    continue
                rip = classify_rip(follow)
                if rip and (header_cpu == cpu
                            or (header_cpu is None and not crossed)):
                    where, func = rip
                    rip_index = index + 1 + offset
                    if where == "idle" and not comm.startswith("swapper"):
                        where = "kernel"
                    break
            result["softlockups"].append({
                "index": index, "time": last_time, "cpu": cpu,
                "stuck": int(m.group(2)), "comm": comm,
                "where": where, "func": func, "rip_index": rip_index,
            })
    result["end"] = last_time
    result["bursts"] = stall_bursts(result["softlockups"])
    return result


def stall_bursts(softlockups, span=BURST_SPAN_SEC):
    """Groups of soft lockups on two or more CPUs reported within span."""
    bursts = []
    group = []
    for s in sorted((s for s in softlockups if s["time"] is not None),
                    key=lambda s: s["time"]):
        if group and s["time"] - group[0]["time"] > span:
            if len(set(x["cpu"] for x in group)) >= 2:
                bursts.append(group)
            group = []
        group.append(s)
    if group and len(set(x["cpu"] for x in group)) >= 2:
        bursts.append(group)
    return bursts


def timed(log):
    """False when the log has no timestamps (printk.time=0)."""
    return log is not None and log["end"] is not None


def recent(log, events):
    """Events (index, time) within the log window before its end; none when
    the log has no timestamps, since then nothing can be placed in time."""
    if log["end"] is None:
        return []
    return [e for e in events
            if e[1] is not None and e[1] >= log["end"] - log["window"]]


def age_text(log, t):
    if t is None or log["end"] is None:
        return "time unknown"
    age = log["end"] - t
    if age < 1:
        return "at end of log"
    return "%s before end of log" % duration_text(age)


def duration_text(sec):
    sec = int(sec)
    if sec < 120:
        return "%ds" % sec
    if sec < 7200:
        return "%dm" % (sec // 60)
    if sec < 172800:
        return "%dh" % (sec // 3600)
    return "%dd" % (sec // 86400)


def category_summary(log, name):
    """'6, 4 in last 10m, last 3s before end of log' or None."""
    events = log["categories"].get(name, [])
    if not events:
        return None
    text = "%d" % len(events)
    near = recent(log, events)
    if len(near) != len(events):
        text += ", %d in last %s" % (len(near), duration_text(log["window"]))
    return text + ", last " + age_text(log, events[-1][1])


def excerpt(lines, indexes, before=2, after=2):
    """[(line, matched)] for the indexes and their neighbours, '...' gaps."""
    shown = set()
    for index in indexes:
        shown.update(range(max(0, index - before),
                           min(len(lines), index + after + 1)))
    rows = []
    previous = None
    for index in sorted(shown):
        if previous is not None and index > previous + 1:
            rows.append(("... unrelated log lines ...", False))
        rows.append((lines[index], index in indexes))
        previous = index
    return rows


# ---------------------------------------------------------------------------
# What the guest cannot see, and where to look instead
# ---------------------------------------------------------------------------

def blind_spots(hypervisor, steal_visible, balloon_driver, log,
                source="vmcore", host_swap_visible=False):
    """
    What the guest cannot see.  source is 'vmcore' or 'sosreport';
    host_swap_visible when the host reports its swapping (VMware Tools).
    """
    spots = []
    if not steal_visible:
        spots.append("steal is not exported to this guest: CPU ready/wait "
                     "time is invisible, CPU findings are inferred")
    if source == "vmcore":
        spots.append("a stall of every vCPU at once (snapshot or vMotion "
                     "stun, co-stop) moves all runqueue clocks together, so "
                     "clock lag cannot show it; only soft lockups while "
                     "idle/user can")
    else:
        spots.append("counters accumulated since boot or power-on average a "
                     "short episode away; sar intervals and the kernel log "
                     "are the evidence tied to a time")
    if not balloon_driver:
        spots.append("no balloon driver: the host can only reclaim this "
                     "guest's memory by swapping it, which the guest never "
                     "sees")
    elif not host_swap_visible:
        spots.append("host-level swapping or compression of guest memory "
                     "is never visible inside the guest")
    if log is not None and log["start"] is not None and log["start"] > 1.0:
        spots.append("kernel log starts %s after boot; earlier events were "
                     "overwritten" % duration_text(log["start"]))
    if log is None or not log["lines"]:
        spots.append("kernel log unavailable: soft-lockup and timer evidence "
                     "not checked")
    return spots


def host_checks(hypervisor, when, source="vmcore"):
    """Where to confirm the verdict outside this dump or sosreport."""
    at = " around %s" % when if when else ""
    name = (hypervisor or "").lower()
    if source == "vmcore":
        other = {
            "vmware": "sosreport of this guest: isos 'vmware' "
                      "(vm.cpu.contention.cpu, guest.mem.ballooned/swapped, "
                      "sar %steal)",
            "kvm": "sosreport of this guest: isos 'vmware' prints proc/stat "
                   "and sar %steal, which KVM does export",
        }
    else:
        other = dict((key, "vmcore of the crash, if there is one: pycrashext "
                           "'vminfo --overcommit' (vCPU clock lag, balloon, "
                           "soft lockups)")
                     for key in ("vmware", "kvm"))
    if "vmware" in name:
        return [
            "vCenter/esxtop for this VM%s: CPU Ready > 5%% per vCPU "
            "(> 1000 ms per 20 s sample), Co-Stop > 3%%, Balloon, Swapped "
            "and Compressed > 0" % at,
            other["vmware"],
        ]
    if "kvm" in name:
        return [
            "host%s: 'virsh domstats --vcpu --balloon' (vcpu.N.wait, "
            "balloon.current vs balloon.maximum), host load, swap and KSM" % at,
            other["kvm"],
        ]
    # lscpu says "Microsoft", RHEL7's x86_hyper "Microsoft HyperV".
    if "hyperv" in name.replace("-", "").replace(" ", "") or \
            "microsoft" in name:
        return [
            "Hyper-V host%s: 'Hyper-V Hypervisor Virtual Processor\\CPU Wait "
            "Time Per Dispatch' and Dynamic Memory pressure/demand" % at,
        ]
    if "xen" in name:
        return ["Xen host%s: 'xentop' VCPU wait and 'xl list' memory" % at]
    return ["the hypervisor's own per-VM CPU wait (ready/steal) and memory "
            "reclaim metrics%s" % at]


# ---------------------------------------------------------------------------
# Standalone: the log part on a saved log
# ---------------------------------------------------------------------------

def log_report(lines):
    log = analyse_log(lines)
    out = []
    if log["end"] is None:
        out.append("no timestamped lines; times unknown")
    else:
        out.append("log covers %.1fs .. %.1fs after boot; 'recent' means the "
                   "last %s" % (log["start"], log["end"],
                                duration_text(log["window"])))
    for name, _ in LOG_CATEGORIES:
        text = category_summary(log, name)
        out.append("  %-12s %s" % (name, text or "none"))
    for s in log["softlockups"]:
        out.append("  soft lockup CPU%-4d stuck %3ds  %-6s %s  %s"
                   % (s["cpu"], s["stuck"], s["where"], s["func"] or s["comm"],
                      age_text(log, s["time"])))
    for burst in log["bursts"]:
        out.append("  burst: %d CPUs within %.0fs at %.1fs"
                   % (len(set(s["cpu"] for s in burst)), BURST_SPAN_SEC,
                      burst[0]["time"]))
    if log["hrtimer_max_ns"]:
        out.append("  longest hrtimer interrupt %.3f ms"
                   % (log["hrtimer_max_ns"] / 1e6))
    return "\n".join(out)


if (__name__ == '__main__'):
    if len(sys.argv) != 2:
        print("usage: python3 overcommit.py <kernel log file>")
        sys.exit(1)
    with open(sys.argv[1], errors="replace") as f:
        print(log_report(f.read().splitlines()))
