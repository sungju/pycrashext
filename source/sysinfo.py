"""
'sysinfo' command: what this machine was, before starting on the vmcore.

One screen that 'sys' does not give: the platform (which hardware vendor, or
which hypervisor or cloud, with the evidence and where that platform keeps
its own logs), the RHEL minor release and its support state, CPU model and
microcode, kdump reservation, taint decoded, boot parameters that change how
a crash reads, the panic sysctls that were armed, third-party products by
their modules (security agents, backup, multipath, cluster filesystems, live
patches), driver stacks, filesystems, network addresses, what the machine
ran (databases, clusters, containers, guest/cloud agents), a count of the
known log signatures, and the commands to start with.

It is meant for a crash startup script: every section fails on its own and
the command never stops with a traceback. The last line,
"SYSINFO platform=... rhel=... cpus=... mem=... taint=...", is for scripts.

The rules are in sysenv.py (checks in sysenv_test.py).

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from pykdump.API import *
from LinuxDump import Tasks

import re

import crashcolor
import logsig
import sysenv


import textwrap

WIDTH = 78
LABEL_W = 10


def color(c):
    try:
        return crashcolor.get_color(c)
    except Exception:
        return ""


def row(label, text, c=None):
    """One labelled line, wrapped under its text."""
    lines = textwrap.wrap(text, WIDTH - LABEL_W - 2, break_on_hyphens=False) or [""]
    start = color(c) if c else ""
    end = color(crashcolor.RESET) if c else ""
    for i, line in enumerate(lines):
        print(" %-*s %s%s%s" % (LABEL_W, label if i == 0 else "", start, line, end))


def heading(text):
    print("")
    crashcolor.set_color(crashcolor.BLUE | crashcolor.BOLD)
    print(" " + text)
    crashcolor.set_color(crashcolor.RESET)


def run(cmd):
    try:
        return exec_crash_command(cmd)
    except Exception:
        return ""


def kv_lines(text):
    """{KEY: value} from 'KEY: value' lines; the first one wins."""
    out = {}
    for line in text.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            if key and key not in out:
                out[key] = val.strip()
    return out


def gdb_string(expr):
    m = re.search(r'"((?:[^"\\]|\\.)*)"', run("p %s" % expr))
    # A char array prints its unused tail as \000 escapes.
    return m.group(1).split("\\000", 1)[0] if m else ""


def read_int(names):
    for name in names:
        if symbol_exists(name):
            try:
                return int(readSymbol(name))
            except Exception:
                pass
    return None


def read_cmdline():
    """
    The whole boot command line. Read through its address: the string
    readSymbol gives for a char * can stop short of a long command line.
    """
    addr = Addr(readSymbol("saved_command_line"))
    try:
        raw = readmem(addr, 4096)
        if isinstance(raw, str):
            raw = raw.encode("latin-1")
        return raw.split(b"\0", 1)[0].decode("utf-8", "replace")
    except Exception:
        chars = []
        for i in range(4096):
            b = readU8(addr + i)
            if b == 0:
                break
            chars.append(chr(b))
        return "".join(chars)


def hypervisor_seen():
    """The kernel's own hypervisor name, "native", or None."""
    if symbol_exists("x86_hyper_type"):
        try:
            val = int(readSymbol("x86_hyper_type"))
            return sysenv.HYPERVISOR_TYPES.get(val, "type %d" % val)
        except Exception:
            pass
    if symbol_exists("x86_hyper"):
        try:
            if int(readSymbol("x86_hyper")) == 0:
                return "native"
            name = gdb_string("x86_hyper->name")
            if name:
                return name
        except Exception:
            pass
    return None


def module_list():
    names = []
    for line in run("mod").splitlines():
        w = line.split()
        if len(w) >= 2 and w[0] != "MODULE":
            names.append(w[1])
    taints = {}
    for line in run("mod -t").splitlines():
        w = line.split()
        if len(w) == 2 and w[0] != "NAME":
            taints[w[0]] = w[1]
    return names, taints


def process_names():
    """
    comm of every thread-group leader. From the task table, not 'ps -G':
    'ps -G' can leave crash's hash queue open for the rest of this epython
    run, and 'mount' and 'net' then fail with "hash queue is in use?".
    """
    try:
        comms = [str(t.comm) for t in Tasks.TaskTable().allThreads() if int(t.pid) == int(t.tgid)]
        if comms:
            return comms
    except Exception:
        pass
    comms = []
    for line in run("ps").splitlines():
        w = line.replace(">", " ", 1).split(None, 8)
        if len(w) >= 9 and w[0].isdigit():
            comms.append(w[8].strip().strip("[]"))
    return comms


def mounts():
    counts = {}
    pseudo = set(("proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "securityfs", "cgroup", "cgroup2",
                  "pstore", "bpf", "efivarfs", "configfs", "debugfs", "tracefs", "hugetlbfs", "mqueue",
                  "autofs", "rpc_pipefs", "binfmt_misc", "fusectl", "selinuxfs", "rootfs", "nsfs",
                  "sockfs", "pipefs", "anon_inodefs", "ramfs", "fuse.gvfsd-fuse", "overlay", "nfsd",
                  "fuse.portal", "squashfs"))
    overlay = 0
    for line in run("mount").splitlines():
        w = line.split()
        if len(w) < 5 or w[0] == "MOUNT":
            continue
        if w[2] == "overlay":
            overlay += 1
        if w[2] in pseudo:
            continue
        counts[w[2]] = counts.get(w[2], 0) + 1
    return counts, overlay


def interfaces():
    out = []
    for line in run("net").splitlines():
        w = line.split()
        if len(w) >= 2 and w[0] != "NET_DEVICE" and w[1] != "lo":
            out.append((w[1], " ".join(w[2:])))
    return out


def uptime_minutes(uptime):
    m = re.match(r"(?:(\d+) days?, )?(\d+):(\d+):(\d+)", uptime or "")
    if not m:
        return None
    days = int(m.group(1) or 0)
    return days * 1440 + int(m.group(2)) * 60 + int(m.group(3))


def fmt_mb(nbytes):
    return "%d MB" % (nbytes >> 20) if nbytes < (4 << 30) else "%.1f GB" % (nbytes / float(1 << 30))


def section(fn, *args):
    try:
        return fn(*args)
    except Exception as e:
        row("", "(%s unavailable: %s)" % (fn.__name__.replace("show_", ""), e))
        return None


class Facts(object):
    pass


def note(f, text, serious=False):
    """A line for 'Worth noting'."""
    f.notes.append((serious, text))


def show_header(f, o):
    s = f.sys
    p, k = f.platform, f.kernel
    kinds = {"vm": "virtual machine", "cloud": "cloud instance", "bare metal": "bare metal", "lpar": ""}
    what = ("%s %s" % (p["label"], kinds.get(p["kind"], ""))).strip()
    line1 = " · ".join(x for x in (s.get("NODENAME"), k["label"], what) if x)
    load = s.get("LOAD AVERAGE", "").replace(", ", "/")
    line2 = "crashed %s · up %s" % (s.get("DATE", "?"), s.get("UPTIME", "?"))
    crashcolor.set_color(crashcolor.BLUE | crashcolor.BOLD)
    print("=" * WIDTH)
    print(" " + line1)
    print(" " + line2)
    print("=" * WIDTH)
    crashcolor.set_color(crashcolor.RESET)
    if s.get("PANIC"):
        row("PANIC", s["PANIC"], crashcolor.LIGHTRED)
    if load:
        row("LOAD", "%s, %s tasks" % (load, s.get("TASKS", "?")))

    mins = uptime_minutes(s.get("UPTIME"))
    if mins is not None and mins < 15:
        note(f, "crashed %d minute(s) after boot: a boot-time or early-service problem" % mins)
    if f.overload:
        note(f, "load %s on %s CPUs (%.0fx): tasks piling up runnable or in D state" % (
            s.get("LOAD AVERAGE", "?").split(",")[0], s.get("CPUS", "?").split()[0], f.overload), True)
    why = sysenv.nmi_panic_cause(s.get("PANIC"), f.log, f.sysctls)
    if why:
        note(f, why, True)
    reroute = logsig.reroute(f.log, f.log_hits)
    if reroute:
        note(f, reroute, True)


def show_machine(f, o):
    p, d, s = f.platform, f.dmi, f.sys
    heading("Machine")
    kinds = {"vm": "Virtual machine on", "cloud": "Cloud instance on", "bare metal": "Bare metal,"}
    text = ("%s %s" % (kinds.get(p["kind"], ""), p["label"])).strip()
    if p["model"] and p["model"].lower() not in p["label"].lower():
        text += " (%s)" % p["model"]
    row("PLATFORM", text, crashcolor.LIGHTGREEN)
    if o.verbose or p["warnings"]:
        row("", "evidence: " + ("; ".join(p["evidence"]) or "none"))
    for w in p["warnings"]:
        note(f, w)
    real_hw = p["kind"] in ("bare metal", "lpar")
    if d.get("DMI_BIOS_VERSION") and (real_hw or o.verbose):
        age = sysenv.firmware_age_years(d.get("DMI_BIOS_DATE"), s.get("DATE"))
        bios = "firmware %s %s" % (d["DMI_BIOS_VERSION"], d.get("DMI_BIOS_DATE", ""))
        if age is not None and age >= 0:
            bios += " (%.1f years old)" % age
        row("", bios)
        if real_hw and age is not None and age >= 4:
            note(f, "firmware is %.0f years old: check the vendor's BIOS/firmware errata" % age)
    if d.get("DMI_PRODUCT_SERIAL") and (real_hw or o.verbose):
        row("", "serial " + d["DMI_PRODUCT_SERIAL"])
    logs = sysenv.platform_logs(p["label"])
    if logs:
        row("", "host side: " + logs)

    cpu = ["%s CPUs" % (s.get("CPUS") or "?")]
    model = gdb_string("boot_cpu_data.x86_model_id").strip() if symbol_exists("boot_cpu_data") else ""
    if model:
        cpu.append(re.sub(r"\s+", " ", model))
    if symbol_exists("boot_cpu_data"):
        m = re.search(r"=\s*(0x[0-9a-f]+|\d+)", run("p/x boot_cpu_data.microcode"))
        if m:
            cpu.append("microcode " + m.group(1))
    m = re.search(r"\((\d+) Mhz\)", s.get("MACHINE", ""))
    if m:
        cpu.append("%s MHz" % m.group(1))
    row("CPU", ", ".join(cpu))

    mem = [s.get("MEMORY") or "?"]
    nodes = read_int(("nr_online_nodes",))
    if nodes:
        mem.append("%d NUMA node%s" % (nodes, "" if nodes == 1 else "s"))
    try:
        if symbol_exists("crashk_res"):
            r = readSymbol("crashk_res")
            if int(r.end) > 0:
                mem.append("kdump reserved %s" % fmt_mb(int(r.end) - int(r.start) + 1))
            else:
                mem.append("no kdump reservation")
    except Exception:
        pass
    row("MEMORY", ", ".join(mem))
    if o.verbose:
        for l in f.sys_text.splitlines():
            if l.strip().startswith("DUMPFILE:"):
                row("DUMPFILE", l.split(":", 1)[1].strip())
        for key in sorted(d):
            row("", "%-22s %s" % (key, d[key]))


def show_kernel(f, o):
    k, s = f.kernel, f.sys
    heading("Kernel")
    rel = s.get("RELEASE", "?")
    text = rel
    m = re.search(r"\w{3} (\w{3} +\d+) [\d:]+ \w+ (\d{4})", s.get("VERSION", ""))
    if m:
        text += " (built %s %s)" % (re.sub(r" +", " ", m.group(1)), m.group(2))
    row("RELEASE", text)
    for fl in k["flavor"]:
        note(f, fl)
    for n in k["notes"]:
        note(f, n)

    state = []
    if f.taint_mask == 0:
        state.append("not tainted")
    elif f.taint_mask:
        letters = "".join(l for _, l, _ in f.taint)
        m = re.search(r"TAINTED_MASK:\s*\S+\s+(\S+)", run("sys -t"))
        state.append("tainted %s (%s)" % (m.group(1) if m else letters,
                                          ", ".join(why for _, _, why in f.taint)))
    if f.selinux is not None:
        state.append("SELinux " + ("enforcing" if f.selinux else "permissive/disabled"))
    if f.fips:
        state.append("FIPS")
    if state:
        row("STATE", ", ".join(state), crashcolor.LIGHTYELLOW if f.taint_mask else None)

    args = sysenv.notable_bootargs(f.cmdline)
    if o.verbose and f.cmdline:
        row("CMDLINE", f.cmdline)
    if args:
        row("BOOT", "  ".join(p for p, _, _ in args))
        for param, why, serious in args:
            if serious:
                note(f, "%s: %s" % (param, why))

    own, default = sysenv.split_armed(f.armed, k.get("rhel"))
    short = lambda lst: ", ".join(name.split(".", 1)[1] for name, _, _ in lst)
    panics = []
    if own:
        panics.append("set here: " + short(own))
    if default:
        panics.append("RHEL default: " + short(default))
    if not f.armed and any(v is not None for v in f.sysctls.values()):
        panics.append("no panic sysctl set")
    if panics:
        row("PANIC ON", "; ".join(panics))
    timers = []
    if f.panic_timeout is not None:
        timers.append("kernel.panic=%d (%s)" % (
            f.panic_timeout, "reboots after %ds" % f.panic_timeout if f.panic_timeout > 0
            else "reboots at once" if f.panic_timeout < 0 else "stays down"))
    if f.hung_timeout is not None:
        timers.append("hung task %ds" % f.hung_timeout)
    if f.watchdog_thresh is not None:
        timers.append("watchdog %ds" % f.watchdog_thresh)
    if timers:
        row("", ", ".join(timers))


def show_software(f, o):
    m, w = f.modules, f.work
    heading("Software")
    third = ["%s: %s (%s)" % (cat, prod, " ".join(mods[:6]) + (" ..." if len(mods) > 6 else ""))
             for cat, prod, mods in m["products"]]
    if m["other_tainted"]:
        shown = m["other_tainted"] if o.verbose else m["other_tainted"][:8]
        txt = " ".join("%s(%s)" % (n, t) for n, t in shown)
        if len(shown) < len(m["other_tainted"]):
            txt += " ... %d more, see mod -t" % (len(m["other_tainted"]) - len(shown))
        third.append("tainting: " + txt)
    for i, text in enumerate(third):
        row("3RD PARTY" if i == 0 else "", text, crashcolor.LIGHTYELLOW)
    drivers = [x for _, mods in m["stacks"] for x in mods]
    row("MODULES", "%d loaded%s" % (len(f.module_names), ": " + " ".join(drivers) if drivers else ""))
    if w["apps"]:
        parts = []
        for label, n, detail in w["apps"]:
            part = label if n == 1 else "%s x%d" % (label, n)
            parts.append(part + (" (%s)" % detail if detail else ""))
        row("RUNNING", "; ".join(parts))
    if w["agents"]:
        products = set(p for _, p, _ in m["products"])
        row("AGENTS", ", ".join(a + (" (user mode)" if a in sysenv.MODULE_AGENTS and a not in products else "")
                                for a, _ in w["agents"]))
    counts, overlay = f.mounts
    if counts:
        parts = ["%s x%d" % (t, n) if n > 1 else t for t, n in sorted(counts.items(), key=lambda x: (-x[1], x[0]))]
        if overlay:
            parts.append("overlay x%d (containers)" % overlay)
        row("FS", ", ".join(parts))
    if f.ifaces:
        shown = f.ifaces if o.verbose else f.ifaces[:8]
        txt = ", ".join(("%s %s" % (n, a)).strip() for n, a in shown)
        if len(shown) < len(f.ifaces):
            txt += ", ... %d more, see net" % (len(f.ifaces) - len(shown))
        row("NETWORK", txt)
    keys = [k for k, _, _ in logsig.SIGNATURES if k in f.log_hits and k != "call_trace"]
    row("LOG", " ".join("%s=%d" % (k, len(f.log_hits[k])) for k in keys) if keys
        else "no known signature in %d lines" % len(f.log))


def show_notes(f, o):
    if not f.notes:
        return
    heading("Worth noting")
    for serious, text in sorted(f.notes, key=lambda n: not n[0]):
        lines = textwrap.wrap(text, WIDTH - 5, break_on_hyphens=False)
        c = crashcolor.LIGHTRED if serious else crashcolor.LIGHTYELLOW
        for i, line in enumerate(lines):
            print("  %s%s %s%s" % (color(c), "!" if i == 0 else " ", line, color(crashcolor.RESET)))


def show_next(f, o):
    steps = sysenv.next_steps(f.platform, f.log_hits.keys(), f.taint, f.armed, f.work["agents"], f.kernel,
                              f.overload)
    heading("Start with")
    w = max(len(c) for c, _ in steps)
    for i, (cmd, why) in enumerate(steps, 1):
        lines = textwrap.wrap(why, WIDTH - w - 8) or [""]
        for j, line in enumerate(lines):
            print("  %s %-*s  %s" % ("%d." % i if j == 0 else "  ", w, cmd if j == 0 else "", line))


def summary_line(f):
    p, k = f.platform, f.kernel
    fields = [
        ("platform", p["label"].replace(" ", "_")),
        ("kind", p["kind"].replace(" ", "_")),
        ("rhel", ("%s.%s" % (k["rhel"], k["minor"])) if k["minor"] is not None
         else (str(k["rhel"]) if k["rhel"] else "none")),
        ("arch", (f.sys.get("MACHINE", "?").split() or ["?"])[0]),
        ("cpus", (f.sys.get("CPUS", "?").split() or ["?"])[0]),
        ("mem", f.sys.get("MEMORY", "?").replace(" ", "")),
        ("taint", "".join(l for _, l, _ in f.taint) or "none"),
        ("thirdparty", ",".join(pr.replace(" ", "_") for _, pr, _ in f.modules["products"]) or "none"),
    ]
    return "SYSINFO " + " ".join("%s=%s" % (k, re.sub(r"_+", "_", re.sub(r"[^\w.,/+-]+", "_", v)).strip("_")) for k, v in fields)


def safe(fn, default):
    try:
        return fn()
    except Exception:
        return default


def log_hypervisor(f):
    for n in f.log_hits.get("hypervisor", [])[:1]:
        m = re.search(r"Hypervisor detected:\s*(.+)$", f.log[n - 1])
        if m:
            return m.group(1).strip()
    return None


def read_selinux():
    val = read_int(("selinux_enforcing",))
    if val is None and symbol_exists("selinux_state"):
        val = int(readSymbol("selinux_state").enforcing)
    return val


def gather():
    """Every fact, each one on its own: one that cannot be read is left empty."""
    f = Facts()
    f.notes = []
    f.sys_text = run("sys")
    f.sys = kv_lines(f.sys_text)
    f.overload = sysenv.overload(f.sys.get("LOAD AVERAGE"), f.sys.get("CPUS"))
    f.dmi = safe(lambda: dict((k, v) for k, v in kv_lines(run("sys -i")).items()
                              if k.startswith("DMI_")), {})
    f.log = run("log").splitlines()
    f.log_hits = safe(lambda: logsig.scan(f.log), {})
    machine = f.sys.get("MACHINE", "")
    ppc = safe(lambda: gdb_string("ppc_md.name"), "") if machine.startswith("ppc") else ""
    f.platform = sysenv.classify_platform(f.dmi, safe(hypervisor_seen, None), machine, ppc,
                                          safe(lambda: log_hypervisor(f), None))
    f.kernel = sysenv.kernel_release(f.sys.get("RELEASE"))
    f.cmdline = safe(read_cmdline, "")
    f.taint_mask = read_int(("tainted_mask",))
    f.taint = sysenv.decode_taint(f.taint_mask or 0, f.kernel.get("rhel"))
    f.sysctls = dict((name, read_int(syms)) for syms, name, _ in sysenv.PANIC_SYSCTLS)
    f.armed = sysenv.armed_panics(f.sysctls)
    f.panic_timeout = read_int(("panic_timeout",))
    f.hung_timeout = read_int(("sysctl_hung_task_timeout_secs",))
    f.watchdog_thresh = read_int(("watchdog_thresh",))
    f.fips = read_int(("fips_enabled",))
    f.selinux = safe(read_selinux, None)
    f.module_names, taints = safe(module_list, ([], {}))
    f.modules = sysenv.classify_modules(f.module_names, taints)
    # 'mount' and 'net' first: they need crash's hash queue free.
    f.mounts = safe(mounts, ({}, 0))
    f.ifaces = safe(interfaces, [])
    f.work = sysenv.workloads(safe(process_names, []))
    return f


def sysinfo():
    op = OptionParser(usage="sysinfo [-v]")
    op.add_option("-v", "--verbose", dest="verbose", default=0, action="store_true",
                  help="Every DMI field, the whole boot command line, every interface and tainted module")
    (o, args) = op.parse_args()

    try:
        f = gather()
    except Exception as e:
        print("sysinfo: could not read the basic facts: %s" % e)
        return

    section(show_header, f, o)
    section(show_machine, f, o)
    section(show_kernel, f, o)
    section(show_software, f, o)
    section(show_notes, f, o)
    section(show_next, f, o)
    print("")
    print(summary_line(f))


if ( __name__ == '__main__'):
    sysinfo()
