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


LABEL_W = 12


def color(c):
    try:
        return crashcolor.get_color(c)
    except Exception:
        return ""


def row(label, text, c=None):
    start = color(c) if c else ""
    end = color(crashcolor.RESET) if c else ""
    print("%-*s: %s%s%s" % (LABEL_W, label, start, text, end))


def cont(text, c=None):
    start = color(c) if c else ""
    end = color(crashcolor.RESET) if c else ""
    print("%-*s  %s%s%s" % (LABEL_W, "", start, text, end))


def rows(label, texts, c=None):
    """The first text on the labelled line, the rest under it."""
    for i, text in enumerate(texts):
        if i == 0:
            row(label, text, c)
        else:
            cont(text, c)


def warn(text):
    cont("! " + text, crashcolor.LIGHTRED)


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
        cont("(%s unavailable: %s)" % (fn.__name__.replace("show_", ""), e))
        return None


class Facts(object):
    pass


def show_header(f):
    s = f.sys
    crashcolor.set_color(crashcolor.BLUE | crashcolor.BOLD)
    print("=" * 78)
    print(" %s   crashed %s   up %s" % (s.get("NODENAME", "?"), s.get("DATE", "?"), s.get("UPTIME", "?")))
    print("=" * 78)
    crashcolor.set_color(crashcolor.RESET)
    if s.get("PANIC"):
        row("PANIC", s["PANIC"], crashcolor.LIGHTRED)
    mins = uptime_minutes(s.get("UPTIME"))
    if mins is not None and mins < 15:
        warn("crashed %d minute(s) after boot: a boot-time or early-service problem" % mins)
    if s.get("LOAD AVERAGE"):
        row("LOAD/TASKS", "load %s, %s tasks" % (s["LOAD AVERAGE"], s.get("TASKS", "?")))
    if f.overload:
        warn("1-minute load is %.0fx the CPU count: tasks piling up runnable or in D state" % f.overload)


def show_platform(f, o):
    p = f.platform
    kinds = {"vm": "Virtual machine on", "cloud": "Cloud instance on", "bare metal": "Bare metal,",
             "lpar": "", "unknown": "Platform:"}
    text = ("%s %s" % (kinds.get(p["kind"], ""), p["label"])).strip()
    if p["model"] and p["model"].lower() not in p["label"].lower():
        text += "  [%s]" % p["model"]
    row("PLATFORM", text, crashcolor.LIGHTGREEN)
    d = f.dmi
    bios = " ".join(x for x in (d.get("DMI_BIOS_VENDOR"), d.get("DMI_BIOS_VERSION"), d.get("DMI_BIOS_DATE")) if x)
    if bios:
        age = sysenv.firmware_age_years(d.get("DMI_BIOS_DATE"), f.sys.get("DATE"))
        line = "BIOS " + bios
        if age is not None and age >= 0:
            line += "  (%.1f years old at the crash)" % age
        cont(line)
        if age is not None and age >= 4 and p["kind"] == "bare metal":
            warn("firmware is %.0f years old: check the vendor's BIOS/firmware errata" % age)
    ids = []
    if d.get("DMI_PRODUCT_SERIAL"):
        ids.append("serial " + d["DMI_PRODUCT_SERIAL"])
    if d.get("DMI_PRODUCT_UUID") and o.verbose:
        ids.append("uuid " + d["DMI_PRODUCT_UUID"])
    if ids:
        cont("  ".join(ids))
    cont("evidence: " + "; ".join(p["evidence"]) if p["evidence"] else "evidence: none (no DMI, no hypervisor type)")
    for w in p["warnings"]:
        warn(w)
    logs = sysenv.platform_logs(p["label"])
    if logs:
        cont("platform side: " + logs)
    if o.verbose and d:
        for k in sorted(d):
            cont("%-24s %s" % (k, d[k]))


def show_kernel(f, o):
    k = f.kernel
    rel = f.sys.get("RELEASE", "?")
    text = "%s = %s" % (rel, k["label"]) if k["label"] != rel else rel
    if k.get("how"):
        text += " (%s)" % k["how"]
    row("KERNEL", text)
    if f.sys.get("VERSION"):
        cont("built " + f.sys["VERSION"])
    for fl in k["flavor"]:
        warn(fl)
    for n in k["notes"]:
        cont("- " + n, crashcolor.LIGHTYELLOW)


def show_hardware(f, o):
    s = f.sys
    cpus = s.get("CPUS", "?")
    text = "%s CPU(s)" % cpus
    model = gdb_string("boot_cpu_data.x86_model_id").strip() if symbol_exists("boot_cpu_data") else ""
    if model:
        text += ", " + re.sub(r"\s+", " ", model)
    row("CPU", text)
    extra = []
    mc = None
    if symbol_exists("boot_cpu_data"):
        m = re.search(r"=\s*(0x[0-9a-f]+|\d+)", run("p/x boot_cpu_data.microcode"))
        if m:
            mc = m.group(1)
            extra.append("microcode " + mc)
    nodes = read_int(("nr_online_nodes",))
    if nodes:
        extra.append("%d NUMA node(s)" % nodes)
    if s.get("MACHINE"):
        extra.append(s["MACHINE"])
    if extra:
        cont(", ".join(extra))
    mem = s.get("MEMORY", "?")
    text = mem
    try:
        if symbol_exists("crashk_res"):
            r = readSymbol("crashk_res")
            size = int(r.end) - int(r.start) + 1
            text += "   kdump reserved %s" % fmt_mb(size) if int(r.end) > 0 else "   kdump: no crashkernel memory reserved"
    except Exception:
        pass
    row("MEMORY", text)
    dumps = [l.split(":", 1)[1].strip() for l in f.sys_text.splitlines() if l.strip().startswith("DUMPFILE:")]
    if dumps:
        row("DUMPFILE", "; ".join(dumps))


def show_taint(f, o):
    mask = f.taint_mask
    if mask is None:
        return
    if mask == 0:
        row("TAINT", "not tainted", crashcolor.LIGHTGREEN)
        return
    t = run("sys -t")
    letters = ""
    m = re.search(r"TAINTED_MASK:\s*\S+\s+(\S+)", t)
    if m:
        letters = m.group(1)
    row("TAINT", "0x%x %s" % (mask, letters), crashcolor.LIGHTYELLOW)
    for bit, letter, why in f.taint:
        cont("%s  %s" % (letter, why))


def show_boot(f, o):
    if not f.cmdline:
        return
    notes = sysenv.notable_bootargs(f.cmdline)
    if o.verbose or not notes:
        row("CMDLINE", f.cmdline)
    rows("BOOT ARGS", ["%-34s %s" % (param, note) for param, note in notes])


def show_sysctls(f, o):
    if f.armed:
        rows("PANICS ON", ["%s=%d: %s becomes a panic" % (name, val, what) for name, val, what in f.armed],
             crashcolor.LIGHTYELLOW)
    else:
        known = [n for n, v in f.sysctls.items() if v is not None]
        if known:
            row("PANICS ON", "no panic sysctl set (%d read, all 0)" % len(known))
    extra = []
    if f.panic_timeout is not None:
        extra.append("kernel.panic=%d (%s)" % (
            f.panic_timeout, "reboot after %ds" % f.panic_timeout if f.panic_timeout > 0
            else "reboot at once" if f.panic_timeout < 0 else "no reboot after panic"))
    if f.hung_timeout is not None:
        extra.append("hung_task_timeout_secs=%d" % f.hung_timeout)
    if f.watchdog_thresh is not None:
        extra.append("watchdog_thresh=%d" % f.watchdog_thresh)
    if extra:
        cont(", ".join(extra))
    sec = []
    if f.fips:
        sec.append("FIPS mode")
    if f.selinux is not None:
        sec.append("SELinux %s" % ("enforcing" if f.selinux else "permissive/disabled"))
    if sec:
        row("SECURITY", ", ".join(sec))


def show_modules(f, o):
    m = f.modules
    third = []
    for cat, prod, mods in m["products"]:
        mods_s = ", ".join(mods[:6]) + (" ..." if len(mods) > 6 else "")
        third.append("%-14s %s (%s)" % (cat, prod, mods_s))
    if m["other_tainted"]:
        shown = m["other_tainted"] if o.verbose else m["other_tainted"][:8]
        txt = ", ".join("%s(%s)" % (n, t) for n, t in shown)
        if len(shown) < len(m["other_tainted"]):
            txt += " ... %d more (mod -t)" % (len(m["other_tainted"]) - len(shown))
        third.append("%-14s %s" % ("tainted", txt))
    rows("THIRD PARTY", third, crashcolor.LIGHTYELLOW)
    rows("DRIVERS", ["%-14s %s" % (cat, " ".join(mods)) for cat, mods in m["stacks"]])
    row("MODULES", "%d loaded" % len(f.module_names))


def show_storage_net(f, o):
    counts, overlay = f.mounts
    if counts:
        parts = ["%s x%d" % (t, n) if n > 1 else t for t, n in sorted(counts.items(), key=lambda x: (-x[1], x[0]))]
        if overlay:
            parts.append("overlay x%d (containers)" % overlay)
        row("FILESYSTEMS", ", ".join(parts))
    if f.ifaces:
        shown = f.ifaces if o.verbose else f.ifaces[:6]
        txt = ", ".join(("%s %s" % (n, a)).strip() for n, a in shown)
        if len(shown) < len(f.ifaces):
            txt += " ... %d more (net)" % (len(f.ifaces) - len(shown))
        row("NETWORK", txt)


def show_workloads(f, o):
    w = f.work
    if w["apps"]:
        parts = []
        for label, n, detail in w["apps"]:
            p = label if n == 1 else "%s x%d" % (label, n)
            if detail:
                p += " (%s)" % detail
            parts.append(p)
        row("WORKLOADS", "; ".join(parts))
    if w["agents"]:
        products = set(p for _, p, _ in f.modules["products"])
        row("AGENTS", ", ".join(a + (" (user mode, no kernel module)"
                                     if a in sysenv.MODULE_AGENTS and a not in products else "")
                                 for a, _ in w["agents"]))


def show_log(f, o):
    hits = f.log_hits
    keys = [k for k, _, _ in logsig.SIGNATURES if k in hits and k != "call_trace"]
    if not keys:
        row("LOG", "no known signature in %d line(s)" % len(f.log))
        return
    row("LOG", " ".join("%s=%d" % (k, len(hits[k])) for k in keys))
    note = logsig.reroute(f.log, hits)
    if note:
        warn("reroute: " + note)


def show_next(f, o):
    steps = sysenv.next_steps(f.platform, f.log_hits.keys(), f.taint, f.armed, f.work["agents"], f.kernel,
                              f.overload)
    print("")
    crashcolor.set_color(crashcolor.BLUE | crashcolor.BOLD)
    print("Start with:")
    crashcolor.set_color(crashcolor.RESET)
    for i, (cmd, why) in enumerate(steps, 1):
        print("  %d. %-36s %s" % (i, cmd, why))


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

    section(show_header, f)
    section(show_platform, f, o)
    section(show_kernel, f, o)
    section(show_hardware, f, o)
    section(show_taint, f, o)
    section(show_boot, f, o)
    section(show_sysctls, f, o)
    section(show_modules, f, o)
    section(show_storage_net, f, o)
    section(show_workloads, f, o)
    section(show_log, f, o)
    section(show_next, f, o)
    print("")
    print(summary_line(f))


if ( __name__ == '__main__'):
    sysinfo()
