"""
System environment of a vmcore: what the machine was, what it ran and where
to start.

Used by the 'sysinfo' command. Everything here works on plain data (the
fields of 'sys', 'sys -i', module names, process names, the boot command
line, log lines), so the rules can be checked outside crash with
sysenv_test.py.

The sections:
  platform   bare metal (and whose), VM (and on which hypervisor), cloud
             instance or LPAR, from DMI, the kernel's hypervisor type and
             the "Hypervisor detected" log line; disagreements are shown
  kernel     RHEL major.minor from the release string, with lifecycle notes
             and non-RHEL or special kernels (UEK, CentOS Stream, debug, RT)
  bootargs   boot parameters that change how a crash reads
  modules    third-party products (security agents, backup, multipath,
             cluster filesystems, live patches) and the driver stacks
  workloads  what the machine was for, from its process names
  next       which commands to run first, from all of the above

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import re


# ---------------------------------------------------------------------------
# Platform
# ---------------------------------------------------------------------------

# Azure sets this chassis asset tag on every VM; plain Hyper-V does not.
AZURE_ASSET_TAG = "7783-7084-3265-9085-8269-3286-77"

# (kind, label, test(dmi fields lower-cased)). First match wins, so clouds
# come before the hypervisor they run on.
_V, _B = "vm", "bare metal"
PLATFORMS = [
    ("cloud", "Microsoft Azure",
     lambda d: d["asset"] == AZURE_ASSET_TAG),
    ("cloud", "Amazon EC2",
     lambda d: "amazon ec2" in d["vendor"] or "amazon" in d["bios_version"]),
    ("cloud", "Google Compute Engine",
     lambda d: d["vendor"] == "google" or "google compute engine" in d["product"]),
    ("cloud", "Oracle Cloud Infrastructure",
     lambda d: "oraclecloud" in d["asset"]),
    ("cloud", "Alibaba Cloud ECS",
     lambda d: "alibaba" in d["vendor"]),
    ("cloud", "Tencent Cloud CVM",
     lambda d: "tencent" in d["vendor"]),
    ("cloud", "IBM Cloud",
     lambda d: "ibm cloud" in d["product"] or "ibm:cloud" in d["asset"]),
    (_V, "OpenStack",
     lambda d: "openstack" in d["product"] or "openstack" in d["vendor"]),
    (_V, "OpenShift Virtualization / KubeVirt",
     lambda d: "kubevirt" in d["vendor"] or "openshift virtualization" in d["product"]),
    (_V, "Red Hat Virtualization / oVirt",
     lambda d: "rhev" in d["product"] or "ovirt" in d["product"] or "ovirt" in d["vendor"]),
    (_V, "Nutanix AHV",
     lambda d: "nutanix" in d["vendor"] or d["product"] == "ahv"),
    (_V, "VMware",
     lambda d: "vmware" in d["vendor"] or "vmware" in d["product"]),
    (_V, "Microsoft Hyper-V",
     lambda d: "microsoft" in d["vendor"] and "virtual machine" in d["product"]),
    (_V, "Xen",
     lambda d: d["vendor"] == "xen" or "hvm domu" in d["product"]),
    (_V, "Oracle VirtualBox",
     lambda d: "innotek" in d["vendor"] or "virtualbox" in d["product"]),
    (_V, "Parallels",
     lambda d: "parallels" in d["vendor"]),
    (_V, "Proxmox VE",
     lambda d: "proxmox" in d["vendor"] or "proxmox" in d["product"]),
    (_V, "KVM/QEMU",
     lambda d: ("qemu" in d["vendor"] or "kvm" in d["product"] or "qemu" in d["product"]
                or "seabios" in d["bios_vendor"])),
    (_B, "Dell",
     lambda d: d["vendor"].startswith("dell")),
    (_B, "HPE",
     lambda d: d["vendor"] in ("hpe", "hp") or "hewlett" in d["vendor"]),
    (_B, "Lenovo",
     lambda d: d["vendor"].startswith("lenovo")),
    (_B, "Cisco UCS",
     lambda d: d["vendor"].startswith("cisco")),
    (_B, "Supermicro",
     lambda d: "supermicro" in d["vendor"]),
    (_B, "Fujitsu",
     lambda d: "fujitsu" in d["vendor"]),
    (_B, "IBM",
     lambda d: d["vendor"] == "ibm"),
    (_B, "Huawei / xFusion",
     lambda d: "huawei" in d["vendor"] or "xfusion" in d["vendor"]),
    (_B, "Inspur",
     lambda d: "inspur" in d["vendor"]),
    (_B, "Quanta",
     lambda d: "quanta" in d["vendor"]),
    (_B, "Intel",
     lambda d: d["vendor"].startswith("intel")),
    (_B, "Gigabyte",
     lambda d: "gigabyte" in d["vendor"]),
    (_B, "ASUS",
     lambda d: d["vendor"].startswith("asus")),
    (_B, "Hitachi",
     lambda d: "hitachi" in d["vendor"]),
    (_B, "NEC",
     lambda d: d["vendor"] == "nec"),
    (_B, "Bull / Atos",
     lambda d: "bull" in d["vendor"] or "atos" in d["vendor"]),
    (_B, "Oracle (Sun) server",
     lambda d: "oracle corporation" in d["vendor"] and "virtualbox" not in d["product"]),
    (_B, "white box (no vendor in DMI)",
     lambda d: "to be filled" in d["vendor"] or d["vendor"] in ("default string", "system manufacturer")),
]

# What to collect from the platform itself when the guest cannot explain it.
PLATFORM_LOGS = {
    "Dell": "iDRAC SupportAssist collection (TSR) and the Lifecycle log",
    "HPE": "iLO Active Health System log (AHS) and the IML",
    "Lenovo": "XClarity Controller FFDC service data",
    "Cisco UCS": "UCS Manager / CIMC tech-support bundle and SEL",
    "Supermicro": "BMC system event log (SEL)",
    "Fujitsu": "iRMC system event log and ServerView data",
    "VMware": "ESXi vmware.log of this VM and esxtop CPU ready / memory balloon",
    "Microsoft Hyper-V": "Hyper-V host event logs (Hyper-V-Worker, VMMS) for this VM",
    "Microsoft Azure": "Azure boot diagnostics, serial console log and Resource Health",
    "Amazon EC2": "EC2 system log / screenshot and the instance status checks",
    "Google Compute Engine": "serial port output and the host maintenance events",
    "Oracle Cloud Infrastructure": "OCI console history and instance metrics",
    "Nutanix AHV": "Prism alerts and the AHV host's qemu log for this VM",
    "KVM/QEMU": "the host's qemu log for this guest and the host's dmesg",
    "Red Hat Virtualization / oVirt": "the host's vdsm.log and qemu log for this VM",
    "OpenStack": "the compute node's nova-compute and qemu logs for this instance",
    "OpenShift Virtualization / KubeVirt": "the virt-launcher pod log of this VM",
    "Xen": "the dom0 xl dmesg and qemu-dm log",
}

# x86_hyper_type values (enum x86_hypervisor_type).
HYPERVISOR_TYPES = {
    0: "native", 1: "VMware", 2: "Hyper-V", 3: "Xen PV", 4: "Xen HVM",
    5: "KVM", 6: "Jailhouse", 7: "ACRN",
}

# The hypervisor name each platform is expected to show to the kernel.
_HYPER_OF = {
    "VMware": "vmware", "Microsoft Hyper-V": "hyper-v", "Microsoft Azure": "hyper-v",
    "Xen": "xen", "KVM/QEMU": "kvm", "Nutanix AHV": "kvm", "Proxmox VE": "kvm",
    "OpenStack": "kvm", "Red Hat Virtualization / oVirt": "kvm",
    "OpenShift Virtualization / KubeVirt": "kvm", "Google Compute Engine": "kvm",
    "Oracle Cloud Infrastructure": "kvm", "Alibaba Cloud ECS": "kvm",
}


def _norm_hyper(name):
    n = (name or "").lower()
    for key, words in (("hyper-v", ("hyper-v", "hyperv", "microsoft")),
                       ("vmware", ("vmware",)), ("xen", ("xen",)), ("kvm", ("kvm",))):
        if any(w in n for w in words):
            return key
    return n


def dmi_fields(dmi):
    """The DMI fields the platform rules test, lower-cased."""
    get = lambda k: (dmi.get(k) or "").strip().lower()
    return {
        "vendor": get("DMI_SYS_VENDOR"),
        "product": get("DMI_PRODUCT_NAME"),
        "bios_vendor": get("DMI_BIOS_VENDOR"),
        "bios_version": get("DMI_BIOS_VERSION"),
        "asset": get("DMI_CHASSIS_ASSET_TAG"),
    }


def classify_platform(dmi, hypervisor=None, machine="", ppc_platform="", log_hypervisor=None):
    """
    Decide what the machine was.

    dmi            {field: value} from 'sys -i'
    hypervisor     the kernel's own idea (x86_hyper_type / x86_hyper->name),
                   "native", or None when unknown
    machine        MACHINE from 'sys' (x86_64, aarch64, ppc64le, s390x)
    ppc_platform   ppc_md.name on POWER ("pSeries", "PowerNV")
    log_hypervisor the name from a "Hypervisor detected: X" log line

    Returns {kind, label, model, evidence[], warnings[]}. kind is one of
    "vm", "cloud", "bare metal", "lpar" or "unknown".
    """
    f = dmi_fields(dmi)
    out = {"kind": "unknown", "label": "unknown", "model": "", "evidence": [], "warnings": []}
    arch = (machine or "").split()[0] if machine else ""

    if arch.startswith("s390"):
        out.update(kind="lpar", label="IBM Z (s390x)")
        out["evidence"].append("MACHINE %s" % arch)
        if hypervisor and _norm_hyper(hypervisor) == "kvm":
            out.update(kind="vm", label="KVM guest on IBM Z")
        return out
    if arch.startswith("ppc"):
        p = (ppc_platform or "").lower()
        if p == "pseries":
            out.update(kind="lpar", label="IBM Power LPAR (PowerVM or KVM guest)")
        elif p == "powernv":
            out.update(kind="bare metal", label="IBM Power, bare metal (OPAL/PowerNV)")
        else:
            out.update(label="IBM Power (%s)" % (ppc_platform or "platform unknown"))
        out["evidence"].append("ppc_md.name %s" % (ppc_platform or "?"))
        return out

    if f["vendor"] or f["product"]:
        out["evidence"].append("DMI %s / %s" % (dmi.get("DMI_SYS_VENDOR", "").strip() or "-",
                                                dmi.get("DMI_PRODUCT_NAME", "").strip() or "-"))
        for kind, label, test in PLATFORMS:
            if test(f):
                out.update(kind=kind, label=label)
                break
        else:
            out.update(label=dmi.get("DMI_SYS_VENDOR", "").strip() or "unknown")
        out["model"] = dmi.get("DMI_PRODUCT_NAME", "").strip()

    if hypervisor is not None:
        out["evidence"].append("kernel hypervisor type: %s" % hypervisor)
    if log_hypervisor:
        out["evidence"].append("log: Hypervisor detected: %s" % log_hypervisor)

    virt_seen = [h for h in (hypervisor, log_hypervisor) if h and _norm_hyper(h) != "native"]
    if out["label"] == "unknown" or out["kind"] == "unknown":
        if virt_seen:
            out.update(kind="vm", label="%s guest (no DMI)" % virt_seen[0]
                       if out["label"] == "unknown" else out["label"])
        elif hypervisor is not None and _norm_hyper(hypervisor) == "native":
            out["kind"] = "bare metal"
            if out["label"] == "unknown":
                out["label"] = "vendor unknown (no DMI)"
        return out

    expected = _HYPER_OF.get(out["label"])
    if out["kind"] == "bare metal" and virt_seen:
        out["warnings"].append("DMI names a hardware vendor but the kernel ran under %s: "
                               "a VM with passed-through SMBIOS, or a nested setup" % virt_seen[0])
        out["kind"] = "vm"
    elif out["kind"] in ("vm", "cloud") and hypervisor is not None:
        seen = _norm_hyper(hypervisor)
        if seen == "native":
            out["warnings"].append("DMI says %s but the kernel saw no hypervisor" % out["label"])
        elif expected and seen != expected:
            # KVM that exposes Hyper-V enlightenments is found as Hyper-V.
            out["warnings"].append("DMI says %s but the kernel detected %s%s" % (
                out["label"], hypervisor,
                " (KVM with Hyper-V enlightenments looks like this)" if seen == "hyper-v" else ""))
    return out


def platform_logs(label):
    """Where the platform keeps its own record of the event, or None."""
    return PLATFORM_LOGS.get(label)


_DMI_DATE = re.compile(r"(\d{1,2})/(\d{1,2})/(\d{4})")
_SYS_DATE = re.compile(r"\w{3}\s+(\w{3})\s+(\d{1,2})\s+[\d:]+\s+(?:\S+\s+)?(\d{4})")
_MONTHS = dict((m, i) for i, m in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1))


def firmware_age_years(bios_date, crash_date):
    """Years from the BIOS date ("MM/DD/YYYY") to the crash ('sys' DATE), or None."""
    b = _DMI_DATE.search(bios_date or "")
    c = _SYS_DATE.search(crash_date or "")
    if not b or not c or c.group(1) not in _MONTHS:
        return None
    bm, by = int(b.group(1)), int(b.group(3))
    cm, cy = _MONTHS[c.group(1)], int(c.group(3))
    return ((cy * 12 + cm) - (by * 12 + bm)) / 12.0


# ---------------------------------------------------------------------------
# Kernel release
# ---------------------------------------------------------------------------

# First release number of each minor's GA kernel.
RHEL_GA = {
    6: [(71, 0), (131, 1), (220, 2), (279, 3), (358, 4), (431, 5), (504, 6),
        (573, 7), (642, 8), (696, 9), (754, 10)],
    7: [(123, 0), (229, 1), (327, 2), (514, 3), (693, 4), (862, 5), (957, 6),
        (1062, 7), (1127, 8), (1160, 9)],
    8: [(80, 0), (147, 1), (193, 2), (240, 3), (305, 4), (348, 5), (372, 6),
        (425, 7), (477, 8), (513, 9), (553, 10)],
    9: [(70, 0), (162, 1), (284, 2), (362, 3), (427, 4), (503, 5), (570, 6),
        (611, 7)],
    10: [(55, 0), (124, 1)],
}

# Minor releases that had Extended Update Support (fixes past the next minor).
RHEL_EUS = {8: (1, 2, 4, 6, 8), 9: (0, 2, 4, 6), 10: (0, 2, 4, 6)}

RHEL_LIFECYCLE = {
    6: "RHEL 6 Maintenance Support ended 2020-11-30: fixes only under ELS",
    7: "RHEL 7 Maintenance Support ended 2024-06-30: fixes only under ELS, on 7.9",
}

_REL = re.compile(r"^(\d+)\.(\d+)\.(\d+)-(\d+)((?:\.\d+)*)\.(el\d+\w*?)(?:_(\d+))?"
                  r"(?:\.(x86_64|aarch64|ppc64le|ppc64|s390x|i686))?(\S*)$")


def kernel_release(release):
    """
    What the kernel release says.

    Returns {rhel, minor, label, flavor[], notes[]}; rhel and minor are None
    when not known.
    """
    r = (release or "").strip()
    out = {"rhel": None, "minor": None, "label": r or "unknown", "flavor": [], "notes": []}
    low = r.lower()
    if "+debug" in low or ".debug" in low or low.endswith("debug"):
        out["flavor"].append("debug kernel (slower; lockdep/kmemleak may be on)")
    if ".rt" in low or "+rt" in low:
        out["flavor"].append("real-time kernel (kernel-rt)")
    if "+64k" in low:
        out["flavor"].append("64k page size kernel")
    if "uek" in low:
        out["label"] = "Oracle UEK kernel %s" % r
        out["notes"].append("Oracle Unbreakable Enterprise Kernel: not a Red Hat kernel")
        return out
    if re.search(r"\.fc\d+", low):
        out["label"] = "Fedora kernel %s" % r
        return out

    m = _REL.match(r)
    if not m:
        out["notes"].append("not a RHEL kernel release string")
        return out
    dist = m.group(6)
    md = re.match(r"el(\d+)", dist)
    rhel = int(md.group(1))
    num = int(m.group(4))
    out["rhel"] = rhel
    table = RHEL_GA.get(rhel, [])

    if m.group(7) is not None:
        minor = int(m.group(7))
        how = "from the _%d suffix" % minor
    else:
        minor = None
        for ga, mi in table:
            if num == ga:
                minor = mi
            elif num > ga:
                minor = mi
        how = "from release %d" % num
        if minor is None:
            out["notes"].append("release %d is older than RHEL %d.0 GA: a pre-GA/beta kernel" % (num, rhel))
        elif rhel >= 8 and num not in [ga for ga, _ in table]:
            # Every shipped el8+ kernel is either a GA build or carries _N,
            # so this one never shipped as RHEL.
            out["notes"].append("release %d is neither a GA build nor has an _N suffix: "
                                "CentOS Stream or a pre-release kernel, after %d.%d" % (num, rhel, minor))
            out["label"] = "CentOS Stream / pre-release %d" % rhel
            out["minor"] = None
            out["how"] = how
            return out
    out["minor"] = minor
    if minor is None:
        out["label"] = "RHEL %d (minor unknown)" % rhel
    else:
        out["label"] = "RHEL %d.%d" % (rhel, minor)
        latest = table[-1][1] if table else None
        if latest is not None and minor < latest and rhel >= 8:
            if minor in RHEL_EUS.get(rhel, ()):
                out["notes"].append("%d.%d is not the latest minor (%d.%d or later exists): "
                                    "fixes only under EUS/E4S, until their end date" % (rhel, minor, rhel, latest))
            else:
                out["notes"].append("%d.%d is a non-EUS minor and no longer gets fixes since %d.%d shipped: "
                                    "update to get fixes" % (rhel, minor, rhel, minor + 1))
    if rhel in RHEL_LIFECYCLE:
        out["notes"].append(RHEL_LIFECYCLE[rhel])
    out["how"] = how
    return out


# ---------------------------------------------------------------------------
# Taint
# ---------------------------------------------------------------------------

# Upstream taint bits.
TAINT_BITS = [
    ("P", "proprietary module loaded"),
    ("F", "module force-loaded"),
    ("S", "out-of-spec system (SMP unsafe CPU)"),
    ("R", "module force-unloaded"),
    ("M", "machine check exception seen"),
    ("B", "bad page reference / unexpected page flags"),
    ("U", "tainted from userspace"),
    ("D", "kernel died (oops/BUG) before this point"),
    ("A", "ACPI table overridden"),
    ("W", "a kernel WARNING fired"),
    ("C", "staging driver loaded"),
    ("I", "working around a severe firmware bug"),
    ("O", "out-of-tree module loaded"),
    ("E", "unsigned module loaded"),
    ("L", "a soft lockup occurred earlier"),
    ("K", "kernel live patched"),
    ("X", "auxiliary taint (distribution defined)"),
    ("T", "built with struct randomization"),
    ("N", "in-kernel test run"),
]
RHEL7_TAINT = {28: ("H", "unsupported hardware (RHEL)"), 29: ("T", "Technology Preview code used (RHEL)")}


def decode_taint(mask, rhel=None):
    """[(bit, letter, meaning)] for each set bit."""
    out = []
    bit = 0
    while mask:
        if mask & 1:
            if rhel == 7 and bit in RHEL7_TAINT:
                letter, why = RHEL7_TAINT[bit]
            elif rhel == 7 and bit >= 16:
                letter, why = "?", "RHEL taint bit %d" % bit
            elif bit < len(TAINT_BITS):
                letter, why = TAINT_BITS[bit]
            else:
                letter, why = "?", "RHEL-specific taint bit %d (see 'sys -t')" % bit
            out.append((bit, letter, why))
        mask >>= 1
        bit += 1
    return out


# ---------------------------------------------------------------------------
# Boot parameters
# ---------------------------------------------------------------------------

# (regex on one parameter, note). The note says what it changes for a crash.
BOOT_PARAMS = [
    (r"^crashkernel=", "kdump memory reservation"),
    (r"^mitigations=off$", "CPU vulnerability mitigations disabled"),
    (r"^(nospectre_v2|nopti|pti=off|spectre_v2=off|spec_store_bypass_disable=off|nospec_store_bypass_disable)$",
     "a CPU vulnerability mitigation disabled"),
    (r"^nosmt", "SMT (hyper-threading) disabled"),
    (r"^(isolcpus|nohz_full|rcu_nocbs|irqaffinity)=", "CPU isolation (latency tuning): busy CPUs can starve housekeeping"),
    (r"^(idle=poll|intel_idle\.max_cstate|processor\.max_cstate)", "C-states limited (latency tuning)"),
    (r"^transparent_hugepage=", "THP mode set at boot"),
    (r"^(hugepages|hugepagesz|default_hugepagesz)=", "hugepages reserved at boot (memory not in the free pool)"),
    (r"^(mem|maxcpus|nr_cpus|possible_cpus)=", "memory or CPU count limited at boot"),
    (r"^numa=off$", "NUMA disabled"),
    (r"^(nmi_watchdog=0|nowatchdog|nosoftlockup)$", "lockup watchdog disabled: lockups will not be reported"),
    (r"^(softlockup_panic|hung_task_panic|panic_on_warn|oops=panic|panic)=", "panic behaviour set at boot"),
    (r"^(unknown_nmi_panic|panic_on_unrecovered_nmi|panic_on_io_nmi)", "NMI panic set at boot"),
    (r"^(selinux=0|enforcing=0)$", "SELinux disabled or permissive at boot"),
    (r"^audit=0$", "audit disabled"),
    (r"^fips=1$", "FIPS mode"),
    (r"^(intel_iommu|amd_iommu|iommu)=", "IOMMU mode set"),
    (r"^(rd\.break|init=|single|emergency|systemd\.unit=(rescue|emergency))", "booted into rescue/debug mode"),
    (r"^(rd\.lvm\.lv|root)=", None),
    (r"^(elevator|scsi_mod\.use_blk_mq|dm_mod\.use_blk_mq)=", "I/O scheduler or blk-mq set at boot"),
    (r"^(clocksource|tsc)=", "clocksource forced"),
    (r"^(cgroup_no_v1|systemd\.unified_cgroup_hierarchy)=", "cgroup version chosen at boot"),
    (r"^(ipv6\.disable=1|net\.ifnames=0|biosdevname=0)$", None),
    (r"^(console|earlyprintk)=", None),
    (r"^(kpti|lockdown|module\.sig_enforce)=", "kernel hardening parameter"),
    (r"^(slub_debug|page_poison|page_owner|kasan|init_on_free|init_on_alloc)", "memory debugging enabled (slower)"),
    (r"^(trace_event|ftrace|tp_printk)", "tracing enabled at boot"),
]
_BOOT = [(re.compile(p), n) for p, n in BOOT_PARAMS]


def notable_bootargs(cmdline):
    """[(param, note)] for the boot parameters worth a look, in cmdline order."""
    out = []
    for word in (cmdline or "").split():
        for pat, note in _BOOT:
            if pat.search(word):
                if note:
                    out.append((word, note))
                break
    return out


# ---------------------------------------------------------------------------
# Modules
# ---------------------------------------------------------------------------

# Third-party products, by module name.
PRODUCTS = [
    (r"^falcon_(lsm|nf|kal)", "security", "CrowdStrike Falcon"),
    (r"^(tmhook|bmhook|dsa_filter|dsa_filter_hook|redirfs|gsch)$", "security", "Trend Micro Deep Security"),
    (r"^(mfe_aac|mfe_fileaccess|mfehidk|mfeaack|mfe_fileaccess_\w+)", "security", "McAfee / Trellix"),
    (r"^(symev|symap|symevrm)", "security", "Symantec / Broadcom endpoint"),
    (r"^(cbsensor|event_collector)", "security", "VMware Carbon Black"),
    (r"^talpa", "security", "Sophos"),
    (r"^eset_rtp", "security", "ESET"),
    (r"^(kav4fs|klif|kl\w*_oas)", "security", "Kaspersky"),
    (r"^(sentinelone|s1_\w+)", "security", "SentinelOne"),
    (r"^(veeamsnap|veeamblksnap|blksnap)$", "backup", "Veeam"),
    (r"^(snapapi\d*|snumbd\d*)$", "backup", "Acronis"),
    (r"^cvblk$", "backup", "Commvault"),
    (r"^dattobd$", "backup", "Datto"),
    (r"^(emcp\w*)$", "storage", "Dell EMC PowerPath"),
    (r"^hdlm\w*$", "storage", "Hitachi HDLM"),
    (r"^scini$", "storage", "Dell PowerFlex (ScaleIO) SDC"),
    (r"^(vxfs|vxio|vxdmp|vxspec|vxportal|fdd|vxodm|vxglm|vxgms|veki|llt|gab|vxfen|amf)$", "storage", "Veritas InfoScale"),
    (r"^(oracleasm|oracleacfs|oracleadvm|oracleoks|oracleafd)$", "storage", "Oracle ASM/ACFS"),
    (r"^(mmfs26|mmfslinux|tracedev)$", "storage", "IBM Storage Scale (GPFS)"),
    (r"^(lustre|lnet|ko2iblnd|osc|mdc|lov|lmv|ptlrpc|obdclass)$", "storage", "Lustre"),
    (r"^(zfs|spl|zcommon|znvpair|zavl|icp|zlua|zunicode)$", "storage", "OpenZFS"),
    (r"^drbd$", "storage", "DRBD"),
    (r"^(nvidia|nvidia_uvm|nvidia_drm|nvidia_modeset|nvidia_peermem)$", "hardware", "NVIDIA GPU driver"),
    (r"^(mlx_compat|mlnx_compat|knem)$", "hardware", "Mellanox/NVIDIA OFED (out of tree)"),
    (r"^(vboxdrv|vboxnetflt|vboxnetadp)$", "virtualization", "VirtualBox host"),
    (r"^(vmmon|vmnet)$", "virtualization", "VMware Workstation host"),
    (r"^(falco|scap|sysdig_probe)$", "monitoring", "Falco / Sysdig"),
    (r"^(sep\d*|socperf\d*|pax|vtsspp)$", "monitoring", "Intel VTune"),
    (r"^(kpatch_\w+|livepatch_\w+)$", "livepatch", "kernel live patch"),
]
_PRODUCTS = [(re.compile(p), c, n) for p, c, n in PRODUCTS]

# In-tree driver stacks worth naming.
STACKS = [
    ("vm drivers", r"^(vmw_pvscsi|vmxnet3|vmw_balloon|vmw_vmci|vmw_vsock_vmci_transport|hv_vmbus|hv_storvsc|"
                   r"hv_netvsc|hv_balloon|hv_utils|virtio_blk|virtio_scsi|virtio_net|virtio_balloon|"
                   r"virtio_console|xen_\w+|ena|gve|mana)$"),
    ("storage", r"^(lpfc|qla2xxx|bfa|megaraid_sas|mpt3sas|mpt2sas|smartpqi|hpsa|aacraid|nvme|nvme_tcp|"
                r"nvme_rdma|nvme_fc|iscsi_tcp|ib_iser|ib_srp|dm_multipath|raid0|raid1|raid10|raid456|"
                r"dm_raid|dm_cache|dm_thin_pool|kvdo|dm_vdo|dm_crypt|bcache|zram)$"),
    ("network", r"^(mlx5_core|mlx4_en|i40e|ice|ixgbe|igb|e1000e|e1000|bnxt_en|bnx2x|tg3|qede|be2net|enic|"
                r"ionic|nfp|sfc|cxgb4|bonding|team|openvswitch|macvlan|ipvlan|vxlan|geneve|wireguard)$"),
    ("cluster", r"^(dlm|gfs2|ocfs2|softdog|iTCO_wdt|ipmi_watchdog)$"),
    ("containers", r"^(overlay|veth|br_netfilter|ip_vs|xt_conntrack)$"),
    ("hypervisor", r"^(kvm|kvm_intel|kvm_amd|vhost_net|vhost)$"),
]
_STACKS = [(c, re.compile(p)) for c, p in STACKS]


def classify_modules(names, taints=None):
    """
    names   loaded module names
    taints  {module: taint letters} from 'mod -t'

    Returns {products: [(category, product, [modules])], stacks: [(category,
    [modules])], other_tainted: [(module, letters)]}.
    """
    taints = taints or {}
    products, seen = [], set()
    for name in names:
        for pat, cat, prod in _PRODUCTS:
            if pat.search(name):
                for p in products:
                    if p[1] == prod:
                        p[2].append(name)
                        break
                else:
                    products.append((cat, prod, [name]))
                seen.add(name)
                break
    stacks = []
    for cat, pat in _STACKS:
        hit = [n for n in names if pat.search(n)]
        if hit:
            stacks.append((cat, hit))
    other = [(n, taints[n]) for n in names if n in taints and n not in seen]
    # A tainted module that is not loaded any more still tainted the kernel.
    other += [(n, t) for n, t in sorted(taints.items()) if n not in names and n not in seen]
    return {"products": products, "stacks": stacks, "other_tainted": other}


# ---------------------------------------------------------------------------
# Workloads
# ---------------------------------------------------------------------------

# (regex on comm, what it says). comm is at most 15 characters.
WORKLOADS = [
    (r"^kubelet$", "Kubernetes node"),
    (r"^(crio|cri-o)$", "CRI-O container runtime"),
    (r"^(openshift|hyperkube|machine-config-|ovnkube)", "OpenShift"),
    (r"^(dockerd|containerd|containerd-shim|conmon|podman)$", "containers"),
    (r"^(qemu-kvm|qemu-system-\w+)$", "KVM host running VMs"),
    (r"^(libvirtd|virtqemud)$", "libvirt"),
    (r"^(corosync|pacemakerd|pacemaker-\w+|sbd)$", "Pacemaker cluster"),
    (r"^(ocssd\.bin|crsd\.bin|ohasd\.bin|evmd\.bin)$", "Oracle Grid / RAC"),
    (r"^ora_pmon_", "Oracle Database"),
    (r"^asm_pmon_", "Oracle ASM instance"),
    (r"^db2sysc$", "IBM Db2"),
    (r"^(hdbindexserver|hdbnameserver|hdbdaemon)$", "SAP HANA"),
    (r"^(sapstart|sapstartsrv|disp\+work)$", "SAP NetWeaver"),
    (r"^(postgres|postmaster)$", "PostgreSQL"),
    (r"^(mysqld|mariadbd)$", "MySQL/MariaDB"),
    (r"^mongod$", "MongoDB"),
    (r"^redis-server$", "Redis"),
    (r"^(ceph-osd|ceph-mon)$", "Ceph"),
    (r"^glusterfsd$", "Gluster"),
    (r"^nfsd$", "NFS server"),
    (r"^smbd$", "Samba server"),
    (r"^(httpd|nginx|haproxy)$", "web / proxy"),
    (r"^ovs-vswitchd$", "Open vSwitch"),
    (r"^splunkd$", "Splunk"),
    (r"^java$", "Java applications"),
]
AGENTS = [
    (r"^vmtoolsd$", "VMware Tools"),
    (r"^qemu-ga$", "QEMU guest agent"),
    (r"^(hv_kvp_daemon|hypervkvpd|hv_vss_daemon)$", "Hyper-V daemons"),
    (r"^waagent$", "Azure agent"),
    (r"^amazon-ssm-agen", "AWS SSM agent"),
    (r"^google_guest_ag", "Google guest agent"),
    (r"^(falcon-sensor|falcond)$", "CrowdStrike Falcon"),
    (r"^(ds_agent|ds_am)$", "Trend Micro Deep Security"),
    (r"^(wdavdaemon|mdatp)", "Microsoft Defender"),
    (r"^(s1-agent|s1-orchestrator|sentinelone)", "SentinelOne"),
    (r"^cbagentd$", "Carbon Black"),
    (r"^(qualys-cloud-ag|nessusd)", "vulnerability scanner"),
    (r"^(TaniumClient|taniumclient)", "Tanium"),
    (r"^(oneagentos|oneagentwatchdo)", "Dynatrace"),
]
_WORKLOADS = [(re.compile(p), n) for p, n in WORKLOADS]
_AGENTS = [(re.compile(p), n) for p, n in AGENTS]

# Agents that freeze filesystems for snapshots: 'fsinfo -z' if I/O hung.
FREEZE_AGENTS = ("VMware Tools", "QEMU guest agent", "Hyper-V daemons")


def _count(comms, table):
    found = []
    for pat, label in table:
        hit = [c for c in comms if pat.search(c)]
        if hit:
            found.append((label, len(hit), hit))
    return found


def workloads(comms):
    """
    comms  process names (thread-group leaders)

    Returns {apps: [(label, count, detail)], agents: [(label, count)]}.
    detail names the Oracle/ASM instances.
    """
    apps = []
    for label, n, hit in _count(comms, _WORKLOADS):
        detail = ""
        if label in ("Oracle Database", "Oracle ASM instance"):
            detail = ", ".join(sorted(set(c.split("_", 2)[2] for c in hit if c.count("_") >= 2)))
        apps.append((label, n, detail))
    agents = [(label, n) for label, n, _ in _count(comms, _AGENTS)]
    return {"apps": apps, "agents": agents}


# ---------------------------------------------------------------------------
# Panic sysctls
# ---------------------------------------------------------------------------

# (symbol candidates, sysctl name, what a non-zero value turns into a panic)
PANIC_SYSCTLS = [
    (("panic_on_oops",), "kernel.panic_on_oops", "an oops"),
    (("softlockup_panic",), "kernel.softlockup_panic", "a soft lockup"),
    (("hardlockup_panic",), "kernel.hardlockup_panic", "a hard lockup"),
    (("sysctl_hung_task_panic",), "kernel.hung_task_panic", "a hung task"),
    (("sysctl_panic_on_oom",), "vm.panic_on_oom", "an OOM"),
    (("panic_on_warn",), "kernel.panic_on_warn", "a WARNING"),
    (("sysctl_panic_on_rcu_stall",), "kernel.panic_on_rcu_stall", "an RCU stall"),
    (("unknown_nmi_panic",), "kernel.unknown_nmi_panic", "an unknown NMI"),
    (("panic_on_unrecovered_nmi",), "kernel.panic_on_unrecovered_nmi", "an unrecovered NMI"),
    (("panic_on_io_nmi",), "kernel.panic_on_io_nmi", "an I/O check NMI"),
]


def armed_panics(values):
    """values {sysctl: int or None}. [(sysctl, value, what)] for the non-zero ones."""
    return [(name, values[name], what) for _, name, what in PANIC_SYSCTLS
            if values.get(name)]


# ---------------------------------------------------------------------------
# Where to start
# ---------------------------------------------------------------------------

# logsig keys -> (command, why)
LOG_NEXT = [
    ("softlockup", "lockup -r", "soft lockups in the log: who held the CPU"),
    ("hardlockup", "lockup -r", "hard lockup in the log"),
    ("hung_task", "hangcheck", "hung tasks in the log: who is blocked and on what"),
    ("rcu_stall", "rcuinfo -s", "RCU stall in the log"),
    ("oom", "meminfo -i", "the OOM killer ran"),
    ("oom_cgroup", "cginfo -m", "a memory cgroup ran out"),
    ("storage", "devinfo -q", "storage errors in the log: requests still in flight"),
    ("netdev_timeout", "netinfo -i", "a NIC transmit timeout"),
    ("corruption", "kmem -s", "a corruption report: check the slab caches"),
    ("hardware", "log | grep -iE 'mce|hardware error|edac'", "hardware errors in the log"),
]


def next_steps(platform, log_hits=(), taint=(), armed=(), agents=(), kernel=None):
    """[(command, why)] in the order to run them; no duplicates."""
    steps = []

    def add(cmd, why):
        if all(cmd != c for c, _ in steps):
            steps.append((cmd, why))

    hits = set(log_hits)
    if "panic" in hits or "oops" in hits:
        add("bt", "the panic task's backtrace")
    for key, cmd, why in LOG_NEXT:
        if key in hits:
            add(cmd, why)
    if platform.get("kind") in ("vm", "cloud"):
        if hits & set(("softlockup", "hardlockup", "hung_task", "rcu_stall", "hypervisor")):
            add("vminfo -o", "a VM with lockups or hangs: was the host overcommitted?")
        else:
            add("vminfo -o", "a VM: rule hypervisor overcommit in or out")
        if hits & set(("hung_task", "storage")):
            add("devinfo -p", "paravirtual I/O rings: did the host stop completing I/O?")
            if any(a in FREEZE_AGENTS for a, _ in agents):
                add("fsinfo -z", "a snapshot agent runs here: is a filesystem frozen?")
    letters = set(l for _, l, _ in taint)
    if letters & set("POE"):
        add("mod -t", "third-party modules tainted the kernel: are they in the backtrace?")
    if "K" in letters:
        add("mod | grep -E 'kpatch|livepatch'", "a live patch is applied: is the crash in patched code?")
    if kernel and kernel.get("rhel") and kernel.get("label", "").startswith("RHEL"):
        add("kvercmp <fixed kernel>", "when a known bug matches, is the fix already in %s?" % kernel["label"])
    add("logscan", "every known log signature with its first and last line")
    return steps
