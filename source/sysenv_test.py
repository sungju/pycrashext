"""
Checks for the system environment rules behind 'sysinfo'.

Run directly: python3 source/sysenv_test.py

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from sysenv import (split_armed, nmi_panic_cause, overload, classify_platform, kernel_release, decode_taint, notable_bootargs,
                    classify_modules, workloads, armed_panics, next_steps, firmware_age_years,
                    platform_logs)


def dmi(vendor, product, bios_vendor="", bios_version="", asset=""):
    return {"DMI_SYS_VENDOR": vendor, "DMI_PRODUCT_NAME": product, "DMI_BIOS_VENDOR": bios_vendor,
            "DMI_BIOS_VERSION": bios_version, "DMI_CHASSIS_ASSET_TAG": asset}


def check_vmware_vm():
    p = classify_platform(dmi("VMware, Inc.", "VMware7,1"), "VMware", "x86_64")
    assert (p["kind"], p["label"]) == ("vm", "VMware"), p
    assert not p["warnings"]
    assert "vmware.log" in platform_logs(p["label"])


def check_azure_is_not_plain_hyperv():
    tag = "7783-7084-3265-9085-8269-3286-77"
    p = classify_platform(dmi("Microsoft Corporation", "Virtual Machine", asset=tag), "Hyper-V")
    assert (p["kind"], p["label"]) == ("cloud", "Microsoft Azure"), p
    p = classify_platform(dmi("Microsoft Corporation", "Virtual Machine"), "Hyper-V")
    assert p["label"] == "Microsoft Hyper-V" and not p["warnings"], p


def check_clouds():
    assert classify_platform(dmi("Amazon EC2", "m5.xlarge"), "KVM")["label"] == "Amazon EC2"
    # Xen-era EC2 shows as Xen with an amazon BIOS version.
    assert classify_platform(dmi("Xen", "HVM domU", bios_version="4.11.amazon"), "Xen HVM")["label"] == "Amazon EC2"
    assert classify_platform(dmi("Google", "Google Compute Engine"), "KVM")["label"] == "Google Compute Engine"
    assert classify_platform(dmi("QEMU", "Standard PC", asset="OracleCloud.com"),
                             "KVM")["label"] == "Oracle Cloud Infrastructure"


def check_kvm_family():
    p = classify_platform(dmi("Red Hat", "RHEV Hypervisor", "SeaBIOS"), "KVM")
    assert p["label"] == "Red Hat Virtualization / oVirt", p
    p = classify_platform(dmi("OpenStack Foundation", "OpenStack Nova"), "KVM")
    assert p["label"] == "OpenStack"
    p = classify_platform(dmi("Nutanix", "AHV"), "KVM")
    assert p["label"] == "Nutanix AHV"
    p = classify_platform(dmi("QEMU", "Standard PC (Q35 + ICH9, 2009)", "SeaBIOS"), "KVM")
    assert p["label"] == "KVM/QEMU" and not p["warnings"]


def check_kvm_with_hyperv_enlightenments_is_explained():
    p = classify_platform(dmi("QEMU", "Standard PC (Q35 + ICH9, 2009)"), "Hyper-V")
    assert p["kind"] == "vm"
    assert any("enlightenments" in w for w in p["warnings"]), p


def check_bare_metal_vendors():
    for vendor, product, label in (("Dell Inc.", "PowerEdge R740", "Dell"),
                                   ("HPE", "ProLiant DL380 Gen10", "HPE"),
                                   ("Hewlett-Packard", "ProLiant DL380p Gen8", "HPE"),
                                   ("Lenovo", "ThinkSystem SR650", "Lenovo"),
                                   ("Cisco Systems Inc", "UCSC-C220-M5SX", "Cisco UCS"),
                                   ("Supermicro", "SYS-1029P", "Supermicro")):
        p = classify_platform(dmi(vendor, product), "native")
        assert (p["kind"], p["label"], p["model"]) == ("bare metal", label, product), p
        assert not p["warnings"]


def check_hardware_vendor_dmi_under_a_hypervisor():
    p = classify_platform(dmi("Dell Inc.", "PowerEdge R740"), "KVM")
    assert p["kind"] == "vm" and p["warnings"], p


def check_dmi_vm_but_kernel_native():
    p = classify_platform(dmi("VMware, Inc.", "VMware Virtual Platform"), "native")
    assert p["warnings"] and "no hypervisor" in p["warnings"][0]


def check_no_dmi():
    p = classify_platform({}, "KVM")
    assert p["kind"] == "vm" and "KVM" in p["label"], p
    p = classify_platform({}, None, log_hypervisor="VMware")
    assert p["kind"] == "vm", p
    p = classify_platform({}, "native")
    assert p["kind"] == "bare metal"
    assert classify_platform({}, None)["kind"] == "unknown"


def check_power_and_z():
    assert classify_platform({}, None, "ppc64le", "pSeries")["kind"] == "lpar"
    assert classify_platform({}, None, "ppc64le", "PowerNV")["kind"] == "bare metal"
    assert classify_platform({}, None, "s390x  (unknown Mhz)")["label"] == "IBM Z (s390x)"


def check_firmware_age():
    age = firmware_age_years("03/01/2017", "Mon Oct 12 10:11:12 AEST 2026")
    assert 9.5 <= age <= 9.7, age
    assert firmware_age_years("", "Mon Oct 12 10:11:12 2026") is None
    assert firmware_age_years("11/12/2020", "Thu Nov 12 01:02:03 2020") == 0.0


def check_rhel_minor_from_suffix_and_table():
    k = kernel_release("4.18.0-553.40.1.el8_10.x86_64")
    assert (k["rhel"], k["minor"], k["label"]) == (8, 10, "RHEL 8.10"), k
    k = kernel_release("3.10.0-1160.119.1.el7.x86_64")
    assert (k["rhel"], k["minor"]) == (7, 9), k
    assert any("ELS" in n for n in k["notes"])
    k = kernel_release("3.10.0-957.27.2.el7.x86_64")
    assert k["minor"] == 6
    k = kernel_release("4.18.0-80.el8.x86_64")
    assert k["minor"] == 0 and k["label"] == "RHEL 8.0", k
    k = kernel_release("5.14.0-284.30.1.el9_2.x86_64")
    assert k["minor"] == 2 and any("EUS" in n for n in k["notes"]), k
    k = kernel_release("5.14.0-362.8.1.el9_3.x86_64")
    assert any("non-EUS" in n for n in k["notes"]), k
    k = kernel_release("2.6.32-754.35.1.el6.x86_64")
    assert (k["rhel"], k["minor"]) == (6, 10)


def check_unshipped_and_foreign_kernels():
    k = kernel_release("5.14.0-590.el9.x86_64")
    assert k["minor"] is None and "Stream" in k["label"], k
    k = kernel_release("4.14.35-2047.510.5.el7uek.x86_64")
    assert k["rhel"] is None and "UEK" in k["label"]
    assert kernel_release("6.5.6-300.fc39.x86_64")["rhel"] is None
    assert kernel_release("5.15.0-91-generic")["rhel"] is None


def check_kernel_flavors():
    assert kernel_release("5.14.0-427.13.1.el9_4.x86_64+debug")["flavor"]
    assert kernel_release("5.14.0-427.13.1.el9_4.x86_64+rt")["flavor"]
    assert kernel_release("4.18.0-553.el8_10.x86_64")["flavor"] == []


def check_taint_decode():
    letters = [l for _, l, _ in decode_taint(0x3001, rhel=8)]
    assert letters == ["P", "O", "E"], letters
    assert [l for _, l, _ in decode_taint(1 << 29, rhel=7)] == ["T"]
    assert "RHEL-specific" in decode_taint(1 << 29, rhel=9)[0][2]
    assert decode_taint(0) == []


def check_bootargs():
    cmd = ("BOOT_IMAGE=(hd0,gpt2)/vmlinuz root=/dev/mapper/rhel-root ro crashkernel=1G-4G:192M,4G-64G:256M "
           "rd.lvm.lv=rhel/root rhgb quiet mitigations=off transparent_hugepage=never nohz_full=2-7 fips=1")
    got = [p.split("=")[0] for p, _, _ in notable_bootargs(cmd)]
    assert got == ["crashkernel", "mitigations", "transparent_hugepage", "nohz_full", "fips"], got
    assert notable_bootargs("ro quiet root=/dev/sda1") == []
    # Values decide: =0 turns these off, and sizes alone reserve nothing.
    quiet = "init_on_alloc=0 init_on_free=0 page_poison=0 default_hugepagesz=2M hugepagesz=2M hugepages=0"
    assert notable_bootargs(quiet) == [], notable_bootargs(quiet)
    loud = dict((p, w) for p, _, w in notable_bootargs("init_on_free=1 hugepages=1024 nowatchdog"))
    assert loud == {"init_on_free=1": True, "hugepages=1024": False, "nowatchdog": True}, loud


def check_modules():
    names = ["falcon_lsm_serviceable", "falcon_nf_netcontain", "vmw_pvscsi", "vmxnet3", "xfs",
             "dm_multipath", "kpatch_5_14_0_427_1_1", "mycorp_drv"]
    m = classify_modules(names, {"falcon_lsm_serviceable": "OE", "mycorp_drv": "POE", "gone": "OE"})
    prods = [(c, p, mods) for c, p, mods in m["products"]]
    assert ("security", "CrowdStrike Falcon", ["falcon_lsm_serviceable", "falcon_nf_netcontain"]) in prods, prods
    assert any(p == "kernel live patch" for _, p, _ in prods)
    assert ("mycorp_drv", "POE") in m["other_tainted"]
    assert ("gone", "OE") in m["other_tainted"], "an unloaded tainting module still counts"
    assert all(n != "falcon_lsm_serviceable" for n, _ in m["other_tainted"])
    stacks = dict(m["stacks"])
    assert stacks["vm drivers"] == ["vmw_pvscsi", "vmxnet3"]
    assert stacks["storage"] == ["dm_multipath"]


def check_workloads():
    comms = ["systemd", "ora_pmon_ORCL", "ora_pmon_PROD", "ora_smon_ORCL", "corosync", "pacemakerd",
             "vmtoolsd", "falcon-sensor", "java", "java", "nfsd", "kubelet"]
    w = workloads(comms)
    apps = dict((a, (n, d)) for a, n, d in w["apps"])
    assert apps["Oracle Database"] == (2, "ORCL, PROD"), apps
    assert apps["Pacemaker cluster"][0] == 2
    assert apps["Java applications"][0] == 2
    assert "Kubernetes node" in apps and "NFS server" in apps
    assert [a for a, _ in w["agents"]] == ["VMware Tools", "CrowdStrike Falcon"]


def check_armed_panics():
    vals = {"kernel.panic_on_oops": 1, "kernel.softlockup_panic": 0, "vm.panic_on_oom": None,
            "kernel.hung_task_panic": 1}
    assert [n for n, _, _ in armed_panics(vals)] == ["kernel.panic_on_oops", "kernel.hung_task_panic"]


def check_next_steps():
    plat = {"kind": "vm", "label": "VMware"}
    steps = [c for c, _ in next_steps(plat, ["panic", "hung_task", "storage"], [(0, "P", "")], (),
                                      [("VMware Tools", 1)], kernel_release("4.18.0-553.el8_10.x86_64"))]
    assert steps[0] == "bt"
    for c in ("hangcheck", "devinfo -s", "vminfo -o", "devinfo -p", "fsinfo -z", "mod -t", "logscan"):
        assert c in steps, (c, steps)
    assert steps.index("hangcheck") < steps.index("vminfo -o")
    assert len(steps) == len(set(steps))
    bare = [c for c, _ in next_steps({"kind": "bare metal"}, ["oops"])]
    assert "vminfo -o" not in bare and "fsinfo -z" not in bare



def check_forced_dump_on_overloaded_vm():
    # An NMI-forced dump of a VM at load 781 on 6 CPUs: look for the hang.
    ratio = overload("781.32, 300.20, 110.86", "6")
    assert ratio and ratio > 100, ratio
    assert overload("3.00, 2.00, 1.00", "8") is None
    assert overload("", "8") is None and overload("1.0, 1.0, 1.0", "") is None
    steps = next_steps({"kind": "vm"}, ["panic", "sysrq", "hypervisor"], overloaded=ratio)
    cmds = [c for c, _ in steps]
    assert cmds[:4] == ["bt", "hangcheck", "lockup -r", "vminfo -o"], cmds
    assert "hung" in dict(steps)["vminfo -o"]
    # "Hypervisor detected" alone is every VM, not a hang.
    calm = dict(next_steps({"kind": "vm"}, ["hypervisor"]))
    assert "rule host overcommit in or out" in calm["vminfo -o"]



def check_rhel_default_panics_apart():
    armed = armed_panics({"kernel.panic_on_oops": 1, "kernel.hardlockup_panic": 1,
                          "kernel.unknown_nmi_panic": 1})
    own, default = split_armed(armed, rhel=9)
    assert [n for n, _, _ in own] == ["kernel.unknown_nmi_panic"], own
    assert [n for n, _, _ in default] == ["kernel.panic_on_oops", "kernel.hardlockup_panic"]
    assert split_armed(armed)[1] == []


def check_nmi_panic_cause():
    log = ["[ 1408.1] Uhhuh. NMI received for unknown reason 30 on CPU 2.",
           "[ 1408.2] Kernel panic - not syncing: NMI: Not continuing"]
    why = nmi_panic_cause('"Kernel panic - not syncing: NMI: Not continuing"', log,
                          {"kernel.unknown_nmi_panic": 1})
    assert why.startswith("an NMI no driver claimed became a panic through kernel.unknown_nmi_panic=1"), why
    assert "looked hung" in why
    iock = nmi_panic_cause("NMI: Not continuing", ["NMI: IOCK error (debug interrupt?) for reason 71"],
                           {"kernel.panic_on_io_nmi": 1})
    assert "panic_on_io_nmi=1" in iock and "looked hung" not in iock
    assert nmi_panic_cause("Kernel panic - not syncing: Fatal exception", log, {}) is None


if (__name__ == '__main__'):
    checks = [v for k, v in sorted(globals().items()) if k.startswith('check_')]
    for check in checks:
        check()
        print("ok  %s" % check.__name__)
    print("\n%d checks passed" % len(checks))
