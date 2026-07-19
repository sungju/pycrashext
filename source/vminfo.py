"""
'vminfo' command: virtual-machine info, ballooning and hypervisor overcommit analysis.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from pykdump.API import *
from LinuxDump import Tasks, percpu

import crashcolor


def vmw_mem(options, balloon, balloon_stats=False):
    print("VMware virtual machine")
    print("----------------------\n")
    print("[ Memory ballooning ]")
    if options.show_details:
        print(balloon)
        symbol_name = 'balloon_stats' if balloon_stats else 'balloon'
        baddr = sym2addr(symbol_name)
        if baddr != 0:
            if balloon_stats:
                balloon_result = exec_crash_command('struct balloon_stats 0x%x -d' % (baddr))
            else:
                balloon_result = exec_crash_command('struct vmballoon.size,target,stats 0x%x -d' % (baddr))
            print ('%s' % (balloon_result))
        else:
            print("Warning: %s symbol address is invalid (0x0), skipping detailed structure display" % symbol_name)

    crashcolor.set_color(crashcolor.LIGHTRED)
    try:
        alloc_size = 0
        target_size = 0
        if balloon_stats:
            alloc_size = balloon.current_pages
            target_size = balloon.target_pages
        else:
            try:
                alloc_size = balloon.size.counter
            except (TypeError, AttributeError):
                alloc_size = balloon.size

            target_size = balloon.target

        print ("allocated size (pages)     = %d" % alloc_size)
        print ("allocated size (bytes)     = %d, (%.2fGB)" %
               (alloc_size * crash.PAGESIZE,
               ((alloc_size * crash.PAGESIZE)/1024/1024/1024)))
        print ("required target (pages)    = %d" % target_size)
        print ("required target (bytes)    = %d, (%.2fGB)" %
               (target_size * crash.PAGESIZE,
               ((target_size * crash.PAGESIZE)/1024/1024/1024)))
    finally:
        crashcolor.set_color(crashcolor.RESET)

    print ("")

    if balloon_stats and (member_offset(balloon, "target_unpopulated") > -1):
        print ("target_unpopulated         = %d" % balloon.target_unpopulated)
        if (member_offset(balloon, "balloon_low") > -1):
            print ("balloon_low                = %d" % balloon.balloon_low)
        if (member_offset(balloon, "balloon_high") > -1):
            print ("balloon_high               = %d" % balloon.balloon_high)
        if (member_offset(balloon, "total_pages") > -1):
            print ("total_pages                = %d" % balloon.total_pages)
        if (member_offset(balloon, "schedule_delay") > -1):
            print ("schedule_delay             = %d" % balloon.schedule_delay)
        if (member_offset(balloon, "max_schedule_delay") > -1):
            print ("max_schedule_delay         = %d" % balloon.max_schedule_delay)
        if (member_offset(balloon, "retry_count") > -1):
            print ("retry_count                = %d" % balloon.retry_count)
        if (member_offset(balloon, "max_retry_count") > -1):
            print ("max_retry_count            = %d" % balloon.max_retry_count)
        print ("")

    if (member_offset(balloon, "n_refused_pages") > -1):
        print ("refused pages              = %d" %
               balloon.n_refused_pages)

    if (member_offset(balloon, "rate_alloc") > -1):
        print ("rate_alloc                 = %d" % balloon.rate_alloc)

    if (member_offset(balloon, "rate_free") > -1):
        print ("rate_free                  = %d" % balloon.rate_free)

    print ("\n")


def show_hv_details(options, hv_context, dm_device):
    addr = hv_context.cpu_context
    print("\nstruct hv_per_cpu_context")
    for i in range(sys_info.CPUS):
        hv_per_cpu_context = percpu.percpu_ptr(addr, i)
        print("CPU %d : 0x%x" % (i, hv_per_cpu_context))


def hv_mem(options, hv_context):
    dm_device = readSymbol("dm_device")
    if dm_device == 0:
        return

    print("Hyper-V virtual machine")
    print("-----------------------\n")
    print("%22s = %d" % ("num_pages_ballooned", dm_device.num_pages_ballooned))
    print("%22s = %d" % ("num_pages_onlined", dm_device.num_pages_onlined))
    print("%22s = %d" % ("num_pages_added", dm_device.num_pages_added))

    if options.show_details == True:
        show_hv_details(options, hv_context, dm_device)


def kvm_mem(options):
    print("KVM/QEMU virtual machine (Nutanix AHV)")
    print("----------------------------------------\n")
    print("[ Memory ballooning ]")

    try:
        drv = readSymbol("virtio_balloon_driver")
        p = drv.driver.p
        if p == 0:
            print("No balloon devices registered")
            return

        knode_driver_off = member_offset("struct device_private", "knode_driver")
        vdev_dev_off = member_offset("struct virtio_device", "dev")

        found = False
        for knode in readSUListFromHead(p.klist_devices.k_list,
                                        "n_node",
                                        "struct klist_node"):
            try:
                dev_priv = readSU("struct device_private",
                                  int(knode) - knode_driver_off)
                dev = dev_priv.device
                vdev = readSU("struct virtio_device", int(dev) - vdev_dev_off)
                vb = readSU("struct virtio_balloon", int(vdev.priv))

                crashcolor.set_color(crashcolor.LIGHTRED)
                num_pages = int(vb.num_pages)
                print("allocated size (pages)     = %d" % num_pages)
                print("allocated size (bytes)     = %d, (%.2fGB)" % (
                    num_pages * crash.PAGESIZE,
                    num_pages * crash.PAGESIZE / 1024 / 1024 / 1024))

                # Target page count — field name varies across kernel versions
                # (num_desired in newer kernels, may be absent in older ones)
                for _target_field in ("num_desired", "num_pfns"):
                    try:
                        num_desired = int(getattr(vb, _target_field))
                        print("required target (pages)    = %d" % num_desired)
                        print("required target (bytes)    = %d, (%.2fGB)" % (
                            num_desired * crash.PAGESIZE,
                            num_desired * crash.PAGESIZE / 1024 / 1024 / 1024))
                        break
                    except Exception:
                        continue
                crashcolor.set_color(crashcolor.RESET)

                if options.show_details:
                    result = exec_crash_command(
                        "struct virtio_balloon 0x%x -d" % int(vb))
                    print("\nDetailed virtio_balloon struct:\n%s" % result)

                found = True
                break  # only one balloon device per guest

            except Exception:
                continue

        if not found:
            print("No virtio_balloon device instances found")

    except Exception as e:
        print("Error reading virtio_balloon data: %s" % str(e))

    crashcolor.set_color(crashcolor.RESET)
    print("\n")


def get_dmi_info():
    """Return a dict of DMI fields parsed from 'sys -i' output."""
    dmi = {}
    for line in exec_crash_command("sys -i").splitlines():
        if ':' in line:
            key, _, val = line.partition(':')
            dmi[key.strip()] = val.strip()
    return dmi


def get_system_info(options):
    results = exec_crash_command("sys -i").splitlines()
    print("System Information")
    print("------------------")
    for line in results:
        words = line.split()
        if not words:
            continue
        if words[0] == 'DMI_PRODUCT_NAME:':
            print(line)
        elif words[0] == 'DMI_BIOS_DATE:':
            print(line)
        elif words[0] == 'DMI_SYS_VENDOR:':
            print(line)
        elif words[0] == 'DMI_BIOS_VERSION:':
            print(line)
        elif words[0] == 'DMI_BIOS_VENDOR:':
            print(line)

    print()


def balloon_info(options):
    get_system_info(options)

    dmi = get_dmi_info()
    vendor      = dmi.get('DMI_SYS_VENDOR',   '').lower()
    product     = dmi.get('DMI_PRODUCT_NAME', '').lower()
    bios_vendor = dmi.get('DMI_BIOS_VENDOR',  '').lower()

    # Hyper-V
    if 'microsoft' in vendor:
        hv_context = 0
        try:
            hv_context = readSymbol("hv_context")
        except Exception:
            pass
        if hv_context != 0:
            hv_mem(options, hv_context)
            return

    # VMware
    elif 'vmware' in vendor:
        balloon = 0
        balloon_stats = False
        try:
            if symbol_exists('balloon'):
                balloon = readSymbol('balloon')
            elif symbol_exists('balloon_stats'):
                balloon = readSymbol('balloon_stats')
                balloon_stats = True
        except Exception:
            pass
        if balloon != 0:
            vmw_mem(options, balloon, balloon_stats)
            return

    # KVM / QEMU / Nutanix AHV
    # Covers: DMI_PRODUCT_NAME: KVM, QEMU; DMI_SYS_VENDOR: QEMU, Nutanix;
    #         DMI_BIOS_VENDOR: SeaBIOS (used by KVM/QEMU), OVMF
    elif ('nutanix' in vendor or
          'ahv' in product or 'kvm' in product or 'qemu' in product or
          'qemu' in vendor or 'kvm' in vendor or
          'seabios' in bios_vendor or 'ovmf' in bios_vendor):
        kvm_mem(options)
        return

    # Fallback: symbol-based detection only when DMI vendor is absent
    else:
        if vendor:
            print("Not VM environment or not recognizable VM")
            return

        hv_context = 0
        try:
            hv_context = readSymbol("hv_context")
        except Exception:
            pass
        if hv_context != 0:
            hv_mem(options, hv_context)
            return

        balloon = 0
        balloon_stats = False
        try:
            if symbol_exists('balloon'):
                balloon = readSymbol('balloon')
            elif symbol_exists('balloon_stats'):
                balloon = readSymbol('balloon_stats')
                balloon_stats = True
        except Exception:
            pass
        if balloon != 0:
            vmw_mem(options, balloon, balloon_stats)
            return

        if symbol_exists("virtio_balloon_driver"):
            kvm_mem(options)
            return

    print("Not VM environment or not recognizable VM")


def show_vmci_handle_arr(vmci_handle_arr, name):
    print("\t%s" % name)
    print("\t\tcapacity: %d" % (vmci_handle_arr.capacity))
    print("\t\tmax_capacity: %d" % (vmci_handle_arr.max_capacity))
    print("\t\tsize: %d" % (vmci_handle_arr.size))
    print("\t\tentries[]: 0x%x" % (vmci_handle_arr.entries))
    try:
        for i in range(0, vmci_handle_arr.capacity):
            vmci_handle = vmci_handle_arr.entries[i]
            print("\t\t\tentries[%d] : context = %d, resource = %d" %
                  (i, vmci_handle.context, vmci_handle.resource))
    except (TypeError, AttributeError, IndexError):
        pass


def show_vmci_context(options, ctx_list):
    for vmci_ctx in readSUListFromHead(ctx_list.head,
                                       "list_item",
                                       "struct vmci_ctx"):
        print(vmci_ctx)
        show_vmci_handle_arr(vmci_ctx.queue_pair_array, "queue_pair_array")
        show_vmci_handle_arr(vmci_ctx.doorbell_array, "doorbell_array")
        show_vmci_handle_arr(vmci_ctx.pending_doorbell_array, "pending_doorbell_array")


def show_vmci_qp_guest_endpoints(options, qp_guest_endpoints):
    for qp_entry in readSUListFromHead(qp_guest_endpoints.head,
                                       "list_item",
                                       "struct qp_entry"):
        print(qp_entry)
        ep = readSU("struct qp_guest_endpoint", qp_entry)
        print(ep)


def show_vm_context(options):
    try:
        ctx_list = readSymbol("ctx_list")
        show_vmci_context(options, ctx_list)

        print("")
        qp_guest_endpoints = readSymbol("qp_guest_endpoints")
        show_vmci_qp_guest_endpoints(options, qp_guest_endpoints)
        return
    except Exception:
        pass


HYPERVISOR_NAMES = {
    0: "native (bare metal)",
    1: "VMware",
    2: "Hyper-V",
    3: "Xen PV",
    4: "Xen HVM",
    5: "KVM",
    6: "Jailhouse",
    7: "ACRN",
}


def oc_get_hypervisor():
    """Return (name, is_virt) from x86_hyper_type, else X86_FEATURE_HYPERVISOR."""
    if symbol_exists("x86_hyper_type"):
        try:
            val = int(readSymbol("x86_hyper_type"))
            return HYPERVISOR_NAMES.get(val, "type %d" % val), (val != 0)
        except Exception:
            pass
    try:
        boot_cpu_data = readSymbol("boot_cpu_data")
        if (boot_cpu_data.x86_capability[4] >> 31) & 1:
            return "hypervisor present", True
    except Exception:
        pass
    return "native (bare metal)", False


def oc_get_steal_state():
    """Return (enabled, steal_by_cpu). enabled is True/False/None.

    steal_by_cpu maps cpu -> (steal_ns, total_ns); empty when unavailable.
    On VMware steal accounting is usually off, so steal reads 0 regardless.
    """
    enabled = None
    if symbol_exists("paravirt_steal_enabled"):
        try:
            enabled = int(readSymbol("paravirt_steal_enabled").enabled.counter) > 0
        except Exception:
            enabled = None

    steal = {}
    if symbol_exists("kernel_cpustat"):
        idx = 7
        try:
            idx = int(EnumInfo("enum cpu_usage_stat")["CPUTIME_STEAL"])
        except Exception:
            pass
        try:
            for cpu, addr in enumerate(percpu.get_cpu_var("kernel_cpustat")):
                kcs = readSU("struct kernel_cpustat", addr)
                buckets = [int(x) for x in kcs.cpustat]
                if idx < len(buckets):
                    steal[cpu] = (buckets[idx], sum(buckets))
        except Exception:
            pass
    return enabled, steal


def oc_get_loadavg():
    """Return (load1, load5, load15) from avenrun (FSHIFT=11), or None."""
    try:
        av = readSymbol("avenrun")
        return tuple(int(av[i]) / 2048.0 for i in range(3))
    except Exception:
        return None


def oc_get_balloon_pages():
    """
    Return (alloc_pages, target_pages, kind) for the detected balloon driver,
    or None.  target_pages is -1 when the driver exposes no target.
    """
    try:
        if symbol_exists("balloon"):
            b = readSymbol("balloon")
            try:
                alloc = int(b.size.counter)
            except (TypeError, AttributeError):
                alloc = int(b.size)
            return alloc, int(b.target), "VMware"
        if symbol_exists("balloon_stats"):
            b = readSymbol("balloon_stats")
            return int(b.current_pages), int(b.target_pages), "VMware"
    except Exception:
        pass
    try:
        dm = readSymbol("dm_device")
        if dm != 0:
            return int(dm.num_pages_ballooned), -1, "Hyper-V"
    except Exception:
        pass
    return None


def oc_collect_runqueues():
    """
    Return a list of per-CPU dicts with cpu, nr_running, tick_stall
    (rq->clock_task - curr->se.exec_start, in seconds: how long the vCPU's
    timer tick appears to have been stalled, i.e. the hypervisor was likely
    not scheduling this vCPU) and oncpu (rq clock - curr->sched_info.
    last_arrival: how long the current task has been continuously on the
    CPU).  A conservative note: on a tick-stalled vCPU the rq clock is
    frozen too, so oncpu UNDER-estimates the real wall time.
    """
    rows = []
    try:
        rqs = Tasks.getRunQueues()
    except Exception:
        return rows
    for rq in rqs:
        row = {"cpu": rq.cpu, "nr_running": -1, "tick_stall": -1.0,
               "curr": "", "pid": -1, "task": 0, "oncpu": -1.0}
        try:
            row["nr_running"] = int(rq.nr_running)
        except Exception:
            pass
        # rq clock (task-time base) with fallbacks
        try:
            ct = int(rq.clock_task)
        except Exception:
            try:
                ct = int(rq.clock)
            except Exception:
                ct = int(rq.Timestamp)
        try:
            es = int(rq.curr.se.exec_start)
            if es:
                row["tick_stall"] = (ct - es) / 1000000000.0
        except Exception:
            pass
        try:
            row["curr"] = str(rq.curr.comm)
            row["pid"] = int(rq.curr.pid)
            row["task"] = int(rq.curr)
        except Exception:
            pass
        try:
            la = int(rq.curr.sched_info.last_arrival)
            if la:
                row["oncpu"] = (int(rq.clock) - la) / 1000000000.0
        except Exception:
            pass
        rows.append(row)
    rows.sort(key=lambda r: r["cpu"])
    return rows


def oc_get_sched_slice_ms():
    """CFS scheduling-latency target in ms (the upper bound for how long a
    task may stay on-CPU when others are runnable)."""
    for sym in ("sysctl_sched_latency", "sysctl_sched_base_slice",
                "normalized_sysctl_sched_latency"):
        try:
            val = int(readSymbol(sym))
            if val:
                return val / 1000000.0
        except Exception:
            continue
    return 24.0


def oc_task_mode(task_addr):
    """
    Return 'user'/'kernel'/None: which side the task was executing when the
    dump was taken.  The first register block in 'bt' output is the context
    the dump NMI interrupted; a userspace RIP means the task was running
    application code at that instant.
    """
    try:
        out = exec_crash_command("bt 0x%x" % task_addr)
    except Exception:
        return None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("RIP:"):
            try:
                rip = int(line.split()[1], 16)
            except Exception:
                return None
            return "user" if rip < 0xffff800000000000 else "kernel"
    return "kernel"


def oc_get_iowait_pct():
    """System-wide iowait as % of all accounted CPU time (since boot)."""
    if not symbol_exists("kernel_cpustat"):
        return None
    idx = 6
    try:
        idx = int(EnumInfo("enum cpu_usage_stat")["CPUTIME_IOWAIT"])
    except Exception:
        pass
    iowait = total = 0
    try:
        for cpu, addr in enumerate(percpu.get_cpu_var("kernel_cpustat")):
            kcs = readSU("struct kernel_cpustat", addr)
            buckets = [int(x) for x in kcs.cpustat]
            if idx < len(buckets):
                iowait += buckets[idx]
                total += sum(buckets)
    except Exception:
        return None
    if not total:
        return None
    return 100.0 * iowait / total


def oc_get_scsi_hosts():
    """
    Best-effort walk of the SCSI hosts (shost_class) returning
    [(name, ndev, busy, blocked, failed)].  'busy' is the number of commands
    outstanding at the (virtual) HBA -- the modern equivalent of the removed
    Scsi_Host.host_busy counter: per-device device_busy where the kernel
    keeps it (RHEL8), else iorequest_cnt - iodone_cnt (RHEL9/10).
    """
    hosts = []
    try:
        sp = readSymbol("shost_class").p
        shost_dev_off = member_offset("struct Scsi_Host", "shost_dev")
        if shost_dev_off < 0:
            return hosts
        # knode_class lives in struct device up to 5.0 (RHEL8) and in
        # struct device_private from 5.1 (RHEL9/10).
        dev_knode_off = member_offset("struct device", "knode_class")
        priv_knode_off = member_offset("struct device_private",
                                       "knode_class")
        if dev_knode_off < 0 and priv_knode_off < 0:
            return hosts
        has_sdev_busy = \
            member_offset("struct scsi_device", "device_busy") >= 0
        has_iocnt = \
            (member_offset("struct scsi_device", "iorequest_cnt") >= 0 and
             member_offset("struct scsi_device", "iodone_cnt") >= 0)
        for knode in readSUListFromHead(sp.klist_devices.k_list, "n_node",
                                        "struct klist_node"):
            try:
                if dev_knode_off >= 0:
                    dev = readSU("struct device",
                                 int(knode) - dev_knode_off)
                else:
                    dev_priv = readSU("struct device_private",
                                      int(knode) - priv_knode_off)
                    dev = dev_priv.device
                shost = readSU("struct Scsi_Host",
                               int(dev) - shost_dev_off)
                busy = 0
                ndev = 0
                for sdev in readSUListFromHead(shost.__devices, "siblings",
                                               "struct scsi_device"):
                    ndev += 1
                    if ndev > 4096:
                        break
                    try:
                        if has_sdev_busy:
                            busy += int(sdev.device_busy.counter)
                        elif has_iocnt:
                            busy += (int(sdev.iorequest_cnt.counter) -
                                     int(sdev.iodone_cnt.counter))
                    except Exception:
                        pass
                try:
                    blocked = int(shost.host_blocked.counter)
                except Exception:
                    try:
                        blocked = int(shost.host_blocked)
                    except Exception:
                        blocked = -1
                try:
                    failed = int(shost.host_failed)
                except Exception:
                    failed = -1
                hosts.append(("host%d" % int(shost.host_no), ndev, busy,
                              blocked, failed))
            except Exception:
                continue
    except Exception:
        pass
    return hosts


def oc_get_inflight_requests():
    """
    Best-effort scan of the block layer for in-flight requests using
    pykdump's LinuxDump.block helpers.  Returns (count, oldest_age_sec):
    requests the guest submitted that the (host-backed) device has not
    completed, and the age of the oldest one.
    """
    count = 0
    oldest = 0.0
    try:
        from LinuxDump.block import get_all_request_queues, \
                get_queue_requests
        for rq in get_all_request_queues(""):
            try:
                for request in get_queue_requests(rq):
                    count += 1
                    try:
                        age = -float(request._reqinfo_.rq_alloc)
                        if age > oldest:
                            oldest = age
                    except Exception:
                        pass
            except Exception:
                continue
    except Exception:
        return -1, -1.0
    return count, oldest


# A vCPU tick stalled longer than this (seconds) is treated as strong evidence
# the hypervisor descheduled it.
TICK_STALL_SEC = 1.0
# A run-queue at/above this depth is treated as a CPU-pressure hotspot.
DEEP_RUNQ = 8


def show_overcommit(options):
    """
    Infer hypervisor CPU/memory overcommit from a single vmcore.

    CPU steal is invisible to a guest that does not account it (VMware), so
    this correlates the signals that remain visible: run-queue depth, load
    average, per-vCPU timer-tick stalls, steal time (when accounted) and
    memory ballooning.
    """
    hyper_name, is_virt = oc_get_hypervisor()
    steal_enabled, steal_by_cpu = oc_get_steal_state()
    loadavg = oc_get_loadavg()
    rows = oc_collect_runqueues()
    slice_ms = oc_get_sched_slice_ms()
    online_n = len(rows) if rows else sys_info.CPUS

    crashcolor.set_color(crashcolor.LIGHTCYAN)
    print("Hypervisor overcommit analysis")
    print("==============================")
    crashcolor.set_color(crashcolor.RESET)
    print("Virtualization : %s" % hyper_name)
    if not is_virt:
        print("\nThis does not look like a virtual machine; overcommit by a "
              "hypervisor does not")
        print("apply. (If this is a VM the hypervisor was not detected.)")
    if steal_enabled is False:
        print("Steal accounting: DISABLED (paravirt_steal_enabled=0) -> "
              "guest cannot measure")
        print("                  CPU steal directly; inference is from load / "
              "run-queues / ticks.")
    elif steal_enabled is True:
        print("Steal accounting: enabled")

    # ------------------------------------------------------------------
    # CPU pressure
    # ------------------------------------------------------------------
    total_runnable = sum(r["nr_running"] for r in rows if r["nr_running"] >= 0)
    max_runq = max((r["nr_running"] for r in rows), default=0)
    deep = [r for r in rows if r["nr_running"] >= DEEP_RUNQ]
    stalled = sorted([r for r in rows if r["tick_stall"] >= TICK_STALL_SEC],
                     key=lambda r: r["tick_stall"], reverse=True)

    max_steal_pct = 0.0
    for (st, tt) in steal_by_cpu.values():
        if tt:
            max_steal_pct = max(max_steal_pct, 100.0 * st / tt)

    print("\n-- CPU pressure --")
    if loadavg:
        ratio = loadavg[0] / online_n if online_n else 0.0
        color = crashcolor.RED if ratio > 1.25 else crashcolor.RESET
        crashcolor.set_color(color)
        print("Load average   : %.2f / %.2f / %.2f (1/5/15m) over %d CPUs "
              "-> %.2fx oversubscribed" %
              (loadavg[0], loadavg[1], loadavg[2], online_n, ratio))
        crashcolor.set_color(crashcolor.RESET)
        if loadavg[0] > loadavg[2] * 2 and loadavg[2] > 0:
            print("                 load1 >> load15: the pile-up is recent "
                  "(sudden stall, not steady load)")
    print("Runnable tasks : %d total across %d CPUs (%.1f per CPU); deepest "
          "run-queue = %d" %
          (total_runnable, online_n,
           (total_runnable / online_n) if online_n else 0.0, max_runq))
    if deep:
        deep_sorted = sorted(deep, key=lambda r: r["nr_running"], reverse=True)
        preview = ", ".join("CPU%d:%d" % (r["cpu"], r["nr_running"])
                            for r in deep_sorted[:8])
        print("Hot run-queues : %d CPUs with >= %d runnable  [%s%s]" %
              (len(deep), DEEP_RUNQ, preview,
               ", ..." if len(deep) > 8 else ""))

    if steal_enabled:
        if max_steal_pct >= 1.0:
            crashcolor.set_color(crashcolor.RED)
            print("CPU steal      : up to %.1f%% of a CPU's time was stolen by "
                  "the hypervisor" % max_steal_pct)
            crashcolor.set_color(crashcolor.RESET)
        else:
            print("CPU steal      : negligible (< 1%)")

    # per-vCPU timer-tick stalls: direct evidence a vCPU was not scheduled
    if stalled:
        crashcolor.set_color(crashcolor.RED)
        print("\nvCPU tick stalls (rq->clock_task - curr->se.exec_start): "
              "timer ticks stopped,")
        print("which on a guest means the hypervisor was NOT running these "
              "vCPUs --")
        crashcolor.set_color(crashcolor.RESET)
        print("  %4s %11s  %s" % ("CPU", "stalled(s)", "task on-CPU"))
        for r in stalled[:12]:
            crashcolor.set_color(crashcolor.LIGHTRED)
            print("  %4d %11.3f  %s" % (r["cpu"], r["tick_stall"], r["curr"]))
            crashcolor.set_color(crashcolor.RESET)
        if len(stalled) > 12:
            print("  ... and %d more" % (len(stalled) - 12))

    # ------------------------------------------------------------------
    # Long user-mode slices.  With other tasks queued, CFS preempts the
    # running task within roughly the scheduling-latency target; user code
    # has no way to block that.  A task observed on-CPU for wall-clock
    # seconds in USER mode with waiters means the preemption tick was not
    # delivered, i.e. the hypervisor was not running this vCPU.
    # ------------------------------------------------------------------
    oncpu_min_sec = max(0.5, slice_ms * 20 / 1000.0)
    over_slice = sorted(
        [r for r in rows
         if r["oncpu"] >= oncpu_min_sec and r["nr_running"] >= 2
         and not r["curr"].startswith("swapper")],
        key=lambda r: r["oncpu"], reverse=True)
    user_violations = []
    if over_slice:
        print("\nTasks on-CPU far beyond the scheduler slice "
              "(CFS target ~%.0f ms):" % slice_ms)
        print("  %4s %-16s %8s %10s %8s %6s %6s" %
              ("CPU", "task", "pid", "on-CPU(s)", "x slice", "queue",
               "mode"))
        for r in over_slice[:8]:
            mode = oc_task_mode(r["task"]) or "?"
            factor = (r["oncpu"] * 1000.0 / slice_ms) if slice_ms else 0.0
            if mode == "user":
                user_violations.append((r, factor))
                crashcolor.set_color(crashcolor.RED)
            print("  %4d %-16s %8d %10.3f %7.0fx %6d %6s" %
                  (r["cpu"], r["curr"][:16], r["pid"], r["oncpu"],
                   factor, r["nr_running"], mode))
            crashcolor.set_color(crashcolor.RESET)
        print("  (kernel mode can legitimately delay preemption; USER mode "
              "cannot)")

    # ------------------------------------------------------------------
    # Memory pressure (ballooning)
    # ------------------------------------------------------------------
    balloon = oc_get_balloon_pages()
    print("\n-- Memory pressure (ballooning) --")
    balloon_pressure = False
    if balloon is None:
        print("No balloon driver found (no host memory reclaim via balloon).")
    else:
        alloc, target, kind = balloon
        gb = crash.PAGESIZE / 1024.0 / 1024.0 / 1024.0
        balloon_pressure = alloc > 0
        color = crashcolor.RED if balloon_pressure else crashcolor.RESET
        crashcolor.set_color(color)
        print("%s balloon  : %d pages reclaimed by host (%.2f GB)" %
              (kind, alloc, alloc * gb))
        if target >= 0:
            print("               target %d pages (%.2f GB)%s" %
                  (target, target * gb,
                   "  [host wants MORE -> rising pressure]" if target > alloc
                   else ("  [at target]" if target == alloc else "")))
        crashcolor.set_color(crashcolor.RESET)

    # ------------------------------------------------------------------
    # Storage pressure: I/O the guest submitted but the host-backed device
    # has not completed.
    # ------------------------------------------------------------------
    scsi_hosts = oc_get_scsi_hosts()
    inflight, oldest_io = oc_get_inflight_requests()
    iowait_pct = oc_get_iowait_pct()

    print("\n-- Storage pressure --")
    storage_busy = False
    total_host_busy = 0
    host_failed_total = 0
    if scsi_hosts:
        total_host_busy = sum(h[2] for h in scsi_hosts if h[2] > 0)
        host_failed_total = sum(h[4] for h in scsi_hosts if h[4] > 0)
        print("SCSI hosts     : %d found, outstanding commands (host_busy) "
              "total = %d" % (len(scsi_hosts), total_host_busy))
        for (name, ndev, busy, blocked, failed) in scsi_hosts:
            if busy > 0 or blocked > 0 or failed > 0:
                extra = ["%d device(s)" % ndev]
                if busy > 0:
                    extra.append("outstanding=%d" % busy)
                if blocked > 0:
                    extra.append("host_blocked=%d" % blocked)
                if failed > 0:
                    extra.append("host_failed=%d (in error recovery!)"
                                 % failed)
                print("                 %s: %s" % (name, ", ".join(extra)))
    else:
        print("SCSI hosts     : none found (or walk unsupported)")
    if inflight >= 0:
        stuck = (inflight >= 16 or oldest_io >= 1.0)
        if stuck:
            crashcolor.set_color(crashcolor.RED)
        print("Block layer    : %d request(s) in flight, oldest waited "
              "%.1fs" % (inflight, oldest_io))
        crashcolor.set_color(crashcolor.RESET)
        if stuck:
            storage_busy = True
    if iowait_pct is not None:
        print("iowait         : %.1f%% of all CPU time (since boot)"
              % iowait_pct)
    if total_host_busy >= 8 or host_failed_total > 0:
        storage_busy = True

    # ------------------------------------------------------------------
    # Verdict
    # ------------------------------------------------------------------
    cpu_over = ((loadavg and online_n and loadavg[0] > online_n * 1.25)
                or max_runq >= DEEP_RUNQ
                or bool(stalled)
                or bool(user_violations)
                or max_steal_pct >= 5.0)

    print("\n== Verdict ==")
    ev_n = [0]

    def print_evidence(headline, why_lines):
        ev_n[0] += 1
        crashcolor.set_color(crashcolor.RED)
        print(" [%d] %s" % (ev_n[0], headline))
        crashcolor.set_color(crashcolor.RESET)
        for wl in why_lines:
            print("     %s" % wl)
        print("")

    if cpu_over:
        crashcolor.set_color(crashcolor.RED)
        print("LIKELY hypervisor CPU overcommit.  Evidence:\n")
        crashcolor.set_color(crashcolor.RESET)

        if user_violations:
            r, factor = user_violations[0]
            more = (", and %d more CPU(s) show the same"
                    % (len(user_violations) - 1)
                    if len(user_violations) > 1 else "")
            print_evidence(
                "'%s' (pid %d) ran USER-mode code on CPU %d for %.3fs in "
                "one stretch" % (r["curr"], r["pid"], r["cpu"], r["oncpu"]) +
                " (~%.0fx the ~%.0f ms CFS slice) with %d tasks queued%s"
                % (factor, slice_ms, r["nr_running"], more),
                ["Why: user code cannot block preemption -- the guest "
                 "kernel preempts via the",
                 "timer tick. A user task holding a CPU for wall-clock "
                 "seconds while others",
                 "queue means the vCPU (and its tick) was not being run by "
                 "the hypervisor."])

        if stalled:
            print_evidence(
                "%d vCPU(s) had their timer tick frozen for up to %.1fs "
                "(rq->clock_task vs" % (len(stalled),
                                        stalled[0]["tick_stall"]) +
                " curr->se.exec_start)",
                ["Why: the tick fires every few ms whenever a vCPU runs. A "
                 "multi-second gap in",
                 "the tick means the hypervisor descheduled that vCPU for "
                 "that long."])

        if loadavg and online_n and loadavg[0] > online_n * 1.25:
            recent = (loadavg[0] > loadavg[2] * 2 and loadavg[2] > 0)
            print_evidence(
                "load average %.2f vs %d CPUs (%.1fx oversubscribed), "
                "run-queues up to %d deep"
                % (loadavg[0], online_n, loadavg[0] / online_n, max_runq) +
                ("; load1 >> load15 (recent pile-up)" if recent else ""),
                ["Why: runnable work piled up because vCPUs stopped "
                 "draining their queues --",
                 "consistent with sudden host CPU starvation rather than a "
                 "gradual load rise."])
        elif max_runq >= DEEP_RUNQ:
            print_evidence(
                "run-queues up to %d tasks deep on single CPUs" % max_runq,
                ["Why: tasks are runnable but not getting CPU time; with a "
                 "healthy vCPU supply",
                 "queues this deep drain in milliseconds."])

        if max_steal_pct >= 5.0:
            print_evidence(
                "CPU steal time up to %.0f%% of a CPU's accounted time"
                % max_steal_pct,
                ["Why: steal is time the hypervisor itself reports it "
                 "withheld this vCPU --",
                 "direct confirmation from the host side."])

        if steal_enabled is False:
            print("  Note: steal is unaccounted on this guest, so the case "
                  "is inferential;")
            print("        confirm against the hypervisor host's CPU-ready "
                  "/ co-stop metrics.")
    elif is_virt:
        print("No clear CPU overcommit signature in this snapshot.")

    if storage_busy:
        crashcolor.set_color(crashcolor.RED)
        print("\nHost STORAGE pressure.  Evidence:\n")
        crashcolor.set_color(crashcolor.RESET)
        head = []
        if total_host_busy > 0:
            head.append("SCSI host_busy total %d" % total_host_busy)
        if host_failed_total > 0:
            head.append("%d command(s) in SCSI error recovery"
                        % host_failed_total)
        if inflight > 0:
            head.append("%d block request(s) in flight (oldest %.1fs)"
                        % (inflight, oldest_io))
        if iowait_pct is not None:
            head.append("iowait %.1f%% since boot" % iowait_pct)
        print_evidence(
            "; ".join(head),
            ["Why: these I/Os entered the guest I/O stack and are still "
             "incomplete. Commands",
             "outstanding at the virtual HBA point at a saturated host "
             "storage path (shared",
             "datastore); requests aged in the guest block layer with few "
             "outstanding at the",
             "HBA mean starved vCPUs could not even dispatch/complete them. "
             "Both are faces",
             "of host overcommit."])

    if balloon_pressure:
        crashcolor.set_color(crashcolor.RED)
        print("\nHost MEMORY pressure.  Evidence:\n")
        crashcolor.set_color(crashcolor.RESET)
        alloc, target, kind = balloon
        gb = crash.PAGESIZE / 1024.0 / 1024.0 / 1024.0
        print_evidence(
            "%s balloon holds %.2f GB of guest memory%s"
            % (kind, alloc * gb,
               " (host wants more)" if target > alloc else " (at target)"),
            ["Why: the balloon only inflates when the hypervisor is short "
             "of physical",
             "memory and reclaims it from guests -- the host is "
             "overcommitted on memory."])

    if not cpu_over and not balloon_pressure and not storage_busy and is_virt:
        print("No hypervisor overcommit evidence found.")


def vminfo():
    op = OptionParser()
    op.add_option("-d", "--details", dest="show_details", default=0,
                  action="store_true",
                  help="Show details")
    op.add_option("-c", "--context", dest="show_context", default=0,
                  action="store_true",
                  help="Show VM Context")
    op.add_option("-o", "--overcommit", dest="overcommit", default=0,
                  action="store_true",
                  help="Infer hypervisor CPU/memory overcommit "
                       "(steal, load, run-queues, tick stalls, balloon)")

    (o, args) = op.parse_args()

    if o.show_context:
        show_vm_context(o)
        return

    if o.overcommit:
        show_overcommit(o)
        return

    balloon_info(o)


if ( __name__ == '__main__'):
    vminfo()
