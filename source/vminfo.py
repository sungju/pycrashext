"""
 Written by Daniel Sungju Kwon
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
    Return a list of per-CPU dicts with cpu, nr_running, and tick_stall
    (rq->clock_task - curr->se.exec_start, in seconds): the time the vCPU's
    timer tick appears to have been stalled, i.e. the hypervisor was likely
    not scheduling this vCPU.
    """
    rows = []
    try:
        rqs = Tasks.getRunQueues()
    except Exception:
        return rows
    for rq in rqs:
        row = {"cpu": rq.cpu, "nr_running": -1, "tick_stall": -1.0,
               "curr": ""}
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
        except Exception:
            pass
        rows.append(row)
    rows.sort(key=lambda r: r["cpu"])
    return rows


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
    # Verdict
    # ------------------------------------------------------------------
    cpu_over = ((loadavg and online_n and loadavg[0] > online_n * 1.25)
                or max_runq >= DEEP_RUNQ
                or bool(stalled)
                or max_steal_pct >= 5.0)

    print("\n== Verdict ==")
    if cpu_over:
        crashcolor.set_color(crashcolor.RED)
        print("LIKELY hypervisor CPU overcommit.")
        crashcolor.set_color(crashcolor.RESET)
        reasons = []
        if loadavg and online_n and loadavg[0] > online_n * 1.25:
            reasons.append("load %.0f on %d CPUs (%.1fx)"
                           % (loadavg[0], online_n, loadavg[0] / online_n))
        if max_runq >= DEEP_RUNQ:
            reasons.append("run-queues up to %d deep" % max_runq)
        if stalled:
            reasons.append("%d vCPU(s) with timer ticks stalled up to %.1fs"
                           % (len(stalled), stalled[0]["tick_stall"]))
        if max_steal_pct >= 5.0:
            reasons.append("steal up to %.0f%%" % max_steal_pct)
        print("  Evidence: " + "; ".join(reasons) + ".")
        if steal_enabled is False:
            print("  Note: steal is unaccounted on this guest, so the case is "
                  "inferential; confirm")
            print("        against the hypervisor host's CPU-ready / co-stop "
                  "metrics.")
    elif is_virt:
        print("No clear CPU overcommit signature in this snapshot.")
    if balloon_pressure:
        crashcolor.set_color(crashcolor.RED)
        print("Host MEMORY pressure present (balloon active) -- check for "
              "co-occurring memory")
        print("overcommit on the host.")
        crashcolor.set_color(crashcolor.RESET)
    if not cpu_over and not balloon_pressure and is_virt:
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
