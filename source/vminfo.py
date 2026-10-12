"""
'vminfo' command: virtual-machine info, ballooning and hypervisor overcommit analysis.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from pykdump.API import *
from LinuxDump import Tasks, percpu

import crashcolor
import overcommit
import re


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

                # The host's target lives in virtio config space, not in
                # struct virtio_balloon (num_pfns is only the size of the
                # batch being inflated/deflated), so it is shown only when
                # a kernel carries a num_desired field.
                try:
                    num_desired = int(vb.num_desired)
                    print("required target (pages)    = %d" % num_desired)
                    print("required target (bytes)    = %d, (%.2fGB)" % (
                        num_desired * crash.PAGESIZE,
                        num_desired * crash.PAGESIZE / 1024 / 1024 / 1024))
                except Exception:
                    print("required target            = <in virtio config "
                          "space, not in the dump>")
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
    """
    Return (name, is_virt) from x86_hyper_type (4.15+), x86_hyper->name
    (RHEL7 and older), else X86_FEATURE_HYPERVISOR.
    """
    if symbol_exists("x86_hyper_type"):
        try:
            val = int(readSymbol("x86_hyper_type"))
            return HYPERVISOR_NAMES.get(val, "type %d" % val), (val != 0)
        except Exception:
            pass
    # RHEL7 knows only VMware, Hyper-V, Xen and KVM; any other hypervisor
    # leaves x86_hyper NULL and is found by the CPUID bit below.
    if symbol_exists("x86_hyper"):
        try:
            if int(readSymbol("x86_hyper")) != 0:
                out = exec_crash_command("p x86_hyper->name")
                m = re.search(r'"([^"]*)"', out)
                if m:
                    return m.group(1), True
        except Exception:
            pass
    try:
        boot_cpu_data = readSymbol("boot_cpu_data")
        if (boot_cpu_data.x86_capability[4] >> 31) & 1:
            return "hypervisor present", True
    except Exception:
        pass
    return "native (bare metal)", False


CPUTIME_DEFAULTS = {
    "CPUTIME_USER": 0, "CPUTIME_NICE": 1, "CPUTIME_SYSTEM": 2,
    "CPUTIME_SOFTIRQ": 3, "CPUTIME_IRQ": 4, "CPUTIME_IDLE": 5,
    "CPUTIME_IOWAIT": 6, "CPUTIME_STEAL": 7, "CPUTIME_GUEST": 8,
    "CPUTIME_GUEST_NICE": 9,
}


def oc_cputime_index(name):
    try:
        return int(EnumInfo("enum cpu_usage_stat")[name])
    except Exception:
        return CPUTIME_DEFAULTS[name]


def oc_get_steal_state():
    """Return (enabled, steal_by_cpu). enabled is True/False/None.

    steal_by_cpu maps cpu -> (steal, total); empty when unavailable.  total
    is every cpustat bucket except guest and guest_nice, which are already
    inside user and nice, so it tracks the vCPU's wall time (tickless idle
    is added back on idle exit) and steal / total reads like CPU Ready.
    The ratio is unit-free, so it reads the same whether cputime is ns or
    jiffies.  On VMware steal accounting is usually off, so steal reads 0.
    """
    enabled = None
    if symbol_exists("paravirt_steal_enabled"):
        try:
            enabled = int(readSymbol("paravirt_steal_enabled").enabled.counter) > 0
        except Exception:
            enabled = None

    steal = {}
    if symbol_exists("kernel_cpustat"):
        idx = oc_cputime_index("CPUTIME_STEAL")
        total_idx = [oc_cputime_index(name) for name in (
            "CPUTIME_USER", "CPUTIME_NICE", "CPUTIME_SYSTEM",
            "CPUTIME_SOFTIRQ", "CPUTIME_IRQ", "CPUTIME_IDLE",
            "CPUTIME_IOWAIT", "CPUTIME_STEAL")]
        try:
            for cpu, addr in enumerate(percpu.get_cpu_var("kernel_cpustat")):
                kcs = readSU("struct kernel_cpustat", addr)
                buckets = [int(x) for x in kcs.cpustat]
                if idx < len(buckets):
                    steal[cpu] = (buckets[idx],
                                  sum(buckets[i] for i in total_idx
                                      if i < len(buckets)))
        except Exception:
            pass
    return enabled, steal


def oc_get_crash_info():
    """DATE, UPTIME and PANIC lines from 'sys', as crash prints them."""
    info = {}
    try:
        for line in exec_crash_command("sys").splitlines():
            key, sep, val = line.partition(":")
            if sep and key.strip() in ("DATE", "UPTIME", "PANIC"):
                info[key.strip()] = val.strip()
    except Exception:
        pass
    return info


def oc_get_loadavg():
    """Return (load1, load5, load15) from avenrun (FSHIFT=11), or None."""
    try:
        av = readSymbol("avenrun")
        return tuple(int(av[i]) / 2048.0 for i in range(3))
    except Exception:
        return None


def oc_get_avenrun_raw():
    """Return the three unscaled avenrun values for detailed output."""
    try:
        av = readSymbol("avenrun")
        return tuple(int(av[i]) for i in range(3))
    except Exception:
        return None


def oc_counter_value(value):
    """Read either a plain integer or an atomic/atomic_long counter."""
    try:
        return int(value.counter)
    except (TypeError, AttributeError):
        return int(value)


def oc_get_totalram_pages():
    """Best-effort current guest RAM size in pages."""
    for name in ("totalram_pages", "_totalram_pages"):
        try:
            if symbol_exists(name):
                return oc_counter_value(readSymbol(name))
        except Exception:
            continue
    return -1


def oc_vmballoon_uncounted():
    """
    True when vmw_balloon does not go through balloon_compaction, so it
    never counts BALLOON_INFLATE: struct vmballoon has no b_dev_info before
    RHEL9.
    """
    try:
        return member_offset("struct vmballoon", "b_dev_info") < 0
    except Exception:
        return True


def oc_find_virtio_balloon():
    """Return the first registered struct virtio_balloon, or None."""
    try:
        drv = readSymbol("virtio_balloon_driver")
        p = drv.driver.p
        if p == 0:
            return None
        knode_driver_off = member_offset("struct device_private",
                                         "knode_driver")
        vdev_dev_off = member_offset("struct virtio_device", "dev")
        if knode_driver_off < 0 or vdev_dev_off < 0:
            return None
        for knode in readSUListFromHead(p.klist_devices.k_list, "n_node",
                                        "struct klist_node"):
            try:
                dev_priv = readSU("struct device_private",
                                  int(knode) - knode_driver_off)
                vdev = readSU("struct virtio_device",
                              int(dev_priv.device) - vdev_dev_off)
                return readSU("struct virtio_balloon", int(vdev.priv))
            except Exception:
                continue
    except Exception:
        pass
    return None


def oc_get_balloon_pages():
    """
    Return balloon data for the detected driver, or None.

    The result contains alloc, target, kind, symbol, address, raw_command
    and out_of_totalram.  target is -1 when the driver exposes no target.
    out_of_totalram is True when the driver takes ballooned pages out of
    totalram_pages (Hyper-V from RHEL8; virtio without DEFLATE_ON_OOM), so
    the guest's configured RAM is totalram_pages + alloc; vmw_balloon leaves
    them in.  'balloon_stats' is the Xen balloon (include/xen/balloon.h).
    """
    try:
        if symbol_exists("balloon"):
            b = readSymbol("balloon")
            try:
                addr = sym2addr("balloon")
            except Exception:
                addr = 0
            if not addr:
                addr = int(b)
            try:
                alloc = int(b.size.counter)
            except (TypeError, AttributeError):
                alloc = int(b.size)
            return {
                "alloc": alloc,
                "target": int(b.target),
                "kind": "VMware",
                "symbol": "balloon",
                "address": addr,
                "raw_command":
                    "struct vmballoon.size,target,stats 0x%x -d" % addr,
                "out_of_totalram": False,
            }
        if symbol_exists("balloon_stats"):
            b = readSymbol("balloon_stats")
            try:
                addr = sym2addr("balloon_stats")
            except Exception:
                addr = 0
            if not addr:
                addr = int(b)
            return {
                "alloc": int(b.current_pages),
                "target": int(b.target_pages),
                "kind": "Xen",
                "symbol": "balloon_stats",
                "address": addr,
                "raw_command": "struct balloon_stats 0x%x -d" % addr,
                "out_of_totalram": False,
            }
    except Exception:
        pass
    try:
        dm = readSymbol("dm_device")
        if dm != 0:
            try:
                addr = sym2addr("dm_device")
            except Exception:
                addr = 0
            if not addr:
                addr = int(dm)
            return {
                "alloc": int(dm.num_pages_ballooned),
                "target": -1,
                "kind": "Hyper-V",
                "symbol": "dm_device",
                "address": addr,
                "raw_command":
                    "struct hv_dynmem_device 0x%x -d" % addr,
                # hv_balloon adjusts managed pages from RHEL8 on, not in
                # RHEL7; x86_hyper_type (4.15+) tells the two apart.
                "out_of_totalram": symbol_exists("x86_hyper_type"),
            }
    except Exception:
        pass
    vb = oc_find_virtio_balloon()
    if vb is not None:
        # The host's target is in virtio config space; num_pfns is only the
        # batch in flight, so it must not stand in for a target.
        target = -1
        try:
            target = int(vb.num_desired)
        except Exception:
            pass
        # VIRTIO_BALLOON_F_DEFLATE_ON_OOM (bit 2): pages stay in totalram.
        deflate_on_oom = False
        try:
            deflate_on_oom = bool((int(vb.vdev.features) >> 2) & 1)
        except Exception:
            pass
        try:
            return {
                "alloc": int(vb.num_pages),
                "target": target,
                "kind": "virtio",
                "symbol": "virtio_balloon",
                "address": int(vb),
                "raw_command":
                    "struct virtio_balloon 0x%x -d" % int(vb),
                "out_of_totalram": not deflate_on_oom,
            }
        except Exception:
            pass
    return None


def oc_collect_runqueues():
    """
    Return per-CPU scheduler data.

    clock_lag compares rq->clock/Timestamp with the freshest runqueue clock.
    A guest vCPU that was descheduled while peers kept running has a stale
    clock, making this a useful single-vmcore CPU-starvation signal.

    curr_runtime is rq->clock_task - curr->se.exec_start.  It is scheduler
    runtime, not wall-clock "tick stall" time; it is retained as raw context
    and used only with the user-mode scheduler-slice check below.
    """
    rows = []
    try:
        rqs = Tasks.getRunQueues()
    except Exception:
        return rows
    for rq in rqs:
        row = {
            "cpu": int(rq.cpu),
            "nr_running": -1,
            "clock": -1,
            "clock_task": -1,
            "timestamp": -1,
            "exec_start": -1,
            "last_arrival": -1,
            "clock_lag": -1.0,
            "curr_runtime": -1.0,
            "curr": "",
            "pid": -1,
            "task": 0,
            "policy": -1,
            "oncpu": -1.0,
        }
        try:
            row["nr_running"] = int(rq.nr_running)
        except Exception:
            pass
        try:
            row["clock"] = int(rq.clock)
        except Exception:
            pass
        try:
            row["clock_task"] = int(rq.clock_task)
        except Exception:
            row["clock_task"] = row["clock"]
        try:
            row["timestamp"] = int(rq.Timestamp)
        except Exception:
            row["timestamp"] = row["clock"]
        try:
            row["exec_start"] = int(rq.curr.se.exec_start)
            if row["exec_start"] and row["clock_task"] >= 0:
                row["curr_runtime"] = (
                    row["clock_task"] - row["exec_start"]
                ) / 1000000000.0
        except Exception:
            pass
        try:
            row["curr"] = str(rq.curr.comm)
            row["pid"] = int(rq.curr.pid)
            row["task"] = int(rq.curr)
            row["policy"] = int(rq.curr.policy)
        except Exception:
            pass
        try:
            row["last_arrival"] = int(rq.curr.sched_info.last_arrival)
            if row["last_arrival"] and row["clock"] >= 0:
                row["oncpu"] = (
                    row["clock"] - row["last_arrival"]
                ) / 1000000000.0
        except Exception:
            pass
        rows.append(row)

    valid_clocks = [r["timestamp"] for r in rows if r["timestamp"] >= 0]
    if valid_clocks:
        newest = max(valid_clocks)
        for row in rows:
            if row["timestamp"] >= 0:
                row["clock_lag"] = (
                    newest - row["timestamp"]
                ) / 1000000000.0
    rows.sort(key=lambda r: r["cpu"])
    return rows


def oc_get_sched_slice_ms():
    """Return a CFS scheduling-interval reference in milliseconds."""
    for sym in ("sysctl_sched_latency", "sysctl_sched_base_slice",
                "normalized_sysctl_sched_latency"):
        try:
            val = int(readSymbol(sym))
            if val:
                return val / 1000000.0
        except Exception:
            continue
    return 24.0


def oc_task_context(task_addr):
    """
    Return (mode, raw_backtrace) for the interrupted task context.

    The first register block in 'bt' output is the context the dump NMI
    interrupted; a userspace RIP means the task was running application code
    at that instant.
    """
    try:
        out = exec_crash_command("bt 0x%x" % task_addr)
    except Exception:
        return None, ""
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("RIP:"):
            # crash may print either "RIP: ffffffff..." or
            # "RIP: 0010:[<ffffffff...>]"; skip the short CS selector.
            matches = re.findall(r"(?:0x)?[0-9a-fA-F]{8,16}", line[4:])
            if not matches:
                return None, out
            try:
                rip = int(matches[0], 16)
            except Exception:
                return None, out
            mode = "user" if rip < 0xffff800000000000 else "kernel"
            return mode, out
    return "kernel", out


TASK_NOLOAD = 0x400


def oc_collect_task_states():
    """
    Return a task-state census and raw rows for runnable/uninterruptible tasks.

    Load average includes both runnable and uninterruptible tasks.  The split
    prevents a large D-state I/O pile-up from being mislabeled CPU overcommit.
    TASK_IDLE (UNINTERRUPTIBLE | NOLOAD) threads, idle kworkers and RCU
    kthreads among them, are not in the load and are counted as 'noload'.
    """
    result = {
        "total": 0,
        "running": 0,
        "uninterruptible": 0,
        "noload": 0,
        "other": 0,
        "running_rows": [],
        "uninterruptible_rows": [],
    }
    try:
        state_field = ("__state" if
                       member_offset("struct task_struct", "__state") >= 0
                       else "state")
        tt = Tasks.TaskTable()
        for task in tt.allThreads():
            try:
                state = int(getattr(task, state_field))
            except Exception:
                try:
                    ts = task.ts
                    state = int(getattr(ts, state_field))
                    task = ts
                except Exception:
                    continue
            try:
                row = (int(task), int(task.pid), str(task.comm), state)
            except Exception:
                row = (0, -1, "?", state)
            result["total"] += 1
            if state == 0:
                result["running"] += 1
                result["running_rows"].append(row)
            elif state & 0x2 and state & TASK_NOLOAD:
                result["noload"] += 1
            elif state & 0x2:
                result["uninterruptible"] += 1
                result["uninterruptible_rows"].append(row)
            else:
                result["other"] += 1
    except Exception:
        pass
    return result


VM_EVENT_NAMES = (
    "PSWPIN", "PSWPOUT", "PGSCAN_KSWAPD", "PGSCAN_DIRECT",
    "PGSCAN_DIRECT_THROTTLE", "PGSTEAL_KSWAPD", "PGSTEAL_DIRECT",
    "ALLOCSTALL", "OOM_KILL", "COMPACTSTALL",
    # Newer kernels split several counters by zone.
    "PGSCAN_KSWAPD_DMA", "PGSCAN_KSWAPD_DMA32", "PGSCAN_KSWAPD_NORMAL",
    "PGSCAN_KSWAPD_MOVABLE", "PGSCAN_DIRECT_DMA", "PGSCAN_DIRECT_DMA32",
    "PGSCAN_DIRECT_NORMAL", "PGSCAN_DIRECT_MOVABLE",
    "ALLOCSTALL_DMA", "ALLOCSTALL_DMA32", "ALLOCSTALL_NORMAL",
    "ALLOCSTALL_MOVABLE",
    # Pages the host took/gave back through balloon_compaction (virtio and
    # newer vmw_balloon; not Hyper-V or the RHEL7 vmw_balloon).
    "BALLOON_INFLATE", "BALLOON_DEFLATE",
)


def oc_get_vm_events():
    """
    Return selected cumulative vm_event_states counters.

    These show guest reclaim/swap/compaction pain, but are deliberately only
    corroborating evidence: a cumulative guest counter cannot by itself prove
    that the hypervisor is short of memory.
    """
    values = {}
    try:
        enum = EnumInfo("enum vm_event_item")
        addrs = list(percpu.get_cpu_var("vm_event_states"))
        states = [readSU("struct vm_event_state", addr) for addr in addrs]
        for name in VM_EVENT_NAMES:
            try:
                idx = int(enum[name])
            except Exception:
                try:
                    idx = int(getattr(enum, name))
                except Exception:
                    continue
            total = 0
            found = False
            for state in states:
                try:
                    total += int(state.event[idx])
                    found = True
                except Exception:
                    pass
            if found:
                values[name] = total
    except Exception:
        pass
    return values


def oc_get_memory_snapshot(show_details=False):
    """Return current swap sizing and optional raw 'kmem -i' output."""
    data = {
        "totalram_pages": oc_get_totalram_pages(),
        "swap_total_pages": -1,
        "swap_free_pages": -1,
        "kmem_raw": "",
    }
    try:
        data["swap_total_pages"] = oc_counter_value(
            readSymbol("total_swap_pages"))
    except Exception:
        pass
    try:
        data["swap_free_pages"] = oc_counter_value(
            readSymbol("nr_swap_pages"))
    except Exception:
        pass
    if show_details:
        try:
            data["kmem_raw"] = exec_crash_command("kmem -i")
        except Exception:
            pass
    return data


def oc_get_log():
    """
    Time-anchored kernel log analysis (overcommit.analyse_log), or None.

    Log records widen the observation window beyond the final snapshot, and
    their timestamps say whether a symptom was at crash time or weeks ago.
    """
    try:
        return overcommit.analyse_log(exec_crash_command("log").splitlines())
    except Exception:
        return None


def oc_related_excerpt(raw, patterns, before=1, after=1):
    """
    Return (excerpt_rows, omitted), where excerpt_rows is [(line, matched)].

    Matching is case-insensitive.  Overlapping context windows are merged.
    """
    lines = raw.splitlines()
    lowered = tuple(pattern.lower() for pattern in patterns)
    matched = set()
    for index, line in enumerate(lines):
        lower = line.lower()
        if any(pattern in lower for pattern in lowered):
            matched.add(index)
    shown = set()
    for index in matched:
        shown.update(range(max(0, index - before),
                           min(len(lines), index + after + 1)))
    rows = []
    previous = None
    for index in sorted(shown):
        if previous is not None and index > previous + 1:
            rows.append(("... unrelated lines ...", False))
        rows.append((lines[index], index in matched))
        previous = index
    return rows, max(0, len(lines) - len(shown))


def oc_print_related_line(line, related=True, color=crashcolor.LIGHTRED):
    """Print a raw/context line with a visible marker and optional color."""
    print("=> " if related else "   ", end="")
    if related:
        crashcolor.set_color(color)
    print(line)
    crashcolor.set_color(crashcolor.RESET)


def oc_print_excerpt(raw, patterns, before=1, after=1,
                     color=crashcolor.LIGHTRED):
    """Print only pattern matches and their surrounding source lines."""
    rows, omitted = oc_related_excerpt(raw, patterns, before, after)
    for line, related in rows:
        oc_print_related_line(line, related, color)
    if not rows:
        print("   <no related lines>")
    if omitted:
        print("   ... %d unrelated line(s) omitted" % omitted)


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


def oc_get_scsi_hosts(request_rows=None):
    """
    Best-effort walk of the SCSI hosts (shost_class) returning
    [(name, ndev, busy, blocked, failed)].  'busy' is the number of commands
    outstanding at the (virtual) HBA -- the equivalent of the removed
    Scsi_Host.host_busy counter.  It is taken as the maximum of two sources:
      - block requests on the host's device queues that are 'active'
        (dispatched to the LLD) or 'softirq' (the LLD has completed them but
        the completion softirq has not yet run to retire them) -- this is
        what scsi_host_busy()/scsishow actually count on blk-mq kernels
        (request_rows comes from oc_get_inflight_requests()). Verified
        request-for-request against 'scsishow' on a live vmcore: 'queued'
        requests are NOT yet dispatched and must be excluded, or idle hosts
        with a deep queue backlog would be misreported as busy;
      - the per-device device_busy counters, kept as a defensive fallback
        for kernels where the block-layer walk above is unavailable (on the
        RHEL8 kernel this was verified against, device_busy itself reads 0
        even while scsishow shows commands outstanding, so it is NOT a
        reliable primary source).
    (iorequest_cnt - iodone_cnt is deliberately NOT used: the two counters
    drift apart over uptime -- e.g. tens of thousands on a CD-ROM device --
    so their difference does not measure outstanding commands.)
    """
    hosts = []
    # requests dispatched to the LLD or awaiting completion softirq, i.e.
    # commands the HBA itself considers outstanding, per request_queue.
    active_by_queue = {}
    for row in (request_rows or []):
        if row[2] in ("active", "softirq"):
            active_by_queue[row[1]] = active_by_queue.get(row[1], 0) + 1
    try:
        # pykdump knows every shost_class layout (class.p went away in
        # RHEL 9.5 and upstream 6.4).
        from LinuxDump.scsi import get_scsi_hosts
        has_sdev_busy = \
            member_offset("struct scsi_device", "device_busy") >= 0
        for shost in get_scsi_hosts() or []:
            try:
                member_busy = 0
                active_busy = 0
                ndev = 0
                for sdev in readSUListFromHead(shost.__devices, "siblings",
                                               "struct scsi_device"):
                    ndev += 1
                    if ndev > 4096:
                        break
                    try:
                        if has_sdev_busy:
                            member_busy += max(0, oc_counter_value(
                                sdev.device_busy))
                    except Exception:
                        pass
                    try:
                        active_busy += active_by_queue.get(
                            int(sdev.request_queue), 0)
                    except Exception:
                        pass
                busy = max(member_busy, active_busy)
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
    pykdump's LinuxDump.block helpers.  Returns
    (count, oldest_age_sec, raw_rows): requests the guest submitted that the
    (host-backed) device has not completed, the age of the oldest one, and
    the source request fields used by the summary.
    """
    count = 0
    oldest = 0.0
    raw_rows = []
    try:
        from LinuxDump.block import get_all_request_queues, \
                get_queue_requests
        for rq in get_all_request_queues(""):
            try:
                for request in get_queue_requests(rq):
                    count += 1
                    age = -1.0
                    try:
                        age = -float(request._reqinfo_.rq_alloc)
                        if age > oldest:
                            oldest = age
                    except Exception:
                        pass
                    try:
                        state = str(request._reqinfo_.state)
                    except Exception:
                        state = "?"
                    try:
                        qaddr = int(request.q)
                    except Exception:
                        try:
                            qaddr = int(rq)
                        except Exception:
                            qaddr = 0
                    try:
                        reqaddr = int(request)
                    except Exception:
                        reqaddr = 0
                    raw_rows.append((reqaddr, qaddr, state, age))
            except Exception:
                continue
    except Exception:
        return -1, -1.0, []
    return count, oldest, raw_rows


# A runqueue clock this far behind the freshest vCPU clock is treated as
# strong evidence that the hypervisor stopped scheduling that vCPU.
VCPU_CLOCK_LAG_SEC = 1.0
# A run-queue at/above this depth is treated as a CPU-pressure hotspot.
DEEP_RUNQ = 8
# Steal as a share of a vCPU's time since boot; the bar of CPU Ready.
STEAL_PCT = 5.0
# Load and runnable tasks per vCPU above which demand exceeds the vCPUs.
LOAD_RATIO = 1.25
# Share of guest swap in use counted as guest memory pressure.
SWAP_HEAVY_RATIO = 0.25
# Detailed output is intentionally bounded: it is an evidence excerpt, not a
# replacement for the underlying crash commands.
DETAIL_CPU_LIMIT = 8
DETAIL_TASK_LIMIT = 10
DETAIL_REQUEST_LIMIT = 10
DETAIL_BACKTRACE_LIMIT = 4
DETAIL_LOG_LINE_LIMIT = 40
SUMMARY_ROW_LIMIT = 12

OVERALL_TEXT = {
    "CONFIRMED": "the host reclaimed this guest's memory (see Memory)",
    "LIKELY": "a host-only signal fired; confirm with the host metrics below",
    "POSSIBLE": "only symptoms guest-local causes also produce; this dump "
                "cannot decide, check the host",
    "UNKNOWN": "no host-only signal could be read; check the host",
    "NO EVIDENCE": "nothing host-specific fired; read the blind spots "
                   "before ruling overcommit out",
    "NOT A VM": "virtualization not detected; the signals show guest "
                "pressure only",
}


def oc_status_color(status, kind=None):
    if status in ("CONFIRMED", "LIKELY") or (status == overcommit.HIT
                                              and kind == overcommit.HOST):
        return crashcolor.LIGHTRED
    if status in ("POSSIBLE", overcommit.HIT):
        return crashcolor.YELLOW
    if status == "UNKNOWN":
        return crashcolor.LIGHTCYAN
    return crashcolor.RESET


def oc_print_signal(sig):
    print("  [", end="")
    crashcolor.set_color(oc_status_color(sig.state, sig.kind))
    print("%-4s" % sig.state, end="")
    crashcolor.set_color(crashcolor.RESET)
    print("] " + overcommit.format_signal(sig))


def oc_cpu_list(rows, fmt, limit=3):
    text = ", ".join(fmt(r) for r in rows[:limit])
    if len(rows) > limit:
        text += " +%d more" % (len(rows) - limit)
    return text


def show_overcommit(options):
    """
    Infer hypervisor CPU/memory overcommit from a single vmcore.

    Every check becomes an overcommit.Signal.  Host-only signals (steal,
    a vCPU tick that stopped in user mode, a user task far past its CFS
    slice, a soft lockup while idle/user, a balloon) decide their domain;
    non-specific CPU symptoms raise it to POSSIBLE at most; guest-side
    pressure is shown for context and never counted.  The report then names
    what the guest cannot see and where to confirm it on the host.
    """
    HIT, MISS, NA = overcommit.HIT, overcommit.MISS, overcommit.NA
    HOST, SUPPORT, CONTEXT = (overcommit.HOST, overcommit.SUPPORT,
                              overcommit.CONTEXT)
    S = overcommit.Signal

    show_all = bool(getattr(options, "show_all", False))
    details = bool(getattr(options, "show_details", False)) or show_all
    hyper_name, is_virt = oc_get_hypervisor()
    crash_info = oc_get_crash_info()
    steal_enabled, steal_by_cpu = oc_get_steal_state()
    loadavg = oc_get_loadavg()
    avenrun_raw = oc_get_avenrun_raw()
    rows = oc_collect_runqueues()
    slice_ms = oc_get_sched_slice_ms()
    online_n = len(rows) if rows else sys_info.CPUS
    total_runnable = sum(r["nr_running"] for r in rows if r["nr_running"] >= 0)
    max_runq = max((r["nr_running"] for r in rows), default=0)
    deepest_cpu = max(rows, key=lambda r: r["nr_running"])["cpu"] if rows else -1
    deep = [r for r in rows if r["nr_running"] >= DEEP_RUNQ]
    clock_lagged = sorted(
        [r for r in rows
         if r["clock_lag"] >= VCPU_CLOCK_LAG_SEC
         and r["nr_running"] >= 2
         and not r["curr"].startswith("swapper")],
        key=lambda r: r["clock_lag"], reverse=True)

    steal_pct_by_cpu = {}
    for cpu, (st, total) in steal_by_cpu.items():
        if total:
            steal_pct_by_cpu[cpu] = 100.0 * st / total
    max_steal_pct = max(steal_pct_by_cpu.values(), default=0.0)
    steal_total = sum(st for st, total in steal_by_cpu.values())
    # Without paravirt_steal_enabled, all-zero steal cannot be told apart
    # from a hypervisor that never reports it.
    steal_visible = bool(steal_by_cpu) and (
        steal_enabled is True or (steal_enabled is None and steal_total > 0))

    # A user task consuming scheduler time far beyond the configured CFS
    # latency while peers wait means its guest preemption tick did not run.
    oncpu_min_sec = max(0.5, slice_ms * 20 / 1000.0)
    over_slice = sorted(
        [r for r in rows
         if r["oncpu"] >= oncpu_min_sec and r["nr_running"] >= 2
         and r["policy"] in (0, 3)
         and not r["curr"].startswith("swapper")],
        key=lambda r: r["oncpu"], reverse=True)
    user_violations = []
    task_contexts = {}
    context_rows = []
    seen_tasks = set()
    for r in clock_lagged + over_slice[:12]:
        if r["task"] in seen_tasks:
            continue
        seen_tasks.add(r["task"])
        context_rows.append(r)
    if show_all:
        for r in rows:
            if r["task"] in seen_tasks:
                continue
            seen_tasks.add(r["task"])
            context_rows.append(r)
    for r in context_rows:
        mode, bt_raw = oc_task_context(r["task"])
        task_contexts[r["task"]] = (mode or "?", bt_raw)

    def mode_of(r):
        return task_contexts.get(r["task"], ("?", ""))[0]

    for r in over_slice[:12]:
        factor = (r["oncpu"] * 1000.0 / slice_ms) if slice_ms else 0.0
        if mode_of(r) == "user":
            user_violations.append((r, factor))
    user_clock_lagged = [r for r in clock_lagged if mode_of(r) == "user"]
    other_clock_lagged = [r for r in clock_lagged if mode_of(r) != "user"]

    task_states = oc_collect_task_states()
    balloon = oc_get_balloon_pages()
    memory = oc_get_memory_snapshot(details)
    vm_events = oc_get_vm_events()
    log = oc_get_log()
    inflight, oldest_io, request_rows = oc_get_inflight_requests()
    scsi_hosts = oc_get_scsi_hosts(request_rows)
    iowait_pct = oc_get_iowait_pct()

    total_host_busy = 0
    host_failed_total = 0
    if scsi_hosts:
        total_host_busy = sum(h[2] for h in scsi_hosts if h[2] > 0)
        host_failed_total = sum(h[4] for h in scsi_hosts if h[4] > 0)
    storage_busy = (
        total_host_busy >= 8 or host_failed_total > 0
        or (inflight >= 16) or oldest_io >= 1.0)

    load_ratio = (
        loadavg[0] / online_n if loadavg and online_n else 0.0)
    runnable_ratio = total_runnable / online_n if online_n else 0.0
    load_high = bool(loadavg and online_n and load_ratio > LOAD_RATIO)
    runnable_high = runnable_ratio > LOAD_RATIO

    balloon_active = bool(balloon and balloon["alloc"] > 0)
    gib_per_page = crash.PAGESIZE / 1024.0 ** 3
    direct_reclaim = sum(
        val for name, val in vm_events.items()
        if name.startswith("PGSCAN_DIRECT"))
    allocstall = sum(
        val for name, val in vm_events.items()
        if name.startswith("ALLOCSTALL"))
    swap_used_pages = -1
    if (memory["swap_total_pages"] >= 0
            and memory["swap_free_pages"] >= 0):
        swap_used_pages = max(
            0, memory["swap_total_pages"] - memory["swap_free_pages"])
    swap_heavy = bool(
        swap_used_pages > 0 and memory["swap_total_pages"] > 0
        and swap_used_pages >= memory["swap_total_pages"] * SWAP_HEAVY_RATIO)

    # ------------------------------------------------------------------
    # Signals
    # ------------------------------------------------------------------
    signals = []
    steal_bar = ">= %.0f%% of vCPU time" % STEAL_PCT
    if not steal_by_cpu:
        signals.append(S("CPU", HOST, "vCPU time stolen (steal)", NA,
                         "kernel_cpustat unavailable", steal_bar))
    elif not steal_visible:
        signals.append(S("CPU", HOST, "vCPU time stolen (steal)", NA,
                         "not exported (paravirt_steal_enabled=0)"
                         if steal_enabled is False else
                         "all zero; hypervisor may not export it",
                         steal_bar))
    else:
        worst = max(steal_pct_by_cpu, key=steal_pct_by_cpu.get,
                    default=-1)
        signals.append(S("CPU", HOST, "vCPU time stolen (steal)",
                         HIT if max_steal_pct >= STEAL_PCT else MISS,
                         "worst CPU%d %.1f%% since boot"
                         % (worst, max_steal_pct), steal_bar))

    lag_bar = ">= %.1fs behind peers, runq >= 2" % VCPU_CLOCK_LAG_SEC
    if not rows:
        signals.append(S("CPU", HOST, "vCPU tick stalled in user mode", NA,
                         "runqueues unreadable", lag_bar))
        signals.append(S("CPU", HOST, "user task far past its CFS slice", NA,
                         "runqueues unreadable"))
    else:
        signals.append(S("CPU", HOST, "vCPU tick stalled in user mode",
                         HIT if user_clock_lagged else MISS,
                         oc_cpu_list(user_clock_lagged,
                                     lambda r: "CPU%d %.1fs"
                                     % (r["cpu"], r["clock_lag"]))
                         or "none", lag_bar))
        signals.append(S("CPU", HOST, "user task far past its CFS slice",
                         HIT if user_violations else MISS,
                         oc_cpu_list(user_violations,
                                     lambda rf: "CPU%d %s(%d) %.1fs = %.0fx"
                                     % (rf[0]["cpu"], rf[0]["curr"],
                                        rf[0]["pid"], rf[0]["oncpu"], rf[1]))
                         or "none",
                         ">= %.1fs on CPU with waiters" % oncpu_min_sec))

    # Log signals count only within the window before the end of the log:
    # a snapshot stun months ago says nothing about this crash.
    window = overcommit.duration_text(overcommit.LOG_WINDOW_SEC)
    quiet_bar = ("watchdog fired while the CPU idled or ran user code, "
                 "within %s of end of log" % window)
    if log is None:
        signals.append(S("CPU", HOST, "soft lockup while idle/user", NA,
                         "kernel log unavailable", quiet_bar))
    elif not overcommit.timed(log):
        signals.append(S("CPU", HOST, "soft lockup while idle/user", NA,
                         "log has no timestamps", quiet_bar))
    else:
        quiet = [s for s in log["softlockups"]
                 if s["where"] in ("idle", "user")]
        near_quiet = [s for s in quiet if s["time"] is not None
                      and s["time"] >= log["end"] - log["window"]]
        if near_quiet:
            value = "%d (%s), last %s" % (
                len(near_quiet),
                oc_cpu_list(near_quiet, lambda s: "CPU%d %s"
                            % (s["cpu"], s["where"])),
                overcommit.age_text(log, near_quiet[-1]["time"]))
        elif quiet:
            value = "none in last %s (%d older, last %s)" % (
                window, len(quiet), overcommit.age_text(log, quiet[-1]["time"]))
        elif log["softlockups"]:
            value = "none (%d in kernel code or unknown)" % len(
                log["softlockups"])
        else:
            value = "none"
        signals.append(S("CPU", HOST, "soft lockup while idle/user",
                         HIT if near_quiet else MISS, value, quiet_bar))

    if loadavg:
        value = "load1 %.2fx, runnable %.2fx per vCPU" % (load_ratio,
                                                           runnable_ratio)
        if load_high and not runnable_high:
            value += "; load is mostly D-state"
        signals.append(S("CPU", SUPPORT, "CPU demand above vCPUs",
                         HIT if load_high and runnable_high else MISS,
                         value, "both > %.2fx" % LOAD_RATIO))
    else:
        signals.append(S("CPU", SUPPORT, "CPU demand above vCPUs", NA,
                         "avenrun unavailable"))
    if rows:
        signals.append(S("CPU", SUPPORT, "deep runqueue",
                         HIT if max_runq >= DEEP_RUNQ else MISS,
                         "%d on CPU%d; %d CPU(s) at/above %d"
                         % (max_runq, deepest_cpu, len(deep), DEEP_RUNQ),
                         ">= %d" % DEEP_RUNQ))
        signals.append(S("CPU", SUPPORT, "vCPU clock lag, kernel/unknown mode",
                         HIT if other_clock_lagged else MISS,
                         oc_cpu_list(other_clock_lagged,
                                     lambda r: "CPU%d %.1fs %s"
                                     % (r["cpu"], r["clock_lag"], mode_of(r)))
                         or "none",
                         "kernel code may have had interrupts off"))
    if log is not None and not overcommit.timed(log):
        signals.append(S("CPU", SUPPORT, "log stall evidence near crash", NA,
                         "log has no timestamps"))
    elif log is not None:
        bursts = log["bursts"]
        near_bursts = [b for b in bursts
                       if b[0]["time"] >= log["end"] - log["window"]]
        if near_bursts:
            big = max(near_bursts,
                      key=lambda b: len(set(s["cpu"] for s in b)))
            value = "%d burst(s); largest %d CPUs, %s" % (
                len(near_bursts), len(set(s["cpu"] for s in big)),
                overcommit.age_text(log, big[0]["time"]))
        elif bursts:
            value = "none in last %s (%d older)" % (window, len(bursts))
        else:
            value = "none"
        signals.append(S("CPU", SUPPORT, "multi-CPU soft lockup burst",
                         HIT if near_bursts else MISS, value,
                         "2+ CPUs within %.0fs, within %s of end of log"
                         % (overcommit.BURST_SPAN_SEC, window)))
        near = []
        older = 0
        last_time = None
        for name in overcommit.CPU_LOG_CATEGORIES:
            events = log["categories"][name]
            n = len(overcommit.recent(log, events))
            older += len(events) - n
            if n:
                near.append("%s %d" % (name, n))
            if events and (last_time is None or
                           (events[-1][1] or 0) > last_time):
                last_time = events[-1][1]
        if near:
            value = "%s; last %s" % (", ".join(near),
                                     overcommit.age_text(log, last_time))
        elif older:
            value = "none in last %s (%d older, last %s)" % (
                window, older, overcommit.age_text(log, last_time))
        else:
            value = "none"
        signals.append(S("CPU", SUPPORT, "stall/timer messages near crash",
                         HIT if near else MISS, value,
                         "within %s of end of log" % window))

    if balloon is None:
        signals.append(S("Memory", HOST, "balloon holds guest memory now",
                         NA, "no balloon driver found", proof=True))
    else:
        alloc = balloon["alloc"]
        target = balloon["target"]
        ram = memory["totalram_pages"]
        if ram > 0 and balloon.get("out_of_totalram"):
            ram += alloc
        value = "%s %.2f GiB" % (balloon["kind"], alloc * gib_per_page)
        if ram > 0:
            value += " (%.1f%% of RAM)" % (100.0 * alloc / ram)
        if target < 0:
            value += ", target not in dump"
        else:
            value += ", target %.2f GiB (%s)" % (
                target * gib_per_page,
                "inflating" if target > alloc else
                "deflating" if target < alloc else "steady")
        signals.append(S("Memory", HOST, "balloon holds guest memory now",
                         HIT if alloc > 0 else MISS, value, "> 0",
                         proof=True))
    if "BALLOON_INFLATE" not in vm_events:
        signals.append(S("Memory", HOST, "balloon inflated since boot", NA,
                         "counter not in this kernel", proof=True))
    elif balloon is not None and balloon["kind"] in ("Hyper-V", "Xen"):
        signals.append(S("Memory", HOST, "balloon inflated since boot", NA,
                         "the %s balloon does not count it" % balloon["kind"],
                         proof=True))
    elif (balloon is not None and balloon["kind"] == "VMware"
          and oc_vmballoon_uncounted()):
        signals.append(S("Memory", HOST, "balloon inflated since boot", NA,
                         "this vmw_balloon (before RHEL9) does not count it",
                         proof=True))
    else:
        inflated = vm_events["BALLOON_INFLATE"]
        deflated = vm_events.get("BALLOON_DEFLATE", 0)
        value = ("inflated %.2f GiB, deflated %.2f GiB"
                 % (inflated * gib_per_page, deflated * gib_per_page))
        signals.append(S("Memory", HOST, "balloon inflated since boot",
                         HIT if inflated else MISS,
                         value if inflated else "0", "> 0", proof=True))

    if memory["swap_total_pages"] > 0:
        signals.append(S("Guest", CONTEXT, "guest swap in use",
                         HIT if swap_heavy else MISS,
                         "%d of %d pages (%.0f%%)"
                         % (max(swap_used_pages, 0),
                            memory["swap_total_pages"],
                            100.0 * max(swap_used_pages, 0)
                            / memory["swap_total_pages"]),
                         ">= %.0f%%" % (SWAP_HEAVY_RATIO * 100)))
    if vm_events:
        signals.append(S("Guest", CONTEXT, "guest reclaim stalls",
                         HIT if allocstall else MISS,
                         "%d allocation stalls, %d direct scans, %d OOM kills"
                         % (allocstall, direct_reclaim,
                            vm_events.get("OOM_KILL", 0)),
                         "since boot"))
    if log is not None:
        for name, label in (("memory", "OOM/allocation failure in log"),
                            ("storage", "storage errors in log")):
            events = log["categories"][name]
            signals.append(S("Guest", CONTEXT, label,
                             HIT if overcommit.recent(log, events) else MISS,
                             overcommit.category_summary(log, name)
                             or "none",
                             "within %s of end of log"
                             % overcommit.duration_text(log["window"])))
    if inflight >= 0 or scsi_hosts:
        value = "%d HBA command(s), " % total_host_busy
        if inflight >= 0:
            value += "%d request(s), oldest %.1fs" % (inflight, oldest_io)
        else:
            value += "block request walk unavailable"
        if host_failed_total:
            value += ", %d failed" % host_failed_total
        signals.append(S("Guest", CONTEXT, "outstanding/aged storage I/O",
                         HIT if storage_busy else MISS, value,
                         ">= 8 HBA cmds, >= 16 requests or >= 1s old"))

    cpu_status = overcommit.domain_verdict(signals, "CPU")
    memory_status = overcommit.domain_verdict(signals, "Memory")
    overall_status = (overcommit.overall_verdict([cpu_status, memory_status])
                      if is_virt else "NOT A VM")

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------
    def verdict_row(domain, status, text):
        print("  %-8s " % domain, end="")
        crashcolor.set_color(oc_status_color(status))
        print("%-12s" % status, end="")
        crashcolor.set_color(crashcolor.RESET)
        print(text)

    crashcolor.set_color(crashcolor.LIGHTCYAN)
    print("Hypervisor overcommit assessment")
    print("================================")
    crashcolor.set_color(crashcolor.RESET)
    steal_label = {
        True: "enabled",
        False: "disabled/unavailable to guest",
        None: "unknown",
    }[steal_enabled]
    print("Guest  : %s; %d vCPU(s); steal accounting %s"
          % (hyper_name, online_n, steal_label))
    if crash_info:
        print("Crash  : %s; uptime %s"
              % (crash_info.get("DATE", "?"), crash_info.get("UPTIME", "?")))
        if crash_info.get("PANIC"):
            print("Panic  : %s" % crash_info["PANIC"])

    print("\nAnswer")
    print("------")
    verdict_row("CPU", cpu_status,
                overcommit.answer_text(signals, "CPU", cpu_status))
    verdict_row("Memory", memory_status,
                overcommit.answer_text(signals, "Memory", memory_status))
    print("  " + "-" * 72)
    verdict_row("Overall", overall_status, OVERALL_TEXT[overall_status])

    sections = (
        (HOST, "Host-only signals (one HIT decides its domain)"),
        (SUPPORT, "Consistent with overcommit, not specific "
                  "(raise CPU to POSSIBLE at most)"),
        (CONTEXT, "Guest-side pressure (context only; never changes "
                  "the answer)"),
    )
    for kind, title in sections:
        mine = [s for s in signals if s.kind == kind]
        if not mine:
            continue
        print("\n" + title)
        for sig in mine:
            oc_print_signal(sig)

    if clock_lagged or over_slice or (log and log["softlockups"]):
        print("\nImplicated vCPUs")
    if clock_lagged:
        print("  Clock lag   contended vCPU clocks stopped relative to peers:")
        print("                CPU      lag    runq  mode    task(pid)")
        for r in clock_lagged[:SUMMARY_ROW_LIMIT]:
            print("               %4d %8.3fs %5d  %-6s  %s(%d)"
                  % (r["cpu"], r["clock_lag"], r["nr_running"],
                     mode_of(r), r["curr"], r["pid"]))
        if len(clock_lagged) > SUMMARY_ROW_LIMIT:
            print("               ... %d more"
                  % (len(clock_lagged) - SUMMARY_ROW_LIMIT))
    if over_slice:
        print("  CFS slices  target %.1fms; long current tasks with waiters:"
              % slice_ms)
        print("                CPU task(pid)                on-CPU   x slice  mode")
        for r in over_slice[:8]:
            factor = (
                r["oncpu"] * 1000.0 / slice_ms if slice_ms else 0.0)
            print("               %4d %-23s %7.3fs %8.0fx  %s"
                  % (r["cpu"], ("%s(%d)" % (r["curr"], r["pid"]))[:23],
                     r["oncpu"], factor, mode_of(r)))
    if log and log["softlockups"]:
        print("  Soft lockups (most recent last):")
        print("                CPU  stuck  where   at        "
              "RIP function / task")
        shown = log["softlockups"][-SUMMARY_ROW_LIMIT:]
        if len(log["softlockups"]) > len(shown):
            print("               ... %d older"
                  % (len(log["softlockups"]) - len(shown)))
        for s in shown:
            print("               %4d %5ds  %-6s  %-9s %s"
                  % (s["cpu"], s["stuck"], s["where"],
                     overcommit.duration_text(log["end"] - s["time"])
                     + " ago" if s["time"] is not None
                     and log["end"] is not None else "?",
                     s["func"] or s["comm"]))
    if task_states["total"]:
        print("\nTask states %d runnable, %d uninterruptible (D), "
              "%d TASK_IDLE (not in load), %d total"
              % (task_states["running"], task_states["uninterruptible"],
                 task_states["noload"], task_states["total"]))

    print("\nBlind spots")
    for spot in overcommit.blind_spots(hyper_name, steal_visible,
                                       balloon is not None, log):
        print("  - " + spot)
    if is_virt:
        print("\nTo confirm on the host")
        for check in overcommit.host_checks(hyper_name,
                                            crash_info.get("DATE", "")):
            print("  - " + check)

    if not details:
        print("\nUse -d with --overcommit to show related raw fields, nearby "
              "context,")
        print("and highlighted triggering values.")
        print("Use -a with --overcommit to show full details for all "
              "runqueues.")
        return

    # ------------------------------------------------------------------
    # Evidence-focused source data.  Keep this separate from the assessment
    # and show only implicated rows plus small context windows.
    # ------------------------------------------------------------------
    print("\nRelated raw data (-d)")
    print("=====================")
    print("=> related/triggering data; unmarked lines are surrounding context")

    direct_cpu_ids = set(
        cpu for cpu, pct in steal_pct_by_cpu.items() if pct >= STEAL_PCT)
    direct_cpu_ids.update(r["cpu"] for r in user_clock_lagged)
    direct_cpu_ids.update(r["cpu"] for r, factor in user_violations)
    all_related_cpu_ids = set(direct_cpu_ids)
    all_related_cpu_ids.update(r["cpu"] for r in clock_lagged)
    all_related_cpu_ids.update(r["cpu"] for r in deep)
    all_related_cpu_ids.update(r["cpu"] for r in over_slice)
    all_related_cpu_ids.update(
        cpu for cpu, pct in steal_pct_by_cpu.items() if pct >= 1.0)
    if not all_related_cpu_ids and (load_high or max_runq >= DEEP_RUNQ):
        all_related_cpu_ids.update(
            r["cpu"] for r in sorted(
                rows, key=lambda row: row["nr_running"],
                reverse=True)[:8])
    row_by_cpu = dict((r["cpu"], r) for r in rows)
    ranked_related_cpus = sorted(
        all_related_cpu_ids,
        key=lambda cpu: (
            cpu in direct_cpu_ids,
            row_by_cpu.get(cpu, {}).get("clock_lag", -1.0),
            steal_pct_by_cpu.get(cpu, 0.0),
            row_by_cpu.get(cpu, {}).get("nr_running", -1)),
        reverse=True)
    related_cpu_ids = set(ranked_related_cpus[:DETAIL_CPU_LIMIT])
    related_cpu_overflow = max(
        0, len(all_related_cpu_ids) - len(related_cpu_ids))
    available_cpu_ids = set(r["cpu"] for r in rows)
    context_cpu_ids = set()
    for cpu in related_cpu_ids:
        for neighbor in (cpu - 1, cpu + 1):
            if neighbor in available_cpu_ids:
                context_cpu_ids.add(neighbor)
    context_cpu_ids.difference_update(all_related_cpu_ids)
    shown_cpu_ids = related_cpu_ids | context_cpu_ids

    print("\n[VM identification]")
    print("detected=%s is_virtual=%s sys_info.CPUS=%d"
          % (hyper_name, is_virt, sys_info.CPUS))
    if symbol_exists("x86_hyper_type"):
        try:
            print("x86_hyper_type=%d" % int(readSymbol("x86_hyper_type")))
        except Exception:
            print("x86_hyper_type=<unavailable>")
    try:
        print("\n$ sys -i")
        sys_raw = exec_crash_command("sys -i")
        oc_print_excerpt(
            sys_raw,
            ("DMI_SYS_VENDOR:", "DMI_PRODUCT_NAME:", "DMI_BIOS_VENDOR:",
             "MACHINE:", "CPUS:"),
            before=0, after=0, color=crashcolor.LIGHTCYAN)
    except Exception:
        print("$ sys -i: <unavailable>")

    print("\n[CPU load and steal]")
    load_line = "avenrun (raw, FSHIFT=11) = %s" % (
        str(avenrun_raw) if avenrun_raw is not None else "unavailable")
    oc_print_related_line(load_line, load_high, crashcolor.YELLOW)
    steal_line = "paravirt_steal_enabled = %s" % (
        str(steal_enabled) if steal_enabled is not None else "unavailable")
    oc_print_related_line(
        steal_line, steal_enabled is False, crashcolor.YELLOW)
    if steal_by_cpu:
        shown_steal_cpus = [
            cpu for cpu in sorted(steal_by_cpu)
            if cpu in related_cpu_ids]
        if shown_steal_cpus:
            print("   %4s %20s %20s %9s"
                  % ("CPU", "CPUTIME_STEAL", "total (no guest)",
                     "steal%"))
        for cpu in shown_steal_cpus:
            st, total = steal_by_cpu[cpu]
            pct = steal_pct_by_cpu.get(cpu, 0.0)
            line = "%4d %20d %20d %8.3f%%" % (cpu, st, total, pct)
            oc_print_related_line(
                line, True,
                crashcolor.LIGHTRED if pct >= STEAL_PCT
                else crashcolor.YELLOW)
        omitted = len(steal_by_cpu) - len(shown_steal_cpus)
        if omitted:
            print("   ... %d unselected CPU steal row(s) omitted" % omitted)

    if show_all:
        print("\n[How to extract runqueue timing data manually]")
        print("  For a given CPU N and its current task:")
        print("    crash> runq -c N                                "
              "# runqueue summary for CPU N")
        print("    crash> struct rq.clock,clock_task <rq_addr>     "
              "# rq clock fields (nanoseconds)")
        print("    crash> p ((struct rq *)&runqueues+N)->clock      "
              "# alternative: rq.clock directly")
        print("    crash> struct task_struct.se <task_addr>         "
              "# scheduler entity (exec_start)")
        print("    crash> struct sched_info.last_arrival <task_addr>"
              "# when task was placed on-CPU")
        print("    crash> bt <task_addr>                            "
              "# backtrace of current task")
        print("  Derived fields:")
        print("    on-CPU       = (rq.clock - curr->sched_info.last_arrival) "
              "/ 1e9  seconds")
        print("    current-exec = (rq.clock_task - curr->se.exec_start)     "
              "/ 1e9  seconds")
        print("    clock-lag    = (max(all rq.Timestamp) - this rq.Timestamp)"
              " / 1e9  seconds")
        print("    depth        = rq.nr_running")

    print("\n[Per-vCPU runqueue fields; clocks are raw nanoseconds]")
    print("   %4s %5s %3s %16s %16s %16s %16s %9s %s"
          % ("CPU", "runq", "POL", "rq.clock", "clock_task",
             "exec_start", "last_arrival", "lag(s)",
             "current(pid/task)"))
    for r in rows:
        if not show_all and r["cpu"] not in shown_cpu_ids:
            continue
        line = (
            "%4d %5d %3d %16d %16d %16d %16d %9.3f %s(%d/0x%x)"
            % (r["cpu"], r["nr_running"], r["policy"], r["clock"],
               r["clock_task"], r["exec_start"], r["last_arrival"],
               r["clock_lag"], r["curr"], r["pid"], r["task"]))
        if r["cpu"] in related_cpu_ids:
            color = (crashcolor.LIGHTRED
                     if r["cpu"] in direct_cpu_ids
                     else crashcolor.YELLOW)
            oc_print_related_line(line, True, color)
        else:
            oc_print_related_line(line, False)
    if not shown_cpu_ids and not show_all:
        print("   <no per-vCPU row met an overcommit evidence threshold>")
    if related_cpu_overflow:
        print("   ... %d additional related CPU row(s) omitted"
              % related_cpu_overflow)
    unrelated_omitted = (
        len(available_cpu_ids - shown_cpu_ids - all_related_cpu_ids))
    if unrelated_omitted > 0 and not show_all:
        print("   ... %d unrelated CPU row(s) omitted"
              % unrelated_omitted)
    print("sysctl scheduler slice = %.3f ms" % slice_ms)

    if context_rows:
        if show_all:
            print("\n[Backtraces for all runqueues]")
        else:
            print("\n[Backtraces used to classify clock-lag/slice task mode]")
        if show_all:
            detail_context_rows = sorted(
                context_rows, key=lambda row: row["cpu"])
        else:
            detail_context_rows = sorted(
                context_rows,
                key=lambda row: row["cpu"] in direct_cpu_ids,
                reverse=True)[:DETAIL_BACKTRACE_LIMIT]
        for r in detail_context_rows:
            mode, bt_raw = task_contexts.get(r["task"], ("?", ""))
            oncpu = ("%.6fs" % r["oncpu"]
                     if r["oncpu"] >= 0 else "unavailable")
            curr_runtime = (
                "%.6fs" % r["curr_runtime"]
                if r["curr_runtime"] >= 0 else "unavailable")
            print("\n$ bt 0x%x  # CPU%d %s(%d), mode=%s, rq on-CPU=%s"
                  % (r["task"], r["cpu"], r["curr"], r["pid"], mode,
                     oncpu))
            timing_color = (
                crashcolor.LIGHTRED if r["cpu"] in direct_cpu_ids
                else crashcolor.YELLOW)
            oc_print_related_line(
                "runqueue timing: depth=%d on-CPU=%s current-exec=%s "
                "clock-lag=%.6fs"
                % (r["nr_running"], oncpu, curr_runtime, r["clock_lag"]),
                True, timing_color)
            oc_print_related_line(
                "raw: rq.clock=%d last_arrival=%d clock_task=%d "
                "exec_start=%d"
                % (r["clock"], r["last_arrival"], r["clock_task"],
                   r["exec_start"]),
                True, timing_color)
            if bt_raw:
                oc_print_excerpt(
                    bt_raw,
                    ("RIP:", "RSP:", "exception RIP", "PID:", "TASK:",
                     "#0 ", "#1 ", "#2 "),
                    before=0, after=1)
            else:
                print("   <unavailable>")
        if not show_all:
            omitted = len(context_rows) - len(detail_context_rows)
            if omitted:
                print("   ... %d additional classification backtrace(s) omitted"
                      % omitted)

    print("\n[Task-state rows]")
    print("total=%d running=%d uninterruptible=%d noload(TASK_IDLE)=%d "
          "other=%d"
          % (task_states["total"], task_states["running"],
             task_states["uninterruptible"], task_states["noload"],
             task_states["other"]))
    related_task_addrs = set(r["task"] for r in context_rows)
    selected_running = [
        row for row in task_states["running_rows"]
        if row[0] in related_task_addrs][:DETAIL_TASK_LIMIT]
    selected_un = []
    if storage_busy or load_high or task_states["uninterruptible"] > online_n:
        remaining = max(0, DETAIL_TASK_LIMIT - len(selected_running))
        selected_un = task_states["uninterruptible_rows"][
            :remaining]
    selected_tasks = selected_running + selected_un
    if selected_tasks:
        print("   %18s %8s %10s %s" % ("TASK", "PID", "STATE", "COMM"))
    for addr, pid, comm, state in selected_tasks:
        color = (crashcolor.LIGHTRED if addr in related_task_addrs
                 else crashcolor.YELLOW)
        oc_print_related_line(
            "0x%016x %8d 0x%08x %s" % (addr, pid, state, comm),
            True, color)
    if not selected_tasks:
        print("   <no task row directly related to the assessment>")
    task_rows_total = (
        len(task_states["running_rows"])
        + len(task_states["uninterruptible_rows"]))
    omitted = task_rows_total - len(selected_tasks)
    if omitted > 0:
        print("   ... %d unrelated runnable/D-state row(s) omitted" % omitted)

    print("\n[Memory symbols and VM events]")
    memory_line = "totalram_pages=%d total_swap_pages=%d nr_swap_pages=%d" % (
        memory["totalram_pages"], memory["swap_total_pages"],
        memory["swap_free_pages"])
    if balloon is not None:
        memory_line += " balloon_out_of_totalram=%s" % bool(
            balloon.get("out_of_totalram"))
    oc_print_related_line(
        memory_line, balloon_active or swap_heavy,
        crashcolor.LIGHTRED if balloon_active else crashcolor.YELLOW)
    nonzero_events = [
        (name, vm_events[name]) for name in sorted(vm_events)
        if vm_events[name] != 0]
    for name, value in nonzero_events:
        color = (crashcolor.LIGHTRED
                 if name in ("OOM_KILL", "BALLOON_INFLATE") and value
                 else crashcolor.YELLOW)
        oc_print_related_line("%-28s %d" % (name, value), True, color)
    zero_events = len(vm_events) - len(nonzero_events)
    if zero_events:
        print("   ... %d zero VM event counter(s) omitted" % zero_events)
    if balloon:
        print("\n$ %s" % balloon["raw_command"])
        try:
            balloon_raw = exec_crash_command(balloon["raw_command"])
            oc_print_excerpt(
                balloon_raw,
                ("size", "target", "current_pages", "target_pages",
                 "num_pages_ballooned", "num_pages", "num_desired",
                 "refused", "retry", "rate_", "schedule_delay"),
                before=1, after=1)
        except Exception as e:
            print("<unavailable: %s>" % str(e))
    if memory["kmem_raw"]:
        print("\n$ kmem -i")
        oc_print_excerpt(
            memory["kmem_raw"],
            ("TOTAL MEM", "FREE", "TOTAL SWAP", "SWAP USED", "SWAP FREE"),
            before=0, after=0,
            color=(crashcolor.LIGHTRED if swap_heavy
                   else crashcolor.LIGHTCYAN))

    print("\n[SCSI host fields]")
    related_hosts = [
        host for host in scsi_hosts
        if host[2] > 0 or host[3] > 0 or host[4] > 0]
    if related_hosts:
        print("   %-8s %8s %12s %12s %12s"
              % ("HOST", "devices", "outstanding", "blocked", "failed"))
    for name, ndev, busy, blocked, failed in related_hosts:
        color = (crashcolor.LIGHTRED
                 if failed > 0 or blocked > 0 or busy >= 8
                 else crashcolor.YELLOW)
        oc_print_related_line(
            "%-8s %8d %12d %12d %12d"
            % (name, ndev, busy, blocked, failed), True, color)
    if not related_hosts:
        print("   <no SCSI host has outstanding/blocked/failed commands>")
    omitted = len(scsi_hosts) - len(related_hosts)
    if omitted:
        print("   ... %d idle SCSI host row(s) omitted" % omitted)

    print("\n[Block request fields]")
    aged_requests = sorted(
        [row for row in request_rows if row[3] >= 1.0],
        key=lambda row: row[3], reverse=True)[:DETAIL_REQUEST_LIMIT]
    if not aged_requests and inflight >= 16:
        aged_requests = sorted(
            request_rows, key=lambda row: row[3],
            reverse=True)[:DETAIL_REQUEST_LIMIT]
    if aged_requests:
        print("   %18s %18s %-12s %s"
              % ("REQUEST", "QUEUE", "STATE", "age(s)"))
    for reqaddr, qaddr, state, age in aged_requests:
        oc_print_related_line(
            "0x%016x 0x%016x %-12s %.6f"
            % (reqaddr, qaddr, state, age),
            True,
            crashcolor.LIGHTRED if age >= 1.0 else crashcolor.YELLOW)
    if not aged_requests:
        print("   <no request is at least 1s old>")
    omitted = len(request_rows) - len(aged_requests)
    if omitted:
        print("   ... %d younger block request row(s) omitted" % omitted)
    if iowait_pct is not None:
        print("iowait = %.1f%% of accounted CPU time since boot" % iowait_pct)

    print("\n[Kernel log matches with two surrounding lines]")
    if log is None:
        print("   <log unavailable>")
    else:
        if log["end"] is not None:
            print("log covers %.1fs .. %.1fs after boot"
                  % (log["start"], log["end"]))
        for name, _ in overcommit.LOG_CATEGORIES:
            events = log["categories"][name]
            if not events:
                continue
            print("\n%s (%s)" % (name, overcommit.category_summary(log, name)))
            context = overcommit.excerpt(
                log["lines"], set(index for index, t in events))
            shown_context = context[-DETAIL_LOG_LINE_LIMIT:]
            omitted = len(context) - len(shown_context)
            if omitted:
                print("   ... %d older context line(s) omitted" % omitted)
            for line, related in shown_context:
                oc_print_related_line(line, related)


def vminfo():
    op = OptionParser()
    op.add_option("-d", "--details", dest="show_details", default=0,
                  action="store_true",
                  help="Show details (with --overcommit, append related raw "
                       "data and context)")
    op.add_option("-a", "--all", dest="show_all", default=0,
                  action="store_true",
                  help="Show full details for all runqueues and how to "
                       "extract their timing fields (implies -d)")
    op.add_option("-c", "--context", dest="show_context", default=0,
                  action="store_true",
                  help="Show VM Context")
    op.add_option("-o", "--overcommit", dest="overcommit", default=0,
                  action="store_true",
                  help="Assess hypervisor CPU/memory overcommit, signal "
                       "by signal")

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
