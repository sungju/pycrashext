"""
'vminfo' command: virtual-machine info, ballooning and hypervisor overcommit analysis.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from pykdump.API import *
from LinuxDump import Tasks, percpu

import crashcolor
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

    The result contains alloc, target, kind, symbol, address and raw_command.
    target is -1 when the driver exposes no target.
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
                "kind": "VMware",
                "symbol": "balloon_stats",
                "address": addr,
                "raw_command": "struct balloon_stats 0x%x -d" % addr,
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
            }
    except Exception:
        pass
    vb = oc_find_virtio_balloon()
    if vb is not None:
        target = -1
        for field in ("num_desired", "num_pfns"):
            try:
                target = int(getattr(vb, field))
                break
            except Exception:
                continue
        try:
            return {
                "alloc": int(vb.num_pages),
                "target": target,
                "kind": "virtio",
                "symbol": "virtio_balloon",
                "address": int(vb),
                "raw_command":
                    "struct virtio_balloon 0x%x -d" % int(vb),
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


def oc_collect_task_states():
    """
    Return a task-state census and raw rows for runnable/uninterruptible tasks.

    Load average includes both runnable and uninterruptible tasks.  The split
    prevents a large D-state I/O pile-up from being mislabeled CPU overcommit.
    """
    result = {
        "total": 0,
        "running": 0,
        "uninterruptible": 0,
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


LOG_PATTERNS = {
    "CPU stall": (
        "soft lockup", "rcu_sched detected stalls",
        "rcu_preempt detected stalls", "rcu: info: rcu_",
    ),
    "Clock/timer": (
        "clocksource watchdog", "timekeeping watchdog",
        "hrtimer: interrupt took", "nohz: local_softirq_pending",
    ),
    "Memory": (
        "invoked oom-killer", "out of memory:", "oom-kill:",
        "page allocation failure",
    ),
    "Storage": (
        "blk_update_request: i/o error", "buffer i/o error",
        "timing out command", "rejecting i/o to offline device",
        "resetting link", "abort command",
    ),
}


def oc_get_log_evidence():
    """
    Return vmcore kernel-log lines that record historical stall symptoms.

    Log records widen the observation window beyond the final snapshot.  They
    remain supporting evidence because the same messages can have guest-local
    causes.
    """
    result = dict((name, []) for name in LOG_PATTERNS)
    try:
        raw = exec_crash_command("log")
    except Exception:
        return result
    for line in raw.splitlines():
        lower = line.lower()
        for name, patterns in LOG_PATTERNS.items():
            if any(pattern in lower for pattern in patterns):
                result[name].append(line)
    return result


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


def show_overcommit(options):
    """
    Infer hypervisor CPU/memory overcommit from a single vmcore.

    CPU steal is invisible to a guest that does not account it (VMware), so
    this correlates direct guest-visible signals (steal, stale vCPU scheduler
    clocks and ballooning) with supporting symptoms (load/runqueues, task
    states, storage queues, VM reclaim counters and historical kernel logs).
    """
    details = bool(getattr(options, "show_details", False))
    hyper_name, is_virt = oc_get_hypervisor()
    steal_enabled, steal_by_cpu = oc_get_steal_state()
    loadavg = oc_get_loadavg()
    avenrun_raw = oc_get_avenrun_raw()
    rows = oc_collect_runqueues()
    slice_ms = oc_get_sched_slice_ms()
    online_n = len(rows) if rows else sys_info.CPUS
    total_runnable = sum(r["nr_running"] for r in rows if r["nr_running"] >= 0)
    max_runq = max((r["nr_running"] for r in rows), default=0)
    deep = [r for r in rows if r["nr_running"] >= DEEP_RUNQ]
    clock_lagged = sorted(
        [r for r in rows
         if r["clock_lag"] >= VCPU_CLOCK_LAG_SEC
         and r["nr_running"] >= 2
         and not r["curr"].startswith("swapper")],
        key=lambda r: r["clock_lag"], reverse=True)

    max_steal_pct = 0.0
    steal_pct_by_cpu = {}
    for (st, tt) in steal_by_cpu.values():
        if tt:
            max_steal_pct = max(max_steal_pct, 100.0 * st / tt)
    for cpu, (st, tt) in steal_by_cpu.items():
        if tt:
            steal_pct_by_cpu[cpu] = 100.0 * st / tt

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
    for r in clock_lagged[:12] + over_slice[:12]:
        if r["task"] in seen_tasks:
            continue
        seen_tasks.add(r["task"])
        context_rows.append(r)
    for r in context_rows:
        mode, bt_raw = oc_task_context(r["task"])
        task_contexts[r["task"]] = (mode or "?", bt_raw)
    for r in over_slice[:12]:
        mode = task_contexts.get(r["task"], ("?", ""))[0]
        factor = (r["oncpu"] * 1000.0 / slice_ms) if slice_ms else 0.0
        if mode == "user":
            user_violations.append((r, factor))
    user_clock_lagged = [
        r for r in clock_lagged
        if task_contexts.get(r["task"], ("?", ""))[0] == "user"]

    task_states = oc_collect_task_states()
    balloon = oc_get_balloon_pages()
    memory = oc_get_memory_snapshot(details)
    vm_events = oc_get_vm_events()
    log_evidence = oc_get_log_evidence()
    scsi_hosts = oc_get_scsi_hosts()
    inflight, oldest_io, request_rows = oc_get_inflight_requests()
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
    load_high = bool(loadavg and online_n
                     and loadavg[0] > online_n * 1.25)
    runnable_high = total_runnable > online_n * 1.25 if online_n else False
    cpu_direct = (
        max_steal_pct >= 5.0 or bool(user_clock_lagged)
        or bool(user_violations))
    cpu_supporting = (
        bool(clock_lagged) or max_runq >= DEEP_RUNQ
        or (load_high and runnable_high))
    if cpu_direct:
        cpu_status = "LIKELY"
    elif cpu_supporting:
        cpu_status = "POSSIBLE"
    else:
        cpu_status = "NO EVIDENCE"

    balloon_active = bool(balloon and balloon["alloc"] > 0)
    balloon_current = bool(
        balloon_active
        and (balloon["target"] < 0 or balloon["target"] > 0))
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
        and swap_used_pages >= memory["swap_total_pages"] * 0.25)
    guest_memory_pressure = swap_heavy or bool(log_evidence["Memory"])
    if balloon_current:
        memory_status = "HOST RECLAIM"
    elif balloon_active:
        memory_status = "RECENT RECLAIM"
    elif guest_memory_pressure:
        memory_status = "GUEST PRESSURE"
    else:
        memory_status = "NO EVIDENCE"

    if storage_busy:
        storage_status = "PRESSURE"
    elif inflight >= 0 or scsi_hosts:
        storage_status = "CLEAR"
    else:
        storage_status = "UNKNOWN"

    if not is_virt:
        overall_status = "NOT A VM"
    elif cpu_status == "LIKELY" or balloon_current:
        overall_status = "LIKELY"
    elif (cpu_status == "POSSIBLE" or balloon_active
          or storage_busy or guest_memory_pressure):
        overall_status = "POSSIBLE"
    else:
        overall_status = "NO EVIDENCE"

    def set_status_color(status):
        if status in ("LIKELY", "HOST RECLAIM", "PRESSURE"):
            crashcolor.set_color(crashcolor.RED)
        elif status in ("POSSIBLE", "RECENT RECLAIM", "GUEST PRESSURE"):
            crashcolor.set_color(crashcolor.YELLOW)
        else:
            crashcolor.set_color(crashcolor.RESET)

    def summary_row(domain, status, text):
        print("  %-8s " % domain, end="")
        set_status_color(status)
        print("%-14s" % status, end="")
        crashcolor.set_color(crashcolor.RESET)
        print(text)

    cpu_summary = []
    if max_steal_pct >= 5.0:
        cpu_summary.append("steal %.1f%%" % max_steal_pct)
    if user_clock_lagged:
        cpu_summary.append(
            "%d contended user-mode vCPU clock(s) lagged, max %.1fs"
            % (len(user_clock_lagged),
               user_clock_lagged[0]["clock_lag"]))
    elif clock_lagged:
        cpu_summary.append("%d contended vCPU clock(s) lagged, max %.1fs"
                           % (len(clock_lagged),
                              clock_lagged[0]["clock_lag"]))
    if user_violations:
        cpu_summary.append("%d user task(s) exceeded CFS slice"
                           % len(user_violations))
    if not cpu_summary and cpu_supporting:
        cpu_summary.append("load %.2fx, deepest runqueue %d"
                           % (load_ratio, max_runq))
    if not cpu_summary:
        cpu_summary.append("no direct CPU-starvation signal")

    mem_summary = "no balloon activity"
    if balloon:
        alloc = balloon["alloc"]
        target = balloon["target"]
        gib_per_page = crash.PAGESIZE / 1024.0 ** 3
        percent = -1.0
        if memory["totalram_pages"] > 0:
            percent = 100.0 * alloc / memory["totalram_pages"]
        mem_summary = "%s balloon %.2f GiB" % (
            balloon["kind"], alloc * gib_per_page)
        if percent >= 0:
            mem_summary += " (%.1f%% of guest RAM)" % percent
        if target > alloc:
            mem_summary += ", target rising"
        elif target == 0 and alloc > 0:
            mem_summary += ", target is zero/deflating"

    storage_summary = "storage walkers unavailable"
    if inflight >= 0 or scsi_hosts:
        storage_summary = "%d HBA command(s), " % total_host_busy
        if inflight >= 0:
            storage_summary += "%d block request(s), oldest %.1fs" % (
                inflight, oldest_io)
        else:
            storage_summary += "block request walk unavailable"

    crashcolor.set_color(crashcolor.LIGHTCYAN)
    print("Hypervisor overcommit assessment")
    print("===============================")
    crashcolor.set_color(crashcolor.RESET)
    steal_label = {
        True: "enabled",
        False: "disabled/unavailable to guest",
        None: "unknown",
    }[steal_enabled]
    print("Guest       : %s; %d vCPU(s); steal accounting %s"
          % (hyper_name, online_n, steal_label))
    if not is_virt:
        print("Scope       : hypervisor not detected; results below are guest "
              "pressure only")

    print("\nAssessment")
    print("----------")
    summary_row("CPU", cpu_status, "; ".join(cpu_summary))
    summary_row("Memory", memory_status, mem_summary)
    summary_row("Storage", storage_status, storage_summary)
    print("  " + "-" * 72)
    summary_row("Overall", overall_status,
                "single-vmcore inference; confirm with host metrics")

    print("\nEvidence")
    print("--------")
    print("CPU")
    if loadavg:
        recent = loadavg[2] > 0 and loadavg[0] > loadavg[2] * 2
        print("  Load        %.2f / %.2f / %.2f over %d vCPUs (%.2fx)%s"
              % (loadavg[0], loadavg[1], loadavg[2], online_n, load_ratio,
                 "; recent pile-up" if recent else ""))
    else:
        print("  Load        unavailable")
    print("  Runqueues   %d runnable; %.1f/vCPU; deepest %d; %d hot (>= %d)"
          % (total_runnable,
             total_runnable / online_n if online_n else 0.0,
             max_runq, len(deep), DEEP_RUNQ))
    if task_states["total"]:
        print("  Task states %d runnable, %d uninterruptible (D), %d total"
              % (task_states["running"],
                 task_states["uninterruptible"], task_states["total"]))
        if load_high and not runnable_high:
            print("              high load is not matched by runnable work; "
                  "D-state/I/O is a better fit")
    if steal_enabled is False:
        print("  Steal       unavailable: paravirt_steal_enabled=0")
    elif steal_by_cpu:
        print("  Steal       maximum %.1f%% since boot" % max_steal_pct)
    else:
        print("  Steal       unavailable")
    if clock_lagged:
        print("  Clock lag   contended vCPU clocks stopped relative to peers:")
        print("                CPU      lag    runq  mode    task(pid)")
        for r in clock_lagged[:12]:
            mode = task_contexts.get(r["task"], ("?", ""))[0]
            print("               %4d %8.3fs %5d  %-6s  %s(%d)"
                  % (r["cpu"], r["clock_lag"], r["nr_running"],
                     mode, r["curr"], r["pid"]))
        if len(clock_lagged) > 12:
            print("               ... %d more" % (len(clock_lagged) - 12))
    if over_slice:
        print("  CFS slices  target %.1fms; long current tasks with waiters:"
              % slice_ms)
        print("                CPU task(pid)                on-CPU   x slice  mode")
        for r in over_slice[:8]:
            mode = task_contexts.get(r["task"], ("?", ""))[0]
            factor = (
                r["oncpu"] * 1000.0 / slice_ms if slice_ms else 0.0)
            print("               %4d %-23s %7.3fs %8.0fx  %s"
                  % (r["cpu"], ("%s(%d)" % (r["curr"], r["pid"]))[:23],
                     r["oncpu"], factor, mode))

    print("\nMemory")
    if balloon:
        alloc = balloon["alloc"]
        target = balloon["target"]
        gib_per_page = crash.PAGESIZE / 1024.0 ** 3
        print("  Balloon     %s: %d pages (%.2f GiB), target %s"
              % (balloon["kind"], alloc, alloc * gib_per_page,
                 ("%d pages" % target) if target >= 0 else "unavailable"))
    else:
        print("  Balloon     no supported active balloon device found")
    if memory["swap_total_pages"] >= 0:
        print("  Guest swap  %s / %d pages used"
              % (str(swap_used_pages) if swap_used_pages >= 0 else "?",
                 memory["swap_total_pages"]))
    if vm_events:
        print("  VM events   direct scans %d; allocation stalls %d; "
              "OOM kills %d (all cumulative)"
              % (direct_reclaim, allocstall,
                 vm_events.get("OOM_KILL", 0)))

    print("\nStorage")
    if scsi_hosts:
        print("  Virtual HBA %d host(s); %d command(s) outstanding; "
              "%d failed/recovery"
              % (len(scsi_hosts), total_host_busy, host_failed_total))
    else:
        print("  Virtual HBA unavailable or no SCSI hosts")
    if inflight >= 0:
        print("  Block layer %d request(s) in flight; oldest %.1fs"
              % (inflight, oldest_io))
    else:
        print("  Block layer request walk unavailable")
    if iowait_pct is not None:
        print("  iowait      %.1f%% of accounted CPU time since boot"
              % iowait_pct)

    log_counts = [
        "%s=%d" % (name, len(lines))
        for name, lines in log_evidence.items() if lines]
    print("\nHistorical kernel log")
    if log_counts:
        print("  Matches     %s" % ", ".join(log_counts))
        print("              supporting symptoms only; see -d for exact lines")
    else:
        print("  Matches     no selected CPU/clock/memory/storage stall messages")

    print("\nInterpretation")
    print("--------------")
    if not is_virt:
        print("No hypervisor conclusion: virtualization was not detected. "
              "The domain data")
        print("above can still identify a guest-local or bare-metal stall.")
    elif overall_status == "NO EVIDENCE":
        print("No clear hypervisor-overcommit signature is present in this "
              "snapshot.")
    else:
        if cpu_status == "LIKELY":
            print("* CPU: steal or a user-mode clock/slice violation is strong "
                  "evidence")
            print("  that the hypervisor withheld vCPU time.")
        elif cpu_status == "POSSIBLE":
            print("* CPU: load/runqueue pressure is compatible with "
                  "overcommit, but not specific to it.")
        if memory_status in ("HOST RECLAIM", "RECENT RECLAIM"):
            print("* Memory: an inflated balloon proves hypervisor-directed "
                  "guest reclaim.")
        elif memory_status == "GUEST PRESSURE":
            print("* Memory: reclaim/swap/OOM data proves guest pressure only, "
                  "not host pressure.")
        if storage_busy:
            print("* Storage: aged/outstanding I/O is compatible with shared "
                  "datastore contention,")
            print("  but guest/device faults can produce the same snapshot.")
    if steal_enabled is False and is_virt:
        print("Confirm CPU with host CPU-ready/co-stop data; guest steal "
              "accounting is disabled.")

    if not details:
        print("\nUse -d with --overcommit to show the raw counters, per-vCPU "
              "clocks,")
        print("task rows, balloon structure, block requests, and matched log "
              "lines.")
        return

    # ------------------------------------------------------------------
    # Raw source data.  Keep this separate from the assessment so the normal
    # report stays compact while -d remains auditable.
    # ------------------------------------------------------------------
    print("\nRaw data (-d)")
    print("=============")

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
        print(exec_crash_command("sys -i"))
    except Exception:
        print("$ sys -i: <unavailable>")

    print("\n[CPU load and steal]")
    print("avenrun (raw, FSHIFT=11) = %s"
          % (str(avenrun_raw) if avenrun_raw is not None else "unavailable"))
    print("paravirt_steal_enabled = %s"
          % (str(steal_enabled) if steal_enabled is not None
             else "unavailable"))
    if steal_by_cpu:
        print("%4s %20s %20s %9s"
              % ("CPU", "CPUTIME_STEAL", "CPUTIME_TOTAL", "steal%"))
        for cpu in sorted(steal_by_cpu):
            st, tt = steal_by_cpu[cpu]
            print("%4d %20d %20d %8.3f%%"
                  % (cpu, st, tt, steal_pct_by_cpu.get(cpu, 0.0)))

    print("\n[Per-vCPU runqueue fields; clocks are raw nanoseconds]")
    print("%4s %5s %3s %16s %16s %16s %16s %9s %s"
          % ("CPU", "runq", "POL", "rq.clock", "clock_task",
             "exec_start", "last_arrival", "lag(s)",
             "current(pid/task)"))
    for r in rows:
        print("%4d %5d %3d %16d %16d %16d %16d %9.3f %s(%d/0x%x)"
              % (r["cpu"], r["nr_running"], r["policy"], r["clock"],
                 r["clock_task"], r["exec_start"], r["last_arrival"],
                 r["clock_lag"], r["curr"], r["pid"], r["task"]))
    print("sysctl scheduler slice = %.3f ms" % slice_ms)

    if context_rows:
        print("\n[Backtraces used to classify clock-lag/slice task mode]")
        for r in context_rows:
            mode, bt_raw = task_contexts.get(r["task"], ("?", ""))
            print("\n$ bt 0x%x  # CPU%d %s(%d), mode=%s"
                  % (r["task"], r["cpu"], r["curr"], r["pid"], mode))
            print(bt_raw if bt_raw else "<unavailable>")

    print("\n[Task-state rows]")
    print("total=%d running=%d uninterruptible=%d other=%d"
          % (task_states["total"], task_states["running"],
             task_states["uninterruptible"], task_states["other"]))
    print("%18s %8s %10s %s" % ("TASK", "PID", "STATE", "COMM"))
    for addr, pid, comm, state in (
            task_states["running_rows"]
            + task_states["uninterruptible_rows"]):
        print("0x%016x %8d 0x%08x %s" % (addr, pid, state, comm))

    print("\n[Memory symbols and VM events]")
    print("totalram_pages=%d total_swap_pages=%d nr_swap_pages=%d"
          % (memory["totalram_pages"], memory["swap_total_pages"],
             memory["swap_free_pages"]))
    for name in sorted(vm_events):
        print("%-28s %d" % (name, vm_events[name]))
    if balloon:
        print("\n$ %s" % balloon["raw_command"])
        try:
            print(exec_crash_command(balloon["raw_command"]))
        except Exception as e:
            print("<unavailable: %s>" % str(e))
    if memory["kmem_raw"]:
        print("\n$ kmem -i")
        print(memory["kmem_raw"])

    print("\n[SCSI host fields]")
    print("%-8s %8s %12s %12s %12s"
          % ("HOST", "devices", "outstanding", "blocked", "failed"))
    for name, ndev, busy, blocked, failed in scsi_hosts:
        print("%-8s %8d %12d %12d %12d"
              % (name, ndev, busy, blocked, failed))

    print("\n[Block request fields]")
    print("%18s %18s %-12s %s"
          % ("REQUEST", "QUEUE", "STATE", "age(s)"))
    for reqaddr, qaddr, state, age in request_rows:
        print("0x%016x 0x%016x %-12s %.6f"
              % (reqaddr, qaddr, state, age))

    print("\n[Matched kernel log lines]")
    for name in LOG_PATTERNS:
        lines = log_evidence[name]
        if not lines:
            continue
        print("\n%s (%d)" % (name, len(lines)))
        for line in lines:
            print(line)


def vminfo():
    op = OptionParser()
    op.add_option("-d", "--details", dest="show_details", default=0,
                  action="store_true",
                  help="Show details (with --overcommit, append raw source "
                       "data)")
    op.add_option("-c", "--context", dest="show_context", default=0,
                  action="store_true",
                  help="Show VM Context")
    op.add_option("-o", "--overcommit", dest="overcommit", default=0,
                  action="store_true",
                  help="Assess hypervisor CPU/memory/storage overcommit "
                       "evidence")

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
