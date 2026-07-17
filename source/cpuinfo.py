"""
 Written by Daniel Sungju Kwon
"""



from pykdump.API import *
from LinuxDump import percpu
from LinuxDump import Tasks

import sys
from optparse import OptionParser

import crashcolor


def  show_cpuid_x86(options):
    phys_cpu_list = {}

    cpuinfo_addrs = percpu.get_cpu_var("cpu_info")
    for cpu, addr in enumerate(cpuinfo_addrs):
        cpuinfo_x86 = readSU("struct cpuinfo_x86", addr)

        try:
            phys_proc_id = cpuinfo_x86.topo.pkg_id
        except:
            phys_proc_id = cpuinfo_x86.phys_proc_id

        phys_cpu_list.setdefault(phys_proc_id, {})[cpu] = cpuinfo_x86

    for phys_cpu, core_dict in phys_cpu_list.items():
        crashcolor.set_color(crashcolor.BLUE)
        print("<<< Physical CPU %3d >>>" % (phys_cpu))
        crashcolor.set_color(crashcolor.RESET)

        for cpu, cpuinfo_x86 in core_dict.items():
            try:
                cpu_core_id = cpuinfo_x86.topo.core_id
            except:
                cpu_core_id = cpuinfo_x86.cpu_core_id

            print("\tCPU %3d, core %3d : 0x%x %s" %
                  (cpu, cpu_core_id,
                   cpuinfo_x86,
                   cpuinfo_x86.x86_model_id))

    print("\n\tFor details, run 'cpuinfo_x86  <address>'")


def show_cpuid(options):
    if (sys_info.machine in ("x86_64", "i386", "i686", "athlon")):
        show_cpuid_x86(options)


def cpufreq_policy_str(policy):
    try:
        return {
            0: "",
            1: "CPUFREQ_POLICY_POWERSAVE",
            2: "CPUFREQ_POLICY_PERFORMANCE",
        } [policy];
    except:
        return ""


def show_cpufreq():
    if (not sys_info.machine in ("x86_64", "i386", "i686", "athlon")):
        print("Some information are only available on x86 architecutres")

    addrs = percpu.get_cpu_var("cpufreq_cpu_data")
    try:
        all_cpu_data = readSymbol("all_cpu_data")
    except:
        all_cpu_data = None
        pass

    for cpu, addr in enumerate(addrs):
        cpufreq_addr = readULong(addr)
        cpufreq_cpu_data = readSU('struct cpufreq_policy', cpufreq_addr)
        if (cpufreq_cpu_data == None or cpufreq_cpu_data == 0):
            print("struct cpufreq_policy = 0x%x" % (cpufreq_cpu_data))
            continue

        cur_cpu_khz = cpufreq_cpu_data.cur
        if (cur_cpu_khz == 0):
            cur_cpu_khz = readSymbol("cpu_khz")

        print("CPU %3d (0x%x) min = %d, max = %d, cur = %d" %
                (cpu, cpufreq_addr, cpufreq_cpu_data.min,
                 cpufreq_cpu_data.max, cur_cpu_khz))
        if (all_cpu_data != None and all_cpu_data != 0):
            cpudata = all_cpu_data[cpu]
            print("\tcpudata = 0x%x, current_pstate = %d, turbo_pstate = %d,\n"
                  "\tmin_pstate = %d, max_pstate = %d, policy = %s" %
                     (cpudata, cpudata.pstate.current_pstate,
                      cpudata.pstate.turbo_pstate,
                      cpudata.pstate.min_pstate,
                      cpudata.pstate.max_pstate,
                     cpufreq_policy_str(cpufreq_cpu_data.policy)))
            try:
                if (member_offset('struct cpudata', 'sample') > -1):
                    if (member_offset('struct sample', 'freq') > -1):
                        print("\t%s" % (exec_crash_command("cpudata.sample.freq -d 0x%x" %
                                            (cpudata))))
                    if (member_offset('struct sample', 'time') > -1):
                        duration_ns =  cpudata.sample.time-cpudata.last_sample_time
                        print("\tupdated %d ns (%d sec) ago" %\
                              (duration_ns, duration_ns / 1000000000))
            except:
                pass



def get_rq_behind():
    """
    Return (behind_by_cpu, watchdog_thresh, softlockup_thresh).

    behind_by_cpu maps cpu -> seconds its runqueue clock is behind the most
    up-to-date runqueue in the system.  This is the same 'N sec behind' signal
    the 'lockup' command reports and tells us which CPUs failed to make
    scheduling progress (a soft lockup pre-condition).
    """
    behind_by_cpu = {}
    watchdog_thresh = -1
    softlockup_thresh = -1
    try:
        rqlist = Tasks.getRunQueues()
        now = max(rq.Timestamp for rq in rqlist)
        for rq in rqlist:
            behind_by_cpu[rq.cpu] = (now - rq.Timestamp) / 1000000000.0
    except Exception:
        return behind_by_cpu, watchdog_thresh, softlockup_thresh

    try:
        watchdog_thresh = readSymbol("watchdog_thresh")
        softlockup_thresh = watchdog_thresh * 2
    except Exception:
        try:
            softlockup_thresh = readSymbol("softlockup_thresh")
            watchdog_thresh = softlockup_thresh // 2
        except Exception:
            watchdog_thresh = 10
            softlockup_thresh = 20

    return behind_by_cpu, watchdog_thresh, softlockup_thresh


def get_base_khz():
    """Base (TSC/MPERF reference) frequency in kHz."""
    for sym in ("cpu_khz", "tsc_khz"):
        try:
            val = readSymbol(sym)
            if val:
                return int(val)
        except Exception:
            continue
    return 0


def get_max_khz_by_cpu():
    """
    Per-CPU maximum frequency (kHz) taken from the cpufreq policy when
    available.  Falls back to an empty dict so callers can use the base freq.
    """
    max_khz = {}
    try:
        addrs = percpu.get_cpu_var("cpufreq_cpu_data")
    except Exception:
        return max_khz

    for cpu, addr in enumerate(addrs):
        try:
            policy_addr = readULong(addr)
            if not policy_addr:
                continue
            policy = readSU("struct cpufreq_policy", policy_addr)
            cur_max = 0
            if member_offset("struct cpufreq_policy", "cpuinfo") >= 0:
                try:
                    cur_max = policy.cpuinfo.max_freq
                except Exception:
                    cur_max = 0
            if not cur_max:
                cur_max = policy.max
            if cur_max:
                max_khz[cpu] = int(cur_max)
        except Exception:
            continue
    return max_khz


def get_jiffies_age_sec(last_update_jiffies):
    """Convert a jiffies timestamp into 'seconds ago' using HZ and jiffies."""
    try:
        hz = sys_info.HZ
    except Exception:
        hz = 1000
    if not hz:
        hz = 1000
    try:
        now = readSymbol("jiffies")
    except Exception:
        return -1.0
    # jiffies can be exported as jiffies_64; normalise to a plain int
    try:
        now = int(now)
    except Exception:
        return -1.0
    delta = now - int(last_update_jiffies)
    if delta < 0:
        return -1.0
    return delta / float(hz)


def get_measured_khz(cpu, base_khz):
    """
    Return (khz, age_sec) for a CPU using the kernel's own APERF/MPERF samples.
    This is driver-agnostic: it is updated from scale_freq_tick() on every
    scheduler tick regardless of the active cpufreq driver.

    Returns (None, -1) when no APERF/MPERF sample is available.
    """
    # RHEL7/8-era: per_cpu(samples) is 'struct aperfmperf_sample' whose .khz
    # field already holds the last measured effective frequency.  We do not try
    # to derive a monotonic 'now' from the dump to age the .time field — that is
    # fragile — so age is reported as n/a for this path (the .khz value is the
    # last tick's sample, which is what matters during a soft lockup).
    if (symbol_exists("samples")
            and member_offset("struct aperfmperf_sample", "khz") >= 0):
        try:
            addrs = percpu.get_cpu_var("samples")
            s = readSU("struct aperfmperf_sample", addrs[cpu])
            khz = int(s.khz)
            if khz:
                return khz, -1.0
        except Exception:
            pass

    # 5.x+: per_cpu(cpu_samples) is 'struct aperfmperf' storing the last tick's
    # aperf/mperf deltas (.acnt/.mcnt) plus a jiffies .last_update.
    if symbol_exists("cpu_samples") and base_khz:
        try:
            addrs = percpu.get_cpu_var("cpu_samples")
            s = readSU("struct aperfmperf", addrs[cpu])
            acnt = int(s.acnt)
            mcnt = int(s.mcnt)
            if mcnt:
                khz = base_khz * acnt // mcnt
                age = -1.0
                if member_offset("struct aperfmperf", "last_update") >= 0:
                    age = get_jiffies_age_sec(s.last_update)
                return khz, age
        except Exception:
            pass

    # Last resort: per_cpu(arch_freq_scale) is a SCHED_CAPACITY_SCALE-relative
    # ratio (1024 == max).  Needs a max frequency to turn into kHz; handled by
    # the caller when it multiplies by max_khz.
    if symbol_exists("arch_freq_scale"):
        try:
            addrs = percpu.get_cpu_var("arch_freq_scale")
            scale = int(readULong(addrs[cpu]))
            # Encode as a negative sentinel so the caller knows this is a scale
            # (relative to 1024), not an absolute kHz value.
            return -scale, -1.0
        except Exception:
            pass

    return None, -1.0


def get_throttle_count(cpu):
    """
    Return (core_count, package_count) thermal-throttle counts for a CPU, or
    (None, None) when the thermal throttle state is not present.  Non-zero
    counts are direct evidence the hardware capped this CPU's frequency.
    """
    if not symbol_exists("thermal_state"):
        return None, None
    try:
        addrs = percpu.get_cpu_var("thermal_state")
        ts = readSU("struct thermal_state", addrs[cpu])
        core = pkg = None
        if member_offset("struct thermal_state", "core_throttle") >= 0:
            try:
                core = int(ts.core_throttle.count)
            except Exception:
                core = None
        if member_offset("struct thermal_state", "package_throttle") >= 0:
            try:
                pkg = int(ts.package_throttle.count)
            except Exception:
                pkg = None
        return core, pkg
    except Exception:
        return None, None


def get_pstate_by_cpu():
    """Per-CPU (current_pstate, max_pstate) from intel_pstate when loaded."""
    pstate = {}
    try:
        all_cpu_data = readSymbol("all_cpu_data")
    except Exception:
        return pstate
    if not all_cpu_data:
        return pstate
    total = sys_info.CPUS
    for cpu in range(total):
        try:
            cpudata = all_cpu_data[cpu]
            if not cpudata:
                continue
            pstate[cpu] = (int(cpudata.pstate.current_pstate),
                           int(cpudata.pstate.max_pstate))
        except Exception:
            continue
    return pstate


# A CPU running below this fraction of its maximum is treated as "slow".
SLOW_FRACTION = 0.60
# APERF/MPERF samples older than this many seconds are treated as not
# representative of the lockup window.
STALE_SAMPLE_SEC = 60.0


def show_cpu_speed(options):
    """
    Driver-agnostic effective CPU speed, aimed at soft-lockup analysis.

    For every online CPU it prints the measured effective frequency (from the
    kernel's APERF/MPERF samples), how it compares to the CPU's maximum, the
    sample age, thermal-throttle counts, intel_pstate cur/max p-state, and how
    far the CPU's runqueue is 'behind'.  A CPU that is BOTH running well below
    its maximum AND behind on scheduling is flagged as a soft-lockup SUSPECT.
    """
    if not sys_info.machine in ("x86_64", "i386", "i686", "athlon"):
        print("Effective-speed analysis is only available on x86 architectures")
        return

    base_khz = get_base_khz()
    max_khz_by_cpu = get_max_khz_by_cpu()
    pstate_by_cpu = get_pstate_by_cpu()
    behind_by_cpu, watchdog_thresh, softlockup_thresh = get_rq_behind()

    online_cpus = get_cpumask_bits("__cpu_online_mask")
    if not online_cpus:
        online_cpus = get_cpumask_bits("cpu_online_map")
    if not online_cpus:
        online_cpus = set(range(sys_info.CPUS))

    crashcolor.set_color(crashcolor.LIGHTCYAN)
    print("Base frequency = %s MHz, kernel.watchdog_thresh = %d "
          "(soft lockup at %d sec)" %
          (("%.0f" % (base_khz / 1000.0)) if base_khz else "n/a",
           watchdog_thresh, softlockup_thresh))
    print("Effective frequency is measured from APERF/MPERF "
          "(driver-agnostic, updated on each scheduler tick)\n")
    crashcolor.set_color(crashcolor.RESET)

    hdr = "%4s %10s %10s %6s %9s %9s %8s %s" % (
        "CPU", "eff.MHz", "max.MHz", "%max", "sample", "behind", "throttle",
        "note")
    print(hdr)
    print("-" * len(hdr))

    any_suspect = False
    for cpu in sorted(online_cpus):
        max_khz = max_khz_by_cpu.get(cpu, base_khz)
        khz, age = get_measured_khz(cpu, base_khz)

        # arch_freq_scale fallback comes back as a negative "scale/1024" value.
        if khz is not None and khz < 0 and max_khz:
            khz = max_khz * (-khz) // 1024

        if khz is None or khz <= 0:
            eff_mhz_str = "n/a"
            pct = None
        else:
            eff_mhz_str = "%.0f" % (khz / 1000.0)
            pct = (100.0 * khz / max_khz) if max_khz else None

        max_mhz_str = ("%.0f" % (max_khz / 1000.0)) if max_khz else "n/a"
        pct_str = ("%.0f%%" % pct) if pct is not None else "n/a"
        if age is not None and age >= 0:
            age_str = "%.1fs" % age
        else:
            age_str = "n/a"

        behind = behind_by_cpu.get(cpu)
        behind_str = ("%.1fs" % behind) if behind is not None else "n/a"

        core_thr, pkg_thr = get_throttle_count(cpu)
        if core_thr is None and pkg_thr is None:
            thr_str = "n/a"
            throttled = False
        else:
            thr_str = "%d/%d" % (core_thr or 0, pkg_thr or 0)
            throttled = bool((core_thr or 0) or (pkg_thr or 0))

        notes = []
        stale = (age is not None and age >= 0 and age > STALE_SAMPLE_SEC)
        slow = (pct is not None and pct < SLOW_FRACTION * 100)
        is_behind = (behind is not None and watchdog_thresh > 0
                     and behind >= watchdog_thresh)

        if pstate_by_cpu.get(cpu):
            cur_ps, max_ps = pstate_by_cpu[cpu]
            notes.append("pstate %d/%d" % (cur_ps, max_ps))
        if throttled:
            notes.append("THROTTLED")
        if stale:
            notes.append("sample stale (>%ds; not representative)"
                         % int(STALE_SAMPLE_SEC))

        color = crashcolor.RESET
        # SUSPECT: measurably slow, the sample is fresh enough to trust, and
        # the CPU is behind on scheduling -> slowness plausibly caused a stall.
        if slow and not stale and is_behind:
            notes.insert(0, "SUSPECT: slow while behind")
            color = crashcolor.RED
            any_suspect = True
        elif throttled and slow:
            color = crashcolor.LIGHTRED
        elif slow or throttled:
            color = crashcolor.YELLOW

        crashcolor.set_color(color)
        print("%4d %10s %10s %6s %9s %9s %8s %s" %
              (cpu, eff_mhz_str, max_mhz_str, pct_str, age_str, behind_str,
               thr_str, ", ".join(notes)))
        crashcolor.set_color(crashcolor.RESET)

    print("")
    if any_suspect:
        crashcolor.set_color(crashcolor.RED)
        print("One or more CPUs were running well below their maximum "
              "frequency while also")
        print("falling behind on scheduling. A sustained low frequency can "
              "stretch a normal")
        print("operation past the %d sec soft-lockup threshold. Cross-check "
              "with 'lockup' and" % softlockup_thresh)
        print("the backtrace of the stuck task ('bt' on the CPU's current "
              "task).")
        crashcolor.set_color(crashcolor.RESET)
    else:
        print("No CPU is both slow and behind. If a soft lockup occurred, the "
              "cause is more")
        print("likely software (spin loops, lock contention, IRQ storms) than "
              "CPU frequency;")
        print("use 'lockup' and the stuck task's backtrace to investigate.")

    if base_khz == 0:
        print("\nNOTE: base frequency (cpu_khz/tsc_khz) was unavailable; "
              "percentages may be approximate.")


TLBSTATE_OK=1
TLBSTATE_LAZY=2

def tlb_str(state):
    if state == TLBSTATE_OK:
        return "TLBSTATE_OK"
    elif state == TLBSTATE_LAZY:
        return "TLBSTATE_LAZY"

    return ""


def show_tlb(options):
    cpuinfo_addrs = percpu.get_cpu_var("cpu_tlbstate")
    for cpu, addr in enumerate(cpuinfo_addrs):
        tlb_state = readSU("struct tlb_state", addr)
        task = 0
        if member_offset("struct tlb_state", "active_mm") >= 0:
            active_mm = tlb_state.active_mm
        elif member_offset("struct tlb_state", "loaded_mm") >= 0:
            active_mm = tlb_state.loaded_mm
        else:
            active_mm = 0

        if active_mm != 0:
            #active_mm = readSU("struct mm_struct", tlb_state.active_mm)
            task = active_mm.owner

        if member_offset("struct tlb_state", "state") >= 0:
            is_lazy = tlb_state.state
        elif member_offset("struct tlb_state", "is_lazy") >= 0:
            is_lazy = TLBSTATE_LAZY if tlb_state.is_lazy else TLBSTATE_OK
        else:
            is_lazy = TLBSTATE_OK

        if is_lazy == TLBSTATE_LAZY:
            crashcolor.set_color(crashcolor.BLUE)
        else:
            crashcolor.set_color(crashcolor.LIGHTGREEN)

        if task != 0:
            task_name = task.comm
        else:
            task_name = ""

        print("CPU %3d : state = %d [%-13s], active_mm = 0x%x (%s)" %
              (cpu, is_lazy, tlb_str(is_lazy), active_mm, task_name))
        crashcolor.set_color(crashcolor.RESET)


def show_cpuidle_driver(options):
    if not symbol_exists("cpuidle_curr_driver"):
        return
    cpuidle_driver = readSymbol("cpuidle_curr_driver")
    if cpuidle_driver == 0 or cpuidle_driver == None:
        print("No cpuidle_driver registered")
        return
    print("driver: %s (struct cpuidle_driver 0x%x)" %
          (cpuidle_driver.name, cpuidle_driver))
    print("\n%-8s : %-37s %s" % ("state", "enter", "enter_dead"))
    print("=" * 76)
    for state in cpuidle_driver.states:
        if state.name == "":
            continue
        enter = enter_dead = "<nop>"
        if state.enter != 0:
            enter = addr2sym(state.enter)
        if state.enter_dead != 0:
            enter_dead = addr2sym(state.enter_dead)

        print("%-8s : 0x%x = %-15s  0x%x = %-15s" %
              (state.name, state.enter, enter, state.enter_dead, enter_dead))
        print("\tdesc: %s, exit_latency: %d, power_usage: %d" %
              (state.desc, state.exit_latency, state.power_usage))


cpu_capability_list = {
    (0*32+ 9) : "X86_FEATURE_APIC",
    (0*32+22) : "X86_FEATURE_ACPI",
    (0*32+23) : "X86_FEATURE_MMX",
    (4*32+ 3) : "X86_FEATURE_MWAIT",
    (7*32+ 0) : "X86_FEATURE_RING3MWAIT",
    (7*32+ 2) : "X86_FEATURE_CPB",
    (7*32+ 3) : "X86_FEATURE_EPB",
    (7*32+ 8) : "X86_FEATURE_HW_PSTATE",
    (7*32+22) : "X86_FEATURE_USE_IBPB",
    (7*32+25) : "X86_FEATURE_IBRS",
    (7*32+26) : "X86_FEATURE_IBPB",
    (7*32+27) : "X86_FEATURE_STIBP",
    (7*32+30) : "X86_FEATURE_IBRS_ENHANCED",
    (18*32+31) : "X86_FEATURE_SPEC_CTRL_SSBD",
}

def show_cpu_capability(options):
    boot_cpu_data = readSymbol("boot_cpu_data")
    for cap_idx, cap_str in cpu_capability_list.items():
        idx = int(cap_idx // 32)
        bit = (1 << (cap_idx % 32))
        addr = boot_cpu_data.x86_capability[idx]
        if (addr & bit) != 0:
            enabled = "enabled"
            crashcolor.set_color(crashcolor.LIGHTCYAN)
        else:
            enabled = "not enabled"
            crashcolor.set_color(crashcolor.RED)
        print("%s %s" % (cap_str, enabled))
        crashcolor.set_color(crashcolor.RESET)


def _fmt_us(us):
    """Format microseconds as a human-readable string."""
    if us < 0:
        return "n/a"
    if us >= 1000000:
        return "%.1fs" % (us / 1000000.0)
    if us >= 1000:
        return "%.1fms" % (us / 1000.0)
    return "%dus" % us


def show_cpuidle_state_table(options):
    try:
        # ------------------------------------------------------------------
        # 1. Collect state definitions — try multiple symbol/access paths
        # ------------------------------------------------------------------
        state_defs = []
        driver_name = "unknown"
        tried = []

        # Path A: cpuidle_curr_driver (RHEL6-8) or cpuidle_driver (some 5.x)
        for sym in ("cpuidle_curr_driver", "cpuidle_driver"):
            tried.append(sym)
            if not symbol_exists(sym):
                continue
            try:
                drv = readSymbol(sym)
                if drv == 0 or drv is None:
                    continue
                driver_name = str(drv.name)
                for s in drv.states:
                    if s.name == "":
                        break   # states are contiguous; empty name = end
                    state_defs.append(s)
                if state_defs:
                    break
            except Exception as e:
                if options.verbose:
                    print("  [%s failed: %s]" % (sym, e))

        # Path B: static cpuidle_state_table (older kernels)
        if not state_defs:
            tried.append("cpuidle_state_table")
            try:
                tbl_ptr = readSymbol("cpuidle_state_table")
                if tbl_ptr == 0 or tbl_ptr is None:
                    if options.verbose:
                        print("  [cpuidle_state_table is NULL — no cpuidle driver active]")
                else:
                    addr = Addr(tbl_ptr)
                    for s in readSUArray("struct cpuidle_state", addr, 8):
                        if s.name == "":
                            break
                        state_defs.append(s)
            except Exception as e:
                if options.verbose:
                    print("  [cpuidle_state_table failed: %s]" % e)

        num_states = len(state_defs)
        if num_states == 0:
            # Check for haltpoll — the typical VM cpuidle driver
            haltpoll_note = ""
            if symbol_exists("haltpoll_driver") or symbol_exists("halt_poll_ns"):
                haltpoll_note = "\n  haltpoll cpuidle driver detected (typical for KVM guests)."
            print("No hardware C-state definitions found.")
            print("  This is expected on virtual machines — guests usually do not use")
            print("  hardware C-states. The hypervisor manages CPU power on their behalf.")
            if haltpoll_note:
                print(haltpoll_note)
            if options.verbose:
                print("  (searched: %s)" % ", ".join(tried))
            return

        # ------------------------------------------------------------------
        # 2. Print state definition table
        # ------------------------------------------------------------------
        crashcolor.set_color(crashcolor.LIGHTCYAN)
        print("CPU Idle Driver : %s\n" % driver_name)
        crashcolor.set_color(crashcolor.RESET)

        hdr = "%-10s %-35s %14s %14s %10s" % (
            "State", "Description", "Exit Lat.(us)", "Target Res.", "Power(mW)")
        print(hdr)
        print("-" * len(hdr))
        for s in state_defs:
            name = str(s.name)
            desc = str(s.desc)[:35]
            try:
                exit_lat = int(s.exit_latency)
            except Exception:
                exit_lat = -1
            try:
                target_res = int(s.target_residency)
            except Exception:
                target_res = -1
            try:
                power = int(s.power_usage)
            except Exception:
                power = -1

            lat_str = _fmt_us(exit_lat) if exit_lat >= 0 else "n/a"
            res_str = _fmt_us(target_res) if target_res >= 0 else "n/a"
            pow_str = "%d" % power if power >= 0 else "n/a"

            # Highlight high-latency states
            if exit_lat > 100:
                crashcolor.set_color(crashcolor.YELLOW)
            print("%-10s %-35s %14s %14s %10s" % (name, desc, lat_str, res_str, pow_str))
            crashcolor.set_color(crashcolor.RESET)

        # ------------------------------------------------------------------
        # 3. Collect per-CPU usage data
        # ------------------------------------------------------------------
        print("")
        cpuidle_devices = percpu.get_cpu_var("cpuidle_devices")
        cpu_data = []   # list of (cpu_idx, [(usage, time_us, disabled), ...])

        for dev_addr in cpuidle_devices:
            try:
                dev = readSU("struct cpuidle_device", dev_addr)
                states_usage = []
                for i, su in enumerate(dev.states_usage):
                    if i >= num_states:
                        break
                    try:
                        usage = int(su.usage)
                    except Exception:
                        usage = 0
                    try:
                        time_us = int(su.time)
                    except Exception:
                        time_us = -1
                    try:
                        disabled = int(su.disable) != 0
                    except Exception:
                        disabled = False
                    states_usage.append((usage, time_us, disabled))
                cpu_data.append(states_usage)
            except Exception:
                cpu_data.append([])

        num_cpus = len(cpu_data)
        if num_cpus == 0:
            return

        # ------------------------------------------------------------------
        # 4. Per-CPU usage table  (state × CPU)
        # ------------------------------------------------------------------
        COL_W = max(14, 8 + 1)   # width per CPU column
        state_col_w = 10

        # Header row
        header = "%-*s" % (state_col_w, "State")
        for cpu_idx in range(num_cpus):
            header += " %*s" % (COL_W, "CPU%d" % cpu_idx)
        crashcolor.set_color(crashcolor.LIGHTCYAN)
        print("Per-CPU C-State Usage  (count / time in state):")
        crashcolor.set_color(crashcolor.RESET)
        print(header)
        print("-" * len(header))

        for s_idx, s in enumerate(state_defs):
            name = str(s.name)
            row = "%-*s" % (state_col_w, name)
            for cpu_idx, states_usage in enumerate(cpu_data):
                if s_idx < len(states_usage):
                    usage, time_us, disabled = states_usage[s_idx]
                    if disabled:
                        cell = "disabled"
                    elif time_us >= 0:
                        cell = "%d/%s" % (usage, _fmt_us(time_us))
                    else:
                        cell = "%d" % usage
                else:
                    cell = "-"
                row += " %*s" % (COL_W, cell)

            # Highlight row if any CPU has non-trivial usage
            total_usage = sum(
                states_usage[s_idx][0]
                for states_usage in cpu_data
                if s_idx < len(states_usage)
            )
            if total_usage > 0:
                crashcolor.set_color(crashcolor.LIGHTGREEN)
            print(row)
            crashcolor.set_color(crashcolor.RESET)

        print("")

    except Exception as e:
        print("Error: %s" % e)


def show_cstate(options):
    show_cpuidle_state_table(options)


def get_cpumask_bits(mask_symbol):
    """Return a set of CPU numbers that are set in the given cpumask symbol."""
    cpu_set = set()
    try:
        cpumask = readSymbol(mask_symbol)
        bits = cpumask.bits
        total = sys_info.CPUS
        bits_per_long = 64 if sys_info.pointersize == 8 else 32
        for cpu in range(total):
            word_idx = cpu // bits_per_long
            bit_idx = cpu % bits_per_long
            if (bits[word_idx] >> bit_idx) & 1:
                cpu_set.add(cpu)
    except Exception as e:
        pass
    return cpu_set


def show_online_cpus(options):
    total = sys_info.CPUS

    # Print raw data section
    crashcolor.set_color(crashcolor.YELLOW)
    print("=" * 76)
    print("RAW DATA (for manual verification)")
    print("=" * 76)
    crashcolor.set_color(crashcolor.RESET)

    print("sys_info.CPUS: %d" % total)
    print("sys_info.pointersize: %d" % sys_info.pointersize)
    bits_per_long = 64 if sys_info.pointersize == 8 else 32
    print("bits_per_long: %d" % bits_per_long)

    # Show possible mask raw data
    possible_sym = None
    for sym in ("__cpu_possible_mask", "cpu_possible_map"):
        if symbol_exists(sym):
            possible_sym = sym
            break

    if possible_sym:
        print("\nPossible CPUs symbol: %s" % possible_sym)
        try:
            cpumask = readSymbol(possible_sym)
            print("  cpumask address: 0x%x" % cpumask)
            # Find the last non-zero element
            bits_list = list(cpumask.bits)
            last_nonzero = -1
            for i in range(len(bits_list) - 1, -1, -1):
                if bits_list[i] != 0:
                    last_nonzero = i
                    break
            # Show bits array in hex, truncated
            if last_nonzero >= 0:
                truncated_bits = ["0x%x" % b for b in bits_list[:last_nonzero + 1]]
                if last_nonzero + 1 < len(bits_list):
                    truncated_bits.append("...")
                print("  cpumask.bits: [%s]" % ", ".join(truncated_bits))
            else:
                print("  cpumask.bits: [0x0, ...]")
            # Show non-zero entries
            for i, val in enumerate(cpumask.bits):
                if val != 0:
                    print("    bits[%d] = 0x%x" % (i, val))
        except Exception as e:
            print("  Error reading: %s" % str(e))

    # Show online mask raw data
    online_sym = None
    for sym in ("__cpu_online_mask", "cpu_online_map"):
        if symbol_exists(sym):
            online_sym = sym
            break

    if online_sym:
        print("\nOnline CPUs symbol: %s" % online_sym)
        try:
            cpumask = readSymbol(online_sym)
            print("  cpumask address: 0x%x" % cpumask)
            # Find the last non-zero element
            bits_list = list(cpumask.bits)
            last_nonzero = -1
            for i in range(len(bits_list) - 1, -1, -1):
                if bits_list[i] != 0:
                    last_nonzero = i
                    break
            # Show bits array in hex, truncated
            if last_nonzero >= 0:
                truncated_bits = ["0x%x" % b for b in bits_list[:last_nonzero + 1]]
                if last_nonzero + 1 < len(bits_list):
                    truncated_bits.append("...")
                print("  cpumask.bits: [%s]" % ", ".join(truncated_bits))
            else:
                print("  cpumask.bits: [0x0, ...]")
            # Show non-zero entries
            for i, val in enumerate(cpumask.bits):
                if val != 0:
                    print("    bits[%d] = 0x%x" % (i, val))
        except Exception as e:
            print("  Error reading: %s" % str(e))

    crashcolor.set_color(crashcolor.YELLOW)
    print("\n" + "=" * 76)
    print("FORMATTED OUTPUT")
    print("=" * 76)
    crashcolor.set_color(crashcolor.RESET)

    # Determine possible CPUs
    possible_cpus = set(range(total))
    for sym in ("__cpu_possible_mask", "cpu_possible_map"):
        if symbol_exists(sym):
            possible_cpus = get_cpumask_bits(sym)
            break

    # Determine online CPUs
    online_cpus = set()
    for sym in ("__cpu_online_mask", "cpu_online_map"):
        if symbol_exists(sym):
            online_cpus = get_cpumask_bits(sym)
            break

    offline_cpus = possible_cpus - online_cpus

    crashcolor.set_color(crashcolor.LIGHTGREEN)
    print("Online  CPUs (%d): %s" % (
        len(online_cpus),
        ", ".join(str(c) for c in sorted(online_cpus)) if online_cpus else "(none)"))
    crashcolor.set_color(crashcolor.RESET)

    crashcolor.set_color(crashcolor.RED)
    print("Offline CPUs (%d): %s" % (
        len(offline_cpus),
        ", ".join(str(c) for c in sorted(offline_cpus)) if offline_cpus else "(none)"))
    crashcolor.set_color(crashcolor.RESET)

    print("\nTotal possible CPUs: %d" % len(possible_cpus))


def cpuinfo():
    op = OptionParser()
    op.add_option("-c", "--capability", dest="capability", default=0,
                  action="store_true",
                  help="Show CPU capability")
    op.add_option("-d", "--driver", dest="driver", default=0,
                  action="store_true",
                  help="Show CPU idle driver")
    op.add_option("-f", "--cpufreq", dest="cpufreq", default=0,
                  action="store_true",
                  help="CPU frequency details")
    op.add_option("-i", "--cpuid", dest="cpuid", default=0,
                  action="store_true",
                  help="Show CPU's physical and core ID")
    op.add_option("-o", "--online", dest="online", default=0,
                  action="store_true",
                  help="Show online/offline CPUs")
    op.add_option("-s", "--cstate", dest="cstate", default=0,
                  action="store_true",
                  help="Show CPU c-state")
    op.add_option("--speed", dest="speed", default=0,
                  action="store_true",
                  help="Show driver-agnostic effective CPU speed "
                       "(APERF/MPERF) for soft-lockup analysis")
    op.add_option("-t", "--tlb", dest="tlb", default=0,
                  action="store_true",
                  help="Show CPU tlb state")
    op.add_option("-v", "--verbose", dest="verbose", default=0,
                  action="store_true",
                  help="Show more information")

    (o, args) = op.parse_args()

    if (o.online):
        show_online_cpus(o)
        sys.exit(0)

    if (o.cpufreq):
        show_cpufreq()
        sys.exit(0)

    if (o.speed):
        show_cpu_speed(o)
        sys.exit(0)

    if (o.cpuid):
        show_cpuid(o)
        sys.exit(0)


    if (o.tlb):
        show_tlb(o)
        sys.exit(0)

    if (o.driver):
        show_cpuidle_driver(o)
        sys.exit(0)

    if (o.capability):
        show_cpu_capability(o)
        sys.exit(0)

    if (o.cstate):
        show_cstate(o)
        sys.exit(0)

    # default action
    show_cpuid(o)

if ( __name__ == '__main__'):
    cpuinfo()
