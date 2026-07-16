"""
 Written by Daniel Sungju Kwon
"""



from pykdump.API import *
from LinuxDump import percpu

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


def show_cpuidle_state_table(options):
    try:
        idx = 0
        cpu_state_name = {}
        try:
            cpuidle_driver = readSymbol("cpuidle_curr_driver")
            idx = 0
            print("CPU idle driver : %s" % (cpuidle_driver.name))
            if options.verbose:
                print(cpuidle_driver)
            for cpuidle_state in cpuidle_driver.states:
                cpu_state_name[idx] = cpuidle_state
                if options.verbose:
                    print(cpuidle_state)
                idx = idx + 1
        except:
            idx = 0
            addr = Addr(readSymbol("cpuidle_state_table"))
            cpuidle_state_table = readSUArray("struct cpuidle_state", addr, 8)
            for cpuidle_state in cpuidle_state_table:
                cpu_state_name[idx] = cpuidle_state
                idx = idx + 1

        cpuidle_devices = percpu.get_cpu_var("cpuidle_devices")
        cpu_idx = 0
        for addr in cpuidle_devices:
            cpuidle_device = readSU("struct cpuidle_device", addr)
            print("CPU %d:" % (cpu_idx))
            if options.verbose:
                print(cpuidle_device)
            state_idx = 0
            for state_usage in cpuidle_device.states_usage:
                if state_usage.disable != 0:
                    state_name = ""
                    try:
                        state_name = cpu_state_name[state_idx].name
                    except:
                        pass
                    print("\t%10s : %d" % (state_name, state_usage.usage))
                state_idx = state_idx + 1
                if state_idx >= idx:
                    break
            cpu_idx = cpu_idx + 1
    except Exception as e:
        print("Error : ", e)
        pass

def show_cstate(options):
    if symbol_exists("cpuidle_state_table"):
        show_cpuidle_state_table(options)
    else:
        print("Cannot tell you")


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
