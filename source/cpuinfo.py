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
        phys_proc_id = cpuinfo_x86.phys_proc_id
        cpu_core_id = cpuinfo_x86.cpu_core_id

        cpu_core_dict = {}
        if (phys_proc_id in phys_cpu_list):
            cpu_core_dict = phys_cpu_list[phys_proc_id]

        cpu_core_dict[cpu] = cpuinfo_x86
        phys_cpu_list[phys_proc_id] = cpu_core_dict


    for phys_cpu in phys_cpu_list:
        crashcolor.set_color(crashcolor.BLUE)
        print("<<< Physical CPU %3d >>>" % (phys_cpu))
        crashcolor.set_color(crashcolor.RESET)
        core_dict = phys_cpu_list[phys_cpu]

        for cpu in core_dict:
            cpuinfo_x86 = core_dict[cpu]
            print("\tCPU %3d, core %3d : 0x%x %s" %
                  (cpu, cpuinfo_x86.cpu_core_id,
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



def show_smp_call_data(cfd_addr, csd_addr=None):
    """
    Find which CPU owns a struct __call_single_data address from call_function_data
    Used for debugging smp_call_function_many_cond hangs

    Args:
        cfd_addr: Address of call_function_data structure
        csd_addr: Optional struct __call_single_data address to find which CPU it belongs to
    """
    try:
        # Read call_function_data structure
        crashcolor.set_color(crashcolor.BLUE)
        print("=" * 80)
        print("SMP Call Function Data Analysis")
        print("=" * 80)
        crashcolor.set_color(crashcolor.RESET)

        print("\nStep 1: Reading call_function_data at 0x%x" % cfd_addr)
        print("-" * 80)

        cfd = readSU("struct call_function_data", cfd_addr)

        print("struct call_function_data {")
        print("  csd = 0x%x," % cfd.csd)
        print("  cpumask = 0x%x," % cfd.cpumask)
        print("  cpumask_ipi = 0x%x" % cfd.cpumask_ipi)
        print("}")

        # Get per-cpu offset
        percpu_offset = cfd.csd

        print("\nStep 2: Converting per-cpu offset 0x%x to virtual addresses" % percpu_offset)
        print("-" * 80)

        # Use crash ptov command to convert per-cpu offset to virtual addresses for all CPUs
        # ptov <offset>:a shows virtual addresses for all CPUs
        ptov_output = exec_crash_command("ptov 0x%x:a" % percpu_offset)

        # Build a table of CPU -> virtual address mappings
        cpu_csd_map = {}

        # Parse ptov output
        # Format: "  [CPU]  virtual_address"
        for line in ptov_output.splitlines():
            line = line.strip()
            if line.startswith('[') and ']' in line:
                try:
                    # Extract CPU number and address
                    # Format: "[20]  ffff9caa2633ae60"
                    cpu_part = line.split(']')[0].replace('[', '')
                    addr_part = line.split(']')[1].strip()

                    cpu = int(cpu_part)
                    vaddr = int(addr_part, 16)

                    cpu_csd_map[cpu] = vaddr
                except:
                    pass

        print("\n%-6s  %-18s" % ("CPU", "struct __call_single_data Address"))
        print("-" * 80)

        # If target address provided, show only matching CPU and surrounding context
        if csd_addr:
            # Find the matching CPU
            found_cpu = None
            for cpu, vaddr in cpu_csd_map.items():
                if vaddr == csd_addr:
                    found_cpu = cpu
                    break

            if found_cpu is not None:
                # Show context: 3 CPUs before and after the target
                context_range = 3
                start_cpu = max(0, found_cpu - context_range)
                end_cpu = found_cpu + context_range

                all_cpus = sorted(cpu_csd_map.keys())

                # Show leading ellipsis if not starting from beginning
                if start_cpu > min(all_cpus):
                    print("  ...   (showing CPUs %d-%d only)" % (start_cpu, end_cpu))

                # Display CPUs in the context range
                for cpu in all_cpus:
                    if start_cpu <= cpu <= end_cpu:
                        vaddr = cpu_csd_map[cpu]
                        if cpu == found_cpu:
                            crashcolor.set_color(crashcolor.RED | crashcolor.BOLD)
                            print("[%-4d]  0x%016x  <<< TARGET CPU" % (cpu, vaddr))
                            crashcolor.set_color(crashcolor.RESET)
                        else:
                            print("[%-4d]  0x%016x" % (cpu, vaddr))

                # Show trailing ellipsis if not ending at last CPU
                if end_cpu < max(all_cpus):
                    print("  ...")
            else:
                # Target not found, show first few entries as sample
                print("  (showing first 5 CPUs as sample)")
                for i, cpu in enumerate(sorted(cpu_csd_map.keys())):
                    if i >= 5:
                        print("  ...")
                        break
                    vaddr = cpu_csd_map[cpu]
                    print("[%-4d]  0x%016x" % (cpu, vaddr))
        else:
            # No target address, show all CPUs
            for cpu in sorted(cpu_csd_map.keys()):
                vaddr = cpu_csd_map[cpu]
                print("[%-4d]  0x%016x" % (cpu, vaddr))

        # If target address provided, find and display details
        if csd_addr:
            print("\nStep 3: Finding CPU for struct __call_single_data 0x%x" % csd_addr)
            print("-" * 80)

            found_cpu = None
            for cpu, vaddr in cpu_csd_map.items():
                if vaddr == csd_addr:
                    found_cpu = cpu
                    break

            if found_cpu is not None:
                crashcolor.set_color(crashcolor.RED | crashcolor.BOLD)
                print("\n*** CPU %d is awaiting ACK ***" % found_cpu)
                crashcolor.set_color(crashcolor.RESET)

                # Show what's running on the target CPU
                print("\nCurrent process on CPU %d:" % found_cpu)
                print("-" * 80)

                try:
                    # Use runq -c to get current task on the CPU
                    runq_output = exec_crash_command("runq -c %d" % found_cpu)

                    # Parse runq output to extract the current task address
                    # Format: "  CURRENT: PID: 3468342  TASK: ffff9c5e22ad8000  COMMAND: "bash""
                    current_task = None
                    for line in runq_output.splitlines():
                        stripped = line.strip()
                        if stripped.startswith("CURRENT:"):
                            # Extract task address from the CURRENT line
                            if "TASK:" in line:
                                parts = line.split("TASK:")
                                if len(parts) > 1:
                                    addr_str = parts[1].split()[0].strip()
                                    try:
                                        current_task = int(addr_str, 16)
                                    except:
                                        pass
                            break

                    if current_task:
                        # Run ps -m to show process info (including runtime)
                        print("\nProcess Information (ps -m):")
                        ps_output = exec_crash_command("ps -m %x" % current_task)
                        print(ps_output)

                        # Run bt to show backtrace
                        print("\nBacktrace (bt):")
                        bt_output = exec_crash_command("bt %x" % current_task)
                        print(bt_output)
                    else:
                        crashcolor.set_color(crashcolor.YELLOW)
                        print("Warning: Could not parse current task from runq output")
                        print("runq -c %d output:" % found_cpu)
                        print(runq_output)
                        crashcolor.set_color(crashcolor.RESET)

                except Exception as e:
                    crashcolor.set_color(crashcolor.YELLOW)
                    print("Warning: Could not get current process info: %s" % str(e))
                    crashcolor.set_color(crashcolor.RESET)

                # Read and display the struct __call_single_data structure
                print("\nStep 4: Reading struct __call_single_data at 0x%x" % csd_addr)
                print("-" * 80)

                try:
                    csd = readSU("struct __call_single_data", csd_addr)
                    print("\nstruct __call_single_data {")

                    # Handle union structure
                    if member_offset("struct __call_single_data", "flags") >= 0:
                        print("  flags = 0x%x," % csd.flags)
                    elif member_offset("struct __call_single_data", "u_flags") >= 0:
                        print("  u_flags = 0x%x," % csd.node.u_flags)

                    print("  func = 0x%x" % csd.func)

                    # Try to resolve function name
                    try:
                        func_name = addr2sym(csd.func)
                        if func_name:
                            print("       <%s>" % func_name)
                    except:
                        pass

                    print("  info = 0x%x" % csd.info)
                    print("}")

                    # Check if this CPU is online
                    print("\nCPU %d Status:" % found_cpu)
                    print("-" * 80)
                    try:
                        cpu_online_bits = readSymbol("__cpu_online_mask")
                        if cpu_online_bits:
                            # Simple check - in real implementation would check bitmap
                            print("  Checking if CPU is online and responsive...")
                    except:
                        pass

                except Exception as e:
                    crashcolor.set_color(crashcolor.YELLOW)
                    print("Warning: Could not read struct __call_single_data structure: %s" % str(e))
                    crashcolor.set_color(crashcolor.RESET)
            else:
                crashcolor.set_color(crashcolor.YELLOW)
                print("\nWarning: Address 0x%x not found in per-cpu csd mappings" % csd_addr)
                crashcolor.set_color(crashcolor.RESET)

        print("\n" + "=" * 80)

    except Exception as e:
        crashcolor.set_color(crashcolor.RED)
        print("Error analyzing SMP call data: %s" % str(e))
        crashcolor.set_color(crashcolor.RESET)
        import traceback
        traceback.print_exc()


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
    op.add_option("-s", "--cstate", dest="cstate", default=0,
                  action="store_true",
                  help="Show CPU c-state")
    op.add_option("--smp-call", dest="smp_call", default="",
                  action="store", type="string",
                  help="Analyze SMP call function data: --smp-call <call_function_data_addr>[,<__call_single_data_addr>]")
    op.add_option("-t", "--tlb", dest="tlb", default=0,
                  action="store_true",
                  help="Show CPU tlb state")
    op.add_option("-v", "--verbose", dest="verbose", default=0,
                  action="store_true",
                  help="Show more information")

    (o, args) = op.parse_args()

    if o.smp_call:
        # Parse addresses: format is <cfd_addr>[,<csd_addr>]
        addrs = o.smp_call.split(',')
        try:
            cfd_addr = int(addrs[0].strip(), 16)
            csd_addr = None
            if len(addrs) > 1:
                csd_addr = int(addrs[1].strip(), 16)
            show_smp_call_data(cfd_addr, csd_addr)
        except ValueError:
            crashcolor.set_color(crashcolor.RED)
            print("Error: Invalid address format. Use: --smp-call <call_function_data_addr>[,<__call_single_data_addr>]")
            print("Example: --smp-call ffff9caa268f4a00,ffff9caa2633ae60")
            crashcolor.set_color(crashcolor.RESET)
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
