"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function

from pykdump.API import *
from LinuxDump import percpu

import sys
from optparse import OptionParser


def  show_cpuid(options):
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
        print("<<< Physical CPU %3d >>>" % (phys_cpu))
        core_dict = phys_cpu_list[phys_cpu]

        for cpu in core_dict:
            cpuinfo_x86 = core_dict[cpu]
            print("\tCPU %3d, core %3d : 0x%x %s" %
                  (cpu, cpuinfo_x86.cpu_core_id,
                   cpuinfo_x86,
                   cpuinfo_x86.x86_model_id))


def cpufreq_policy_str(policy):
    return {
        0: "",
        1: "CPUFREQ_POLICY_POWERSAVE",
        2: "CPUFREQ_POLICY_PERFORMANCE",
    } [policy];

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
                print("\t%s" %
                      (exec_crash_command("cpudata.sample.freq -d 0x%x" %
                                          (cpudata))))
            except:
                pass

def cpuinfo():
    op = OptionParser()
    op.add_option("--cpufreq", dest="cpufreq", default=0,
                  action="store_true",
                  help="CPU frequency details")
    op.add_option("--cpuid", dest="cpuid", default=0,
                  action="store_true",
                  help="Show CPU's physical and core ID")

    (o, args) = op.parse_args()

    if (o.cpufreq):
        show_cpufreq()
        sys.exit(0)

    if (o.cpuid):
        show_cpuid(o)
        sys.exit(0)

    # default action
    show_cpufreq()

if ( __name__ == '__main__'):
    cpuinfo()
