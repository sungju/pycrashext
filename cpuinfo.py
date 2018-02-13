"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function

from pykdump.API import *
from LinuxDump import percpu

import sys
from optparse import OptionParser


def cpufreq_policy_str(policy):
    return {
        0: "",
        1: "CPUFREQ_POLICY_POWERSAVE",
        2: "CPUFREQ_POLICY_PERFORMANCE",
    } [policy];

def show_cpufreq():
    if (not sys_info.machine in ("x86_64", "i386", "i686", "athlon")):
        print("Only available on x86 architecutres")
        sys.exit(1)

    addrs = percpu.get_cpu_var("cpufreq_cpu_data")
    try:
        all_cpu_data = readSymbol("all_cpu_data")
    except:
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

    (o, args) = op.parse_args()

    if (o.cpufreq):
        show_cpufreq()
        sys.exit(0)

    # default action
    show_cpufreq()

if ( __name__ == '__main__'):
    cpuinfo()