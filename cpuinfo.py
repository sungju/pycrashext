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
    all_cpu_data = readSymbol("all_cpu_data")
    for cpu, addr in enumerate(addrs):
        cpufreq_addr = readULong(addr)
        cpufreq_cpu_data = readSU('struct cpufreq_policy', cpufreq_addr)
        cpudata = all_cpu_data[cpu]
        print("CPU %3d, min = %d, max = %d, cur = %d\n"
              "\tcurrent_pstate = %d, policy = %s" %
                (cpu, cpufreq_cpu_data.min, cpufreq_cpu_data.max,
                 cpufreq_cpu_data.cur,
                 cpudata.pstate.current_pstate,
                 cpufreq_policy_str(cpufreq_cpu_data.policy)))

def cpuinfo():
    op = OptionParser()
    op.add_option("--cpufreq", dest="cpufreq", default=0,
                  action="store_true",
                  help="CPU frequency details")

    (o, args) = op.parse_args()

    if (o.cpufreq):
        show_cpufreq()
#        sys.exit(0)


if ( __name__ == '__main__'):
    cpuinfo()
