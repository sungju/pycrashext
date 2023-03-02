"""
 Written by Sungju Kwon <sungju.kwon@gmail.com>
"""
from pykdump.API import *

from LinuxDump import Tasks
from LinuxDump.trees import *
from LinuxDump import percpu

import crashcolor

import sys

sysinfo = {}
sys_str = ""

def get_system_info():
    global sysinfo
    global sys_str

    if (len(sysinfo) > 0):
        return

    sys_str = exec_crash_command("sys")
    resultlines = sys_str.splitlines()
    for line in resultlines:
        words = line.split(":")
        sysinfo[words[0].strip()] = line[len(words[0]) + 2:].strip()

def show_case_info(options):
    global sysinfo
    red_str = crashcolor.get_color(crashcolor.LIGHTRED)
    green_str = crashcolor.get_color(crashcolor.GREEN)
    blue_str = crashcolor.get_color(crashcolor.BLUE)
    reset_str = crashcolor.get_color(crashcolor.RESET)

    get_system_info()

    dump_path = sysinfo["DUMPFILE"]
    dump_path = dump_path[:dump_path.find("crash/")]
    try:
        f = open(dump_path + "caseno", "r")
        print(" Case No: %s, " % (red_str + f.read() + reset_str), end="")
    except:
        pass
    print("Hostname: %s" % (green_str + sysinfo["NODENAME"] + reset_str))
    print("=-" * 28)
    if options.sysinfo:
        print(sys_str)


def caseinfo():
    op = OptionParser()
    op.add_option("-s", "--sys", dest="sysinfo", default=0,
                  action="store_true",
                  help="Shows sys output")

    (o, args) = op.parse_args()

    show_case_info(o)


if ( __name__ == '__main__'):
    caseinfo()
