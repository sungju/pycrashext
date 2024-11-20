"""
 Written by Sungju Kwon <sungju.kwon@gmail.com>
"""
from pykdump.API import *

from LinuxDump import Tasks
from LinuxDump.trees import *
from LinuxDump import percpu

import crashcolor

import sys
from datetime import datetime

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
    blink_str = crashcolor.get_color(crashcolor.BLINK)
    underline_str = crashcolor.get_color(crashcolor.UNDERLINE)

    get_system_info()

    dump_path = sysinfo["DUMPFILE"]
    caseno_str = ""
    try:
        if "crash/" in dump_path:
            dump_path = dump_path[:dump_path.find("crash/")]
        elif "/tasks/" in dump_path:
            tasks_id = dump_path[dump_path.find("/tasks/") + 7:]
            tasks_id = tasks_id[:tasks_id.find("/")]
            dump_path = dump_path[:dump_path.find("%s/" % tasks_id) + len(tasks_id) + 1]

        with open(dump_path + "caseno", "r") as f:
            caseno_str = f.read()
    except:
        pass

    if caseno_str != "":
        print(" Case No: %s, " % (red_str + caseno_str + reset_str), end="")
    print("Hostname: %s" % (green_str + sysinfo["NODENAME"] + reset_str))
    crash_date=sysinfo["DATE"]
    tz=crash_date.split()[-2]
    crash_date = crash_date.replace(tz, "")
    datetime_fmt = '%a %b %d %H:%M:%S %Y'
    dt = datetime.strptime(crash_date, datetime_fmt)
    date_ago = datetime.now() - dt
    crash_date_color=reset_str
    if date_ago.days < 7:
        crash_date_color=green_str
    elif date_ago.days < 30:
        crash_date_color=blue_str + underline_str
    else:
        crash_date_color=red_str + underline_str + blink_str

    print(" Collected %s%d days%s ago. %s%s%s" % (crash_date_color,
                                                  date_ago.days,
                                                  reset_str,
                                                  underline_str,
                                                  sysinfo["DATE"],
                                                  reset_str))
    if options.sysinfo:
        print("=-" * 28)
        print(sys_str)
        cmd_line_addr = Addr(readSymbol("saved_command_line"))
        print(read_string(cmd_line_addr))
        #print("%s" % readSymbol("saved_command_line"))


def read_string(addr, delimiter=0x0):
    result = ""
    idx = 0
    while True:
        one_byte = readU8(addr + idx)
        idx = idx + 1
        if one_byte == delimiter:
            break
        result = result + str(chr(one_byte))

    return result

def caseinfo():
    op = OptionParser()
    op.add_option("-s", "--sys", dest="sysinfo", default=0,
                  action="store_true",
                  help="Shows sys output")

    (o, args) = op.parse_args()

    show_case_info(o)


if ( __name__ == '__main__'):
    caseinfo()
