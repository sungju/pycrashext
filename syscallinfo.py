"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *
from LinuxDump import Tasks
import sys

import crashcolor

pattern = re.compile(r"(.+)/linux-(?P<releaseversion>[^/]+)/(?P<filepath>.*)")

def get_file_path(words):
    if len(words) >= 4 and words[3].startswith("/"):
        m = pattern.search(words[3])
        filepath = m.group('filepath')
        if len(words) > 4:
            filepath = filepath + " " + words[4]
    elif len(words) == 3:
        filepath = ""
    else:
        filepath = words[3]
        crashcolor.set_color(crashcolor.LIGHTRED)

    return filepath


def sys_call_table_info():
    max_syscalls = 0
    if sys_info.machine.startswith("ppc"):
        sys_call_table = sym2addr("sys_call_table")
        sys_call_table = readULong(sys_call_table)
    else:
        sys_call_table = readSymbol("sys_call_table")
        max_syscalls = len(sys_call_table)

    return sys_call_table, max_syscalls


def get_kernel_start_addr():
    if sys_info.machine.startswith("ppc"):
        kernel_start_addr = sym2addr("_stext")
        if kernel_start_addr == None:
            return 0
        return kernel_start_addr

    return 0


def show_syscall_table(options):
    sys_call_table, max_syscalls = sys_call_table_info()

    idx = 0
    kernel_start_addr = get_kernel_start_addr()
    while True:
        if max_syscalls > 0:
            call_addr = sys_call_table[idx]
        else:
            call_addr = readULong(sys_call_table + idx * 8)

        if kernel_start_addr > 0 and call_addr < kernel_start_addr:
            break

        result = exec_crash_command("sym 0x%x" % call_addr)
        if result != None and result.startswith("sym"):
            break
        words = result.split()
        filepath = get_file_path(words)
        print("%3d %s %s %-25s %s" % (idx, words[0], words[1], words[2], filepath))
        crashcolor.set_color(crashcolor.RESET)

        idx = idx + 1
        if max_syscalls > 0 and idx >= max_syscalls:
            break



def show_syscall_details(options):
    sys_call_table, max_syscalls = sys_call_table_info()
    if max_syscalls > 0 and options.syscall_no >= max_syscalls:
        print("Invalid system call number %d.  Available range is %d~%d" %
              (options.syscall_no, 0, max_syscalls - 1))
        return

    pass


invalid_start_list = [ "jmp", "callq" ]

def set_invalid_start_list():
    arch = sys_info.machine
    if (arch in ("x86_64", "i386", "i686", "athlon")):
        invalid_start_list = [ "jmp", "callq" ]
    elif (sys_info.machine.startswith("arm")):
        invalid_start_list = [ "b", "bl" ]
    elif (sys_info.machine.startswith("ppc")):
        invalid_start_list = [ "b", "bl" ]


def check_syscall_table(options):
    set_invalid_start_list()
    sys_call_table, max_syscalls = sys_call_table_info()

    hook_call_no = 0
    trap_call_no = 0
    idx = 0
    kernel_start_addr = get_kernel_start_addr()
    while True:
        if max_syscalls > 0:
            call_addr = sys_call_table[idx]
        else:
            call_addr = readULong(sys_call_table + idx * 8)

        if kernel_start_addr > 0 and call_addr < kernel_start_addr:
            break

        result = exec_crash_command("sym 0x%x" % call_addr)
        if result.startswith("sym"):
            break
        words = result.split()
        filepath = get_file_path(words)
        if len(words) == 4 and not words[3].startswith("/"):
            hook_call_no = hook_call_no + 1
            crashcolor.set_color(crashcolor.LIGHTRED)
            print("%3d %s"  % (idx, result), end='')
        else:
            dis_result = exec_crash_command("dis 0x%x 1" % call_addr)
            dis_words = dis_result.split()
            if len(dis_words) >= 4 and dis_words[2].strip() in invalid_start_list:
                trap_call_no = trap_call_no + 1
                crashcolor.set_color(crashcolor.BLUE)
                print("%3d %s %s %-25s %s" %
                      (idx, words[0], words[1], words[2], filepath))
                print("\t%s" % (dis_result[dis_result.find(dis_words[2]):]),
                      end='')

        crashcolor.set_color(crashcolor.RESET)

        idx = idx + 1
        if max_syscalls > 0 and idx >= max_syscalls:
            break

    if hook_call_no > 0 or trap_call_no > 0:
        print("=" * 75)
        if hook_call_no > 0:
            print("%d system calls were replaced" % hook_call_no)

        if trap_call_no > 0:
            print("%d system calls were modified" % trap_call_no)
    else:
        print("No issues detected")


def syscallinfo():
    op = OptionParser()
    op.add_option("--check", dest="syscall_check", default=0,
                  action="store_true",
                  help="Check for any modifications in syscall table")

    op.add_option("-n", dest="syscall_no", default=-1,
                  type="int", action="store",
                  help="Shows detailed information for a specific syscall no")

    (o, args) = op.parse_args()

    if (o.syscall_check):
        check_syscall_table(o)
        sys.exit(0)

    if (o.syscall_no > -1):
        show_syscall_details(o)
        sys.exit(0)

    show_syscall_table(o)

if ( __name__ == '__main__'):
    syscallinfo()
