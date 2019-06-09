"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *
from LinuxDump import Tasks
from LinuxDump import syscall
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
    if symbol_exists("ia32_sys_call_table") and syscall.sct32 != None:
        sys_call_table = syscall.sct32
    elif syscall.sct != None:
        sys_call_table = syscall.sct
    else:
        sys_call_table = None

    if sys_call_table != None:
        max_syscalls = len(sys_call_table)

    return sys_call_table, max_syscalls


def get_kernel_start_addr():
    if sys_info.machine.startswith("ppc"):
        kernel_start_addr = sym2addr("_stext")
        if kernel_start_addr == None:
            return 0
        return kernel_start_addr

    return 0


def show_syscall_details(options):
    sys_call_table, max_syscalls = sys_call_table_info()
    if max_syscalls > 0 and options.syscall_no >= max_syscalls:
        print("Invalid system call number %d.  Available range is %d~%d" %
              (options.syscall_no, 0, max_syscalls - 1))
        return


def check_syscall_table(options):
    sys_call_table, max_syscalls = sys_call_table_info()

    invalid_start_list = [ "jmp", "callq" ]
    arch = sys_info.machine
    if arch.startswith("arm") or arch.startswith("ppc"):
        #invalid_start_list = [ "bl" ]
        pass # As the normal call also has 'bl' in some calls, not use it yet

    hook_call_no = 0
    trap_call_no = 0
    idx = 0
    for sys_call in sys_call_table:
        call_addr = sym2addr(sys_call)
        result = exec_crash_command("sym 0x%x" % call_addr)
        if result != None and result.startswith("sym"):
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
            elif options.syscall_check == False:
                print("%3d %s %s %-25s %s" % (idx, words[0], words[1], words[2], filepath))


        crashcolor.set_color(crashcolor.RESET)

        idx = idx + 1

    if hook_call_no > 0 or trap_call_no > 0:
        print("=" * 75)
        if hook_call_no > 0:
            print("%d system calls were replaced" % hook_call_no)

        if trap_call_no > 0:
            print("%d system calls were modified" % trap_call_no)
    elif options.syscall_check:
        print("No issues detected")


def syscallinfo():
    op = OptionParser()
    op.add_option("-c", "--check", dest="syscall_check", default=0,
                  action="store_true",
                  help="Check for any modifications in syscall table")

    op.add_option("-n", "--no", dest="syscall_no", default=-1,
                  type="int", action="store",
                  help="Shows detailed information for a specific syscall no")

    (o, args) = op.parse_args()

    check_syscall_table(o)

if ( __name__ == '__main__'):
    syscallinfo()
