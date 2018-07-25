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
        filepath = m.group('filepath') + " " + words[4]
    else:
        filepath = words[3]
        crashcolor.set_color(crashcolor.LIGHTRED)

    return filepath


def show_syscall_table(options):
    sys_call_table = readSymbol("sys_call_table")
    for idx in range(0, len(sys_call_table)):
        result = exec_crash_command("sym 0x%x" % sys_call_table[idx])
        words = result.split()
        filepath = get_file_path(words)

        print("%3d %s %s %-25s %s" % (idx, words[0], words[1], words[2], filepath))
        crashcolor.set_color(crashcolor.RESET)

invalid_start_list = [ "jmp", "callq" ]

def set_invalid_start_list():
    arch = sys_info.machine
    if (arch in ("x86_64", "i386", "i686", "athlon")):
        invalid_start_list = [ "jmp", "callq" ]
    elif (sys_info.machine.startswith("arm")):
        invalid_start_list = [ "jmp", "callq" ]
    elif (sys_info.machine.startswith("ppc")):
        invalid_start_list = [ "jmp", "callq" ]


def check_syscall_table(options):
    set_invalid_start_list()
    sys_call_table = readSymbol("sys_call_table")
    hook_call_no = 0
    trap_call_no = 0
    for idx in range(0, len(sys_call_table)):
        result = exec_crash_command("sym 0x%x" % sys_call_table[idx])
        words = result.split()
        filepath = get_file_path(words)
        if len(words) == 4:
            hook_call_no = hook_call_no + 1
            crashcolor.set_color(crashcolor.LIGHTRED)
            print("%3d %s"  % (idx, result), end='')
        else:
            dis_result = exec_crash_command("dis 0x%x 1" % sys_call_table[idx])
            dis_words = dis_result.split()
            if len(dis_words) >= 4 and dis_words[2].strip() in invalid_start_list:
                trap_call_no = trap_call_no + 1
                crashcolor.set_color(crashcolor.BLUE)
                print("%3d %s %s %-25s %s" %
                      (idx, words[0], words[1], words[2], filepath))
                print("\t%s" % (dis_result[dis_result.find(dis_words[2]):]),
                      end='')

        crashcolor.set_color(crashcolor.RESET)

    if hook_call_no > 0 or trap_call_no > 0:
        print("=" * 75)
    if hook_call_no > 0:
        print("%d system calls were replaced" % hook_call_no)

    if trap_call_no > 0:
        print("%d system calls were modified" % trap_call_no)


def syscallinfo():
    op = OptionParser()
    op.add_option("--check", dest="syscall_check", default=0,
                  action="store_true",
                  help="Check for any modifications in syscall table")

    (o, args) = op.parse_args()

    if (o.syscall_check):
        check_syscall_table(o)
        sys.exit(0);

    show_syscall_table(o)

if ( __name__ == '__main__'):
    syscallinfo()
