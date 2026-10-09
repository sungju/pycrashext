"""
'logscan' command: which known kernel-log signatures this dump holds.

Scans the 'log' output for the messages that decide how a crash is analysed
(panic, oops, corruption, stack, atomic context, OOM, soft/hard lockup, hung
tasks, RCU stalls, NETDEV watchdog, storage transport errors, MCE/EDAC,
hypervisor, sysrq), and prints a count, the first and last 'log' line number
and what each one points to, then those lines exactly as 'log' prints them.
A panic caused by a detection sysctl (softlockup_panic, hung_task_panic,
panic_on_oom) gets a reroute note: analyse the condition, not the panic.

The catalogue is logsig.py, which also runs on a saved log:
    python3 logsig.py <log file>

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from pykdump.API import *

import logsig


def logscan():
    op = OptionParser(usage="logscan [-a]")
    op.add_option("-a", "--all", dest="show_all", default=0, action="store_true",
                  help="Print every matching line, not only the first and last")

    (o, args) = op.parse_args()
    lines = exec_crash_command("log").splitlines()
    print(logsig.report(lines, source="log", show_all=o.show_all))


if ( __name__ == '__main__'):
    logscan()
