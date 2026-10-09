"""
'preempt' command: decode preempt_count values.

    preempt <value>...   decode each value (e.g. preempt 0x00010002)
    preempt -l           decode every preempt_count the kernel log prints
                         ('scheduling while atomic', 'preempt_count: N'),
                         each after its log line as printed

The decoding is preemptcount.py, which also runs on its own:
    python3 preemptcount.py <value>...

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from pykdump.API import *

import preemptcount


def preempt():
    op = OptionParser(usage="preempt [-l] [<value>...]")
    op.add_option("-l", "--log", dest="log", default=0, action="store_true",
                  help="Decode every preempt_count printed in the kernel log")

    (o, args) = op.parse_args()
    if o.log:
        print(preemptcount.report_log(exec_crash_command("log").splitlines()))
    for a in args:
        try:
            print(preemptcount.describe(int(a, 0)))
        except ValueError:
            print("not a number: %s" % a)
    if not o.log and not args:
        print("usage: preempt [-l] [<value>...]   e.g. preempt 0x00010002, preempt -l")


if ( __name__ == '__main__'):
    preempt()
