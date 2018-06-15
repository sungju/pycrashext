"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *

from LinuxDump import Tasks

import sys

def show_clocksource_details(clocksource_addr):
    clocksource = readSU('struct clocksource', clocksource_addr)
    print("\tname : %s" % clocksource.name)
    print("\tread : %s (0x%x)" % (addr2sym(clocksource.read), clocksource.read))


def show_timesources(show_details):
    """
    ** current clocksource
    crash> curr_clocksource
    curr_clocksource = $26 = (struct clocksource *) \
            0xffffffff81a97640 <clocksource_hpet>
    crash> clocksource.name 0xffffffff81a97640
      name = 0xffffffff81791c74 "hpet"

      ** Available clocksources
      crash> list -H clocksource_list -s clocksource.name -o clocksource.list
    """
    curr_clocksource = readSymbol("curr_clocksource")
    print ("Current clocksource = %s (0x%x)\n" %
          (addr2sym(curr_clocksource), curr_clocksource))
    clocksource_list = readSymbol("clocksource_list")
    for clocksource_addr in readSUListFromHead(clocksource_list,
                                    'list',
                                    'struct clocksource'):
        print ("%s (0x%x)" % (addr2sym(clocksource_addr), clocksource_addr))
        if (show_details):
            show_clocksource_details(clocksource_addr)


def timeinfo():
    op = OptionParser()
    op.add_option("--source", dest="timesource", default=0,
                  action="store_true",
                  help="Show time sources")
    op.add_option("--details", dest="show_details", default=0,
                  action="store_true",
                  help="Show details")

    (o, args) = op.parse_args()

    if (o.timesource):
        show_timesources(o.show_details)

if ( __name__ == '__main__'):
    timeinfo()
