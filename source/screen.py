"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *

from LinuxDump import Tasks

import sys
import operator

import crashcolor
import crashhelper

def do_reset_screen(options):
    crashcolor.clear_screen()
    crashcolor.set_cursor(0,0)


def screen():
    op = OptionParser()
    op.add_option("-r", "--reset", dest="reset_screen", default=0,
                  action="store_true",
                  help="reset screen")

    (o, args) = op.parse_args()

    if (o.reset_screen):
        do_reset_screen(o)
        sys.exit(0)


if ( __name__ == '__main__'):
    screen()
