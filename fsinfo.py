"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *
from LinuxDump import Tasks
import sys


def dentry_to_filename (dentry) :
    if (dentry == 0):
        return "<>"

    try:
        crashout = exec_crash_command ("files -d {:#x}".format(dentry))
        filename = crashout.split()[-1]
        if filename == "DIR" :
            filename = "<blank>"
        return filename
    except:
        return "<invalid>"


def get_frozen_str(frozen_type):
    return {
        0: "SB_UNFROZEN",
        1: "SB_FREEZE_WRITE",
        2: "SB_FREEZE_PAGEFAULT",
        3: "SB_FREEZE_FS",
        4: "SB_FREEZE_COMPLETE",
        -1: "UNRECOGNIZED STATE",
    }[frozen_type]


def all_filesystem_info(options):
    super_blocks = sym2addr("super_blocks")
    for sb in readSUListFromHead(super_blocks,
                                         "s_list",
                                         "struct super_block"):
        frozen = -1
        if (member_offset('struct super_block', 's_frozen') >= 0):
            frozen = sb.s_frozen
        elif (member_offset('struct super_block', 's_writers') >= 0):
            frozen = sb.s_writers.frozen

        frozen_str = get_frozen_str(frozen)
        print ("frozen=%s, %s (%s) [%s]" %
               (frozen_str,
               dentry_to_filename(sb.s_root), sb.s_id,
                sb.s_type.name))



def fsinfo():
    op = OptionParser()
    op.add_option("--details", dest="filesystem_details", default=0,
                  action="store_true",
                  help="Show scheduling classes")

    (o, args) = op.parse_args()

    all_filesystem_info(o)

if ( __name__ == '__main__'):
    fsinfo()
