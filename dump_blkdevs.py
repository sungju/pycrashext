from __future__ import print_function

from pykdump.API import *

from LinuxDump.fs import *
from LinuxDump import Dev

import sys

def decode_devt(dev):
    if (dev >>16):
        # New-style
        major = dev >> 20
        minor = dev ^ (major<<20)
    else:
        # Old-style
        major = dev >>8
        minor = dev & 0xff
    return (int(major), int(minor))

def dump_blkdevs():
    pa = readSymbol('major_names')
    print ("BLKDEV        NAME")
    for major, s in enumerate(pa):
        if (s == 0):
            continue

        name = s.name
        print (" %3d     %-15s" %  (major, name))

    if (symbol_exists('all_bdevs')):
        for bd in readSUListFromHead(sym2addr('all_bdevs'),
                                     'bd_list', 'struct block_device'):
            major, minor = decode_devt(bd.bd_dev)
            gendisk_addr = bd.bd_disk
            gendisk = readSU('struct gendisk', gendisk_addr)
            name = ""
            if (gendisk != 0):
                name = gendisk.disk_name
            print ("  %3d:%3d     %-15s" % (major, minor, name))


if ( __name__ == '__main__'):
    #Dev.print_blkdevs(1)
    dump_blkdevs()
