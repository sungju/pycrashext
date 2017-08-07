from __future__ import print_function

from pykdump.API import *

from LinuxDump.fs import *
from LinuxDump import Dev

import sys

def dump_chrdevs():
    pa = readSymbol('chrdevs');
    print ('CHRDEV     NAME            OPERATIONS')

    if (struct_exists('char_device_struct')):
        for addr in pa:
            while (addr):
                s = readSU('struct char_device_struct', addr)
                major = s.major
                name = s.name
                addr = s.next
                print ("%3d      %-15s" %(major, name))
    else:
        for major, s in enumerate(pa):
            #print ("%3d   %-11s" % (major, s))
            if (s == 0):
                continue
            cdev_addr = s.cdev
            ops = 0
            if (cdev_addr != 0):
                cdev = readSU('struct cdev', cdev_addr)
                ops = cdev.ops
            name = s.name
            print (" %3d     %-15s   0x%016x  <%s>" % \
                   (major, name, ops, addr2sym(ops)))

if ( __name__ == '__main__'):
    dump_chrdevs()
