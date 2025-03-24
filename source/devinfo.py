"""
 Written by Daniel Sungju Kwon
"""
from pykdump.API import *

from LinuxDump.fs import *
from LinuxDump import Dev
from LinuxDump.block import *

import sys
import operator

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


def show_blkdevs_details(options, gendisk):
    request_queue = gendisk.queue
    nr_hw_queues = request_queue.nr_hw_queues
    print("\tnr_hw_queues : %d" % (nr_hw_queues))
    for idx in range(0, nr_hw_queues):
       blk_mq_hw_ctx = request_queue.queue_hw_ctx[idx]
       blk_mq_tags = blk_mq_hw_ctx.tags
       print("\t\tqueue_hw_ctx[%d].tags.nr_tags = %d" % (idx, blk_mq_tags.nr_tags))

    pass


def show_blkdevs(options):
    pa = readSymbol('major_names')
    print ("BLKDEV        NAME")
    for major, s in enumerate(pa):
        if (s == 0):
            continue

        name = s.name
        print (" %3d     %-15s" %  (major, name))

    if symbol_exists("bdev_map"):
        # It doesn't problematic case the blkext device with minor 0
        # does not get added to the bdev_map. Red Hat BZ#1739140
        # Thanks John Pittman for share this info.
        dev_len = len(pa)
        bdev_map = readSymbol("bdev_map")
        print("%5s:%5s(%5s)%-17s  %-18s %-18s" %
              ("MAJOR", "MINOR", "COUNT", " NAME", "gendisk", "request_queue"))
        for i in range(0, dev_len):
            addr = pa[i]
            if addr == 0:
                continue
            blk_major_name = readSU("struct blk_major_name", addr)
            major = blk_major_name.major
            probe = bdev_map.probes[major if i == major else i]
            probe_list = []
            while probe:
                major, minor = decode_devt(probe.dev)
                if major == 0:
                    break
                if probe.data == 0:
                    break
                probe_list.append(probe)
                probe = probe.next

            for i in range(len(probe_list) - 1, -1, -1):
                probe = probe_list[i]
                major, minor = decode_devt(probe.dev)
                gendisk_addr = probe.data
                gendisk = readSU('struct gendisk', gendisk_addr)
                if (gendisk == 0):
                    break

                name = gendisk.disk_name
                print ("%5d:%5d(%5d) %-17s 0x%16x 0x%16x" %
                       (major, minor, gendisk.minors, name, gendisk, gendisk.queue))

                show_blkdevs_details(options, gendisk)

    elif (symbol_exists('all_bdevs')):
        print("%5s:%5s(%5s)%-17s  %-18s %-18s" %
              ("MAJOR", "MINOR", "COUNT", " NAME", "gendisk", "request_queue"))
        for bd in readSUListFromHead(sym2addr('all_bdevs'),
                                     'bd_list', 'struct block_device'):
            major, minor = decode_devt(bd.bd_dev)
            gendisk_addr = bd.bd_disk
            gendisk = readSU('struct gendisk', gendisk_addr)
            name = ""
            if (gendisk == 0):
                continue

            name = gendisk.disk_name
            print ("%5d:%5d(%5d) %-17s 0x%16x 0x%16x" %
                   (major, minor, gendisk.minors, name, gendisk, gendisk.queue))
            print ("  %3d:%3d     %-10s" % (major, minor, name))

            show_blkdevs_details(options, gendisk)


def show_chrdevs():
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


def show_iotlb(options):
    io_tlb_list = readSymbol("io_tlb_list")
    io_tlb_nslabs = readSymbol("io_tlb_nslabs")
    io_tlb_used = readSymbol("io_tlb_used")
    io_tlb_index = readSymbol("io_tlb_index")
    print("io_tlb_list = 0x%x" % (io_tlb_list))
    print("io_tlb_nslabs = %d" % (io_tlb_nslabs))
    print("io_tlb_used = %d" % (io_tlb_used))
    print("io_tlb_index = %d" % (io_tlb_index))
    print("io_tlb_list[%d] = %d" % (io_tlb_index, io_tlb_list[io_tlb_index]))

    if options.show_details:
        for i in range(0, io_tlb_nslabs):
            print("io_tlb_list[%d] = %d" % (i, io_tlb_list[i]))


def show_requests(options):
    filter = ""
    rq_list_dict = {}
    for rq in get_all_request_queues(filter):
        for request in get_queue_requests(rq):
            reqinfo = request._reqinfo_
            rq_list_dict[request] = reqinfo.rq_alloc


    sorted_rq_list = sorted(rq_list_dict.items(),
            key=operator.itemgetter(1), reverse=True)
    for request, _ in sorted_rq_list:
        rq = request.q
        reqinfo = request._reqinfo_
        dev_name = rq_names[rq]
        try:
            hd_struct = request.part
            dev_name = hd_struct.__dev.kobj.name
        except:
            pass

        rq_alloc = reqinfo.rq_alloc
        alloc_time = "%.3f" % rq_alloc
        try:
            if rq_alloc < 0:
                alloc_time = "%.3f sec ago" % (-rq_alloc)
        except:
            pass

        if rq_alloc  < -5:
            if rq_alloc > -10:
                crashcolor.set_color(crashcolor.GREEN)
            elif rq_alloc > -20:
                crashcolor.set_color(crashcolor.MAGENTA)
            elif rq_alloc > -50:
                crashcolor.set_color(crashcolor.BLUE)
            else:
                crashcolor.set_color(crashcolor.RED)
        else:
            crashcolor.set_color(crashcolor.RESET)

        print("0x%x %7s %5s  allocated  %s" % (request, reqinfo.state, dev_name, alloc_time))
        crashcolor.set_color(crashcolor.RESET)


def devinfo():
    op = OptionParser()
    op.add_option("-b", "--block",
                  action="store_true",
                  dest="show_block",
                  default=False,
                  help="Show block device list")

    op.add_option("-c", "--char",
                  action="store_true",
                  dest="show_char",
                  default=False,
                  help="Show character device list")

    op.add_option("-d", "--details", dest="show_details", default=0,
                  action="store_true",
                  help="Show detailed information")

    op.add_option("-i", "--iotlb", dest="show_iotlb", default=False,
                  action="store_true",
                  help="Show IOTLB data")

    op.add_option("-q", "--requests", dest="show_requests", default=False,
                  action="store_true",
                  help="Show requests list")

    (o, args) = op.parse_args()

    if o.show_block:
        show_blkdevs(o)

    if o.show_char:
        show_chrdevs()

    if o.show_iotlb:
        show_iotlb(o)

    if o.show_requests:
        show_requests(o)


if ( __name__ == '__main__'):
    devinfo()
