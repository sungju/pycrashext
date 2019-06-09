"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *
from LinuxDump.inet import *
from LinuxDump.inet import proto, netdevice

import sys

import crashcolor


def show_network_interfaces(options):
    for dev in netdevice.dev_base_list():
        dev_addr = "Not available"
        if (dev.dev_addr != 0):
            dev_addr = ("%02x:%02x:%02x:%02x:%02x:%02x" %
                        (dev.dev_addr[0], dev.dev_addr[1],
                         dev.dev_addr[2], dev.dev_addr[3],
                         dev.dev_addr[4], dev.dev_addr[5]))


        netdev_ops = dev.netdev_ops
        netdev_ops_str = addr2sym(netdev_ops)
        driver_module = ""
        crashout = exec_crash_command("sym %s" %
                                      (netdev_ops_str))
        driver_module = crashout.split()[-1]
        if (driver_module[0] != "["):
            driver_module = "<built-in>"

        print ("0x%016x : %s (%s) managed by " %
               (dev, dev.name, dev_addr), end='')
        crashcolor.set_color(crashcolor.BLUE)
        print ("%s" % driver_module)
        crashcolor.set_color(crashcolor.RESET)
        if (options.network_details):
            print ("\tnetdev_ops = %s (0x%x)" %
                   (netdev_ops_str, netdev_ops))

            master_name = ""
            if (member_offset("struct net_device", "master") >= 0):
                if (dev.master != 0):
                    master_name = dev.master.name
            else:
                master_name = "Not available"

            print("\tMTU: %d, Master = <%s>" %
                  (dev.mtu, master_name))

            print("\tIRQ: %d, num_tx_queues = %d, real_num_tx_queues = %d" %
                  (dev.irq, dev.num_tx_queues, dev.real_num_tx_queues))



def netinfo():
    op = OptionParser()
    op.add_option("-i", "--interface", dest="show_interface", default=0,
                  action="store_true",
                  help="Show network interfaces")

    op.add_option("-d", "--details", dest="network_details", default=0,
                  action="store_true",
                  help="Show network details")

    (o, args) = op.parse_args()

    if (o.show_interface):
        show_network_interfaces(o)
        sys.exit(0)


    show_network_interfaces(o)


if ( __name__ == '__main__'):
    netinfo()
