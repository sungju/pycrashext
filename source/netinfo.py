"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *
from LinuxDump.inet import *
from LinuxDump.inet import proto, netdevice

import sys
import collections

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



def get_proto_list():
    result_list = {}
    proto_list = readSymbol("proto_list")
    for proto in readSUListFromHead(proto_list,
                                    "node",
                                    "struct proto"):
        result_list[proto.inuse_idx] = proto

    return collections.OrderedDict(sorted(result_list.items()))


def show_network_protocols(options):
    int_size =getSizeOf("int")
    for idx, proto in get_proto_list().items():
        print("0x%x : %s (inuse_idx = %d)" %
              (proto, proto.name, proto.inuse_idx))
        for name, addr in {"mem" : proto.sysctl_mem,
                           "wmem" : proto.sysctl_wmem,
                           "rmem" : proto.sysctl_rmem}.items():
            if addr > 0:
                min_val = readUInt(addr)
                default_val = readUInt(addr + int_size)
                max_val = readUInt(addr + int_size * 2)
            else:
                min_val = default_val = max_val = 0

            print("\t%s = [%d, %d, %d]" % (name, min_val, default_val, max_val))


def show_unix_sock(options, sock):
    unix_sock = readSU("struct unix_sock", sock)
    print("\tunix_sock.peer <struct unix_sock 0x%x>" % unix_sock.peer)
    print("\tunix_sock.addr", unix_sock.addr)
    if unix_sock.addr != 0x0:
        print("\t\taddr = '%s'" % (unix_sock.addr.name.sun_path))


def ip2str(ipnum):
    return socket.inet_ntoa(struct.pack('!L', ipnum))


def show_inet_sock(options, sock):
    inet_sock = readSU("struct inet_sock", sock)
    print("sk_sndbuf = %d, sk_rcvbuf = %d" %
          (inet_sock.sk.sk_sndbuf, inet_sock.sk.sk_rcvbuf))
    print("\tsrc addr = %s:%d" % (ip2str(sock.__sk_common.skc_rcv_saddr),
                                sock.__sk_common.skc_num))
    print("\tdst addr = %s:%d" % (ip2str(sock.__sk_common.skc_daddr),
                                 sock.__sk_common.skc_dport))


def show_socket_details(options):
    socket = readSU("struct socket", int(options.socket_addr, 16))
    if socket == 0 or socket == None:
        print("Not a valid socket address")
        return

    print(socket)
    print("state =", socket.state)
    ops_name = addr2sym(socket.ops)
    if ops_name == "unix_stream_ops":
        show_unix_sock(options, socket.sk)
    elif ops_name == "inet_stream_ops":
        show_inet_sock(options, socket.sk)


AF_UNIX = 1
AF_LOCAL = 1
AF_INET = 2
AF_INET6 = 10
AF_NETLINK = 16

def show_sock_details(options):
    sock = readSU("struct sock", int(options.sock_addr, 16))
    if sock == 0 or sock == None:
        print("Not a valid sock address")
        return

    print(sock)
    skc_family = sock.__sk_common.skc_family
    if skc_family == AF_UNIX:
        show_unix_sock(options, sock)
    elif skc_family == AF_INET:
        show_inet_sock(options, sock)



def netinfo():
    op = OptionParser()
    op.add_option("-i", "--interface", dest="show_interface", default=0,
                  action="store_true",
                  help="Show network interfaces")

    op.add_option("-d", "--details", dest="network_details", default=0,
                  action="store_true",
                  help="Show network details")

    op.add_option("-p", "--proto", dest="show_protocols", default=0,
                  action="store_true",
                  help="Show network protocols")

    op.add_option("-s", "--socket", dest="socket_addr", default="",
                  action="store",
                  help="Show socket details")

    op.add_option("-S", "--sock", dest="sock_addr", default="",
                  action="store",
                  help="Show struct sock details")


    (o, args) = op.parse_args()

    if (o.show_interface):
        show_network_interfaces(o)
        sys.exit(0)


    if (o.show_protocols):
        show_network_protocols(o)
        sys.exit(0)


    if (o.socket_addr != ""):
        show_socket_details(o)
        sys.exit(0)

    if (o.sock_addr != ""):
        show_sock_details(o)
        sys.exit(0)


    show_network_interfaces(o)


if ( __name__ == '__main__'):
    netinfo()
