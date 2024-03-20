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
        if (options.details):
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


def show_nft(options):
    init_net = readSymbol("init_net")
    netns_nftables = init_net.nft
    rbtree_type_addr = sym2addr("nft_set_rbtree_type")
    for nft_table in readSUListFromHead(netns_nftables.tables,
                                        "list",
                                        "struct nft_table"):
        print("%s %s" % (nft_table, nft_table.name))

        for nft_set in readSUListFromHead(nft_table.sets,
                                          "list",
                                          "struct nft_set"):
            nft_rbtree = readSU("struct nft_rbtree", nft_set.data)
            if nft_set.ops == rbtree_type_addr and nft_rbtree.root.rb_node != 0:
                rbtree_count = len(exec_crash_command("tree -t rbtree 0x%x" %
                                                  (nft_rbtree.root)).splitlines())
            else:
                rbtree_count = 0

            rbcount_kdigit = len("%d" % (rbtree_count / 100)) - 1

            print("\t%s %s %8d %s" % (nft_set, nft_set.name, rbtree_count, "#" * rbcount_kdigit))

            if not options.details:
                continue

            for nft_set_binding in readSUListFromHead(nft_set.bindings,
                                                      "list",
                                                      "struct nft_set_binding"):
                nft_chain = nft_set_binding.chain
                print("\t\t%s %s" % (nft_set_binding, nft_chain))
                rule_cnt = 0
                for nft_rule in readSUListFromHead(nft_chain.rules,
                                                   "list",
                                                   "struct nft_rule"):
                    rule_cnt += 1
                    print("\t\t\t%s %s" % (nft_rule, nft_rule.handle))
                print("\t\t\trule_count = %d" % (rule_cnt))



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


SHUTDOWN_MASK = 3
RCV_SHUTDOWN = 1
SEND_SHUTDOWN = 2


def get_sk_shutdown_str(sk_shutdown):
    shutdown_type = sk_shutdown & SHUTDOWN_MASK
    if shutdown_type == RCV_SHUTDOWN:
        return "RCV_SHUTDOWN"
    elif shutdown_type == SEND_SHUTDOWN:
        return "SEND_SHUTDOWN"
    else:
        return "NO SHUTDOWN"


SOCK_ASYNC_NOSPACE = 1 << 0
SOCK_ASYNC_WAITDATA = 1 << 1
SOCK_NOSPACE = 1 << 2
SOCK_PASSCRED = 1 << 3
SOCK_PASSSEC = 1 << 4
SOCK_EXTERNALLY_ALLOCATED = 1 << 5

def get_sk_socket_flags(sk_socket_flags):
    sk_socket_flags = sk_socket_flags & 0x3f
    return {
        SOCK_ASYNC_NOSPACE : "SOCK_ASYNC_NOSPACE",
        SOCK_ASYNC_WAITDATA : "SOCK_ASYNC_WAITDATA",
        SOCK_NOSPACE : "SOCK_NOSPACE",
        SOCK_PASSCRED : "SOCK_PASSCRED",
        SOCK_PASSSEC : "SOCK_PASSSEC",
        SOCK_EXTERNALLY_ALLOCATED : "SOCK_EXTERNALLY_ALLOCATED",
        0 : "NONE"
    }[sk_socket_flags]


TCP_ESTABLISHED = 1
TCP_SYN_SENT = 2
TCP_SYN_RECV = 3
TCP_FIN_WAIT1 = 4
TCP_FIN_WAIT2 = 5
TCP_TIME_WAIT = 6
TCP_CLOSE = 7
TCP_CLOSE_WAIT = 8
TCP_LAST_ACK = 9
TCP_LISTEN = 10
TCP_CLOSING = 11
TCP_NEW_SYN_RECV = 12
TCP_MAX_STATES = 13

def get_skc_state_str(skc_state):
    if skc_state >= TCP_MAX_STATES:
        skc_state = TCP_MAX_STATES
    return {
        TCP_ESTABLISHED : "TCP_ESTABLISHED",
        TCP_SYN_SENT : "TCP_SYN_SENT",
        TCP_SYN_RECV : "TCP_SYN_RECV",
        TCP_FIN_WAIT1 : "TCP_FIN_WAIT1",
        TCP_FIN_WAIT2 : "TCP_FIN_WAIT2",
        TCP_TIME_WAIT : "TCP_TIME_WAIT",
        TCP_CLOSE : "TCP_CLOSE",
        TCP_CLOSE_WAIT : "TCP_CLOSE_WAIT",
        TCP_LAST_ACK : "TCP_LAST_ACK",
        TCP_LISTEN : "TCP_LISTEN",
        TCP_CLOSING : "TCP_CLOSING",
        TCP_NEW_SYN_RECV : "TCP_NEW_SYN_RECV",
        TCP_MAX_STATES : "Invalid",
        0 : "Invalid",
    }[skc_state]


def show_sock_status(sock):
    print("\n< socket status >")
    print("\t<struct socket 0x%x>" % (sock.sk_socket))
    print("\tsk_socket->flags = %s" % (get_sk_socket_flags(sock.sk_socket.flags)))
    print("\tskc_state = %s" % (get_skc_state_str(sock.__sk_common.skc_state)))
    print("\tsk_err = %d, sk_shutdown = %s" % \
          (sock.sk_err, get_sk_shutdown_str(sock.sk_shutdown)))
    print("\tsk_wmem_queued = %d" % (sock.sk_wmem_queued))
    print("\tsk_sndbuf = %d, sk_rcvbuf = %d" %
          (sock.sk_sndbuf, sock.sk_rcvbuf))


def show_peer_sock_tasks(sock):
    if sock == 0 or sock == None:
        return

    sock_addr = "%x" % (sock)
    tt = Tasks.TaskTable()

    print("\n\t<Tasks with this peer unix_sock>")
    print("\t%s" % ("-" * 32))

    for t in tt.allThreads():
        try:
            socklist = exec_crash_command("net -s %d" % (t.pid))
        except:
            continue

        if socklist.find(sock_addr) >= 0:
            print("\t%s (%d)" % (t.comm, t.pid))
    pass


def show_unix_sock(options, sock):
    unix_sock = readSU("struct unix_sock", sock)
    print(unix_sock)
    print("\tunix_sock.peer <struct unix_sock 0x%x>" % unix_sock.peer)
    print("\tunix_sock.addr", unix_sock.addr)
    if unix_sock.addr != 0x0:
        print("\t\taddr = '%s'" % (unix_sock.addr.name.sun_path))
    print("\tunix_sock.peer_wait", unix_sock.peer_wq.wait)

    if options.details:
        if unix_sock.peer != 0:
            show_peer_sock_tasks(unix_sock.peer)

    show_sock_status(sock)


def ip2str(ipnum):
    return socket.inet_ntoa(struct.pack('!L', ipnum))


def show_inet_sock(options, sock):
    inet_sock = readSU("struct inet_sock", sock)
    print(inet_sock)
    print("\tsrc addr = %s:%d" % (ip2str(sock.__sk_common.skc_rcv_saddr),
                                sock.__sk_common.skc_num))
    print("\tdst addr = %s:%d" % (ip2str(sock.__sk_common.skc_daddr),
                                 sock.__sk_common.skc_dport))

    show_sock_status(sock)


def show_netlink_sock(options, sock):
    offset = member_offset("struct netlink_sock", "sk")
    netlink_sock = readSU("struct netlink_sock", sock - offset)
    print(netlink_sock)
    print("\tpeer_pid = %d" % (sock.sk_peer_pid))

    show_sock_status(sock)


def show_socket_details(options):
    socket = readSU("struct socket", int(options.socket_addr, 16))
    if socket == 0 or socket == None:
        print("Not a valid socket address")
        return

    print("state =", socket.state)
    ops_name = addr2sym(socket.ops)
    if ops_name == "unix_stream_ops":
        show_unix_sock(options, socket.sk)
    elif ops_name == "inet_stream_ops":
        show_inet_sock(options, socket.sk)
    elif ops_name == "netlink_ops":
        show_netlink_sock(options, socket.sk)
    else:
        print(socket)


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

    skc_family = sock.__sk_common.skc_family
    if skc_family == AF_UNIX:
        show_unix_sock(options, sock)
    elif skc_family == AF_INET:
        show_inet_sock(options, sock)
    elif skc_family == AF_NETLINK:
        show_netlink_sock(options, sock)
    else:
        print(sock)


def netinfo():
    op = OptionParser()
    op.add_option("-d", "--details", dest="details", default=0,
                  action="store_true",
                  help="Show network details")

    op.add_option("-i", "--interface", dest="show_interface", default=0,
                  action="store_true",
                  help="Show network interfaces")

    op.add_option("-n", "--nft", dest="nft", default=0,
                  action="store_true",
                  help="Show nft information")

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

    if (o.nft):
        show_nft(o)
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
