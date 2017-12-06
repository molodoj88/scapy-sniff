from scapy.all import *


def cb(pkt):
    tcp_sport = pkt.sprintf("%TCP.sport%")
    tcp_dport = pkt.sprintf("%TCP.dport%")
    if tcp_sport in TCP_SERVICES:
        tcp_sport = TCP_SERVICES[tcp_sport]
    if tcp_dport in TCP_SERVICES:
        tcp_dport = TCP_SERVICES[tcp_dport]
    print pkt.sprintf("{}: %IP.src%\n{}: %IP.dst%\n{}: {}\n{}: {}\n".format('IP src',
                                                                          'IP dst',
                                                                          'TCP source port',
                                                                          tcp_sport,
                                                                          'TCP dest port',
                                                                          tcp_dport))


sniff(iface='enp4s0f1', prn=cb, count=5, filter="tcp")

