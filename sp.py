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

    udp_sport = pkt.sprintf("%UDP.sport%")
    udp_dport = pkt.sprintf("%UDP.dport%")
    if udp_sport in UDP_SERVICES:
        udp_sport = TCP_SERVICES[udp_sport]
    if udp_dport in UDP_SERVICES:
        udp_dport = UDP_SERVICES[udp_dport]
        print pkt.sprintf("{}: %IP.src%\n{}: %IP.dst%\n{}: {}\n{}: {}\n".format('IP src',
                                                                                'IP dst',
                                                                                'UDP source port',
                                                                                udp_sport,
                                                                                'UDP dest port',
                                                                                udp_dport))












sniff(iface='wlp3s0', prn=cb, count=5, filter="udp || tcp")

#s = {(src_ip, dst_ip) : {'tcp' : [{(src_port, dst_port): n_packets}]}}









