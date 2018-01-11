from scapy.all import *
from PyQt5.QtCore import QObject
from PyQt5 import QtCore


class Sniffer(QObject):
    signal_pkt_received = QtCore.pyqtSignal(list)

    def __init__(self, interface='wlp3s0', parent=None):
        super(Sniffer, self).__init__(parent)
        self.interface = interface

    @QtCore.pyqtSlot()
    def do_sniff(self):
        sniff(iface=self.interface, prn=self.cb, count=5000, filter="tcp")

    def cb(self, pkt):
        ip_src = pkt.sprintf("%IP.src%")
        ip_dst = pkt.sprintf("%IP.dst%")
        tcp_sport = pkt.sprintf("%TCP.sport%")
        tcp_dport = pkt.sprintf("%TCP.dport%")
        if tcp_sport in TCP_SERVICES:
            tcp_sport = TCP_SERVICES[tcp_sport]
        if tcp_dport in TCP_SERVICES:
            tcp_dport = TCP_SERVICES[tcp_dport]

        pkt_desc = [ip_src, ip_dst, tcp_sport, tcp_dport]

        self.signal_pkt_received.emit(pkt_desc)
