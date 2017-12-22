from scapy.all import *
from PyQt5.QtCore import QObject
from PyQt5 import QtCore


class Sniffer(QObject):
    signal_send_msg = QtCore.pyqtSignal(str)

    def __init__(self, parent=None):
        super(Sniffer, self).__init__(parent)

    @QtCore.pyqtSlot()
    def do_sniff(self):
        self.signal_send_msg.emit("Hello, log!")
        sniff(iface='enp4s0f1', prn=self.cb, count=5, filter="tcp")

    def cb(self, pkt):
        tcp_sport = pkt.sprintf("%TCP.sport%")
        tcp_dport = pkt.sprintf("%TCP.dport%")
        if tcp_sport in TCP_SERVICES:
            tcp_sport = TCP_SERVICES[tcp_sport]
        if tcp_dport in TCP_SERVICES:
            tcp_dport = TCP_SERVICES[tcp_dport]
        packet_desc = pkt.sprintf("{}: %IP.src%\n{}: %IP.dst%\n{}: {}\n{}: {}\n".format('IP src',
                                                                              'IP dst',
                                                                              'TCP source port',
                                                                              tcp_sport,
                                                                              'TCP dest port',
                                                                              tcp_dport))
        self.signal_send_msg.emit(packet_desc.replace("\n", "; "))
