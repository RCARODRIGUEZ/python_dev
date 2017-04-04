'''
Testing Scapy Sniffer

Author: Ricardo Castro Rodriguez CE
Date: 3.4.17

'''
from scapy.all import *
import os
import sys

def packet_sniffer():
    print "Begin Sniffer"
    pkt = scapy.all.sniffer(iface = "eth0", proto = "tcp")
    pkt.show()


if __name__ == '__main__':
    def display():
        version = 0.1
        print "Packet Sniffer V{0}".format(version)
