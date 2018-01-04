#! /usr/bin/env python2.7
from scapy.all import *
from netfilterqueue import NetfilterQueue

true_ttl_value = 0
true_window_size = 0
initial_handshake_done = False

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

def inspect(packet):
    pkt = IP(packet.get_payload())
    if pkt.haslayer(TCP):
        F = pkt['TCP'].flags
        if (F & SYN) and  (F & ACK) and not initial_handshake_done:
            true_ttl_value = pkt['IP'].ttl
            initial_handhshake_done = True
            print "Initial handshake detected"
            print "True ttl: ", true_ttl_value
            packet.accept()

        if ((F & FIN) and (F & PSH) and (F & ACK)) or (F & RST):
            print pkt['IP'].ttl
            if (pkt['IP'].ttl - true_ttl_value >=1):
                print "suspicious packet detected"
                packet.drop()
    else:
        print "No TCP layer"
    packet.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(1, inspect) 
try:
    print "Netcreeper running..."
    nfqueue.run()
except KeyboardInterrupt:
    pass
