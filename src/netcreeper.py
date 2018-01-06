#! /usr/bin/env python2.7
from scapy.all import *
from netfilterqueue import NetfilterQueue

verdict_given = False
info =  {} # {IP_Addrs : [ttl]}

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
    global info
    global verdict_given

    source_ip = str(pkt['IP'].src)
    ttl = pkt['IP'].ttl
    
    if pkt.haslayer(TCP):
        F = pkt['TCP'].flags
        if (F & SYN) and  (F & ACK) and (source_ip not in info): 
            info.update({source_ip: [ttl, 0]})
            print "Initial Handshake detected. IP: %s, Suspicious TTL: %d, True TTL:%d" %(source_ip, ttl, info[source_ip][0])
            packet.accept()
            verdict_given = True

        elif (F & FIN)  and (source_ip in info):# and (F & PSH) and (F & ACK)) or (F & RST)) and (source_ip in info):# and initial_handshake_done:
            if (ttl - info[source_ip][0] >= 1 or ttl - info[source_ip][0] <= -1):
                print "Dropping suspicious FIN packet detected. IP: %s, Supicious TTL: %d, True TTL:%d" %(source_ip, ttl, info[source_ip][0])
                packet.drop()
                verdict_given = True
            else:
                packet.accept()
        elif (F & RST) and (source_ip in info):
            if (ttl - info[source_ip][0] >= 1  or ttl - info[source_ip][0] <= -1):
                print "Dropping suspicious RST packet detected. IP: %s, Suspicious TTL: %d, True TTL:%d" %(source_ip, ttl, info[source_ip][0])
                packet.drop()
                verdict_given = True
            else:
                print "Deleting stream. IP: %s, This TTL: %d, True TTL:%d" %(source_ip, ttl, info[source_ip][0])
                del info[source_ip]
                packet.accept()
                verdict_given = True

    if not verdict_given:
        packet.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(1, inspect) 
try:
    print "Netcreeper running..."
    nfqueue.run()
except KeyboardInterrupt:
    print info
    pass
