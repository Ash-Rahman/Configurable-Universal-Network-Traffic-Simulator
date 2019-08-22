#!/usr/bin/python

from scapy.all import *

from random import getrandbits
from ipaddress import IPv4Address, IPv6Address 
import sys
import time
import subprocess

pkts = []
#pkts=rdpcap("large_incremental_length_test.pcap")
count = 0

def makepcap():
    global pkts
    global count 
    pktSeq1 = 1
    pktSeq2 = 1
    count = 0
    iter = 0

    #ether_1_addr = "0a:01:01:01:01:01"
    #ether_2_addr = "0a:02:02:02:02:02"

    ether_1_addr = "90:e2:ba:aa:78:a8"
    ether_2_addr = "90:e2:ba:aa:69:05"

    while (count < 40000):

        ipv4Add1 = generate_ipv4_addr()
        ipv4Add2 = generate_ipv4_addr()

        #ipv4Add1 = "62.29.219.100"
        #ipv4Add2 = "73.34.151.185"
        ipv6Add = generate_ipv6_addr()

        # SYN message
        p=Ether(src=ether_1_addr, dst=ether_2_addr)/IP(src=ipv4Add1,dst=ipv4Add2)/TCP(sport=26,dport=40,flags='S',seq=0,ack=0)
        pkts.append(p)

        # SYN / ACK
        p=Ether(src=ether_2_addr, dst=ether_1_addr)/IP(src=ipv4Add2,dst=ipv4Add1)/TCP(sport=40,dport=26,flags='SA',seq=0, ack=1)
        pkts.append(p)

        # ACK message
        p=Ether(src=ether_1_addr, dst=ether_2_addr)/IP(src=ipv4Add1,dst=ipv4Add2)/TCP(sport=26,dport=40,flags='A',seq=1, ack=1)
        pkts.append(p)

        # Count must be even for the FIN sequence numbers to be correct

        # PSH / ACK message
        p=Ether(src=ether_1_addr, dst=ether_2_addr)/IP(src=ipv4Add1,dst=ipv4Add2)/TCP(sport=26,dport=40,flags='PA',seq=pktSeq1)/Raw(RandString(size=1))
        pkts.append(p)
        pktSeq1 += count;

        # PSH / ACK message
        p=Ether(src=ether_2_addr, dst=ether_1_addr)/IP(src=ipv4Add2,dst=ipv4Add1)/TCP(sport=40,dport=26,flags='PA',seq=pktSeq2)/Raw(RandString(size=1))
        pkts.append(p)
        pktSeq2 += count;
        
        # Add a print here - to display progress.

        # Increment UDP packets
        p=Ether(src=ether_1_addr, dst=ether_2_addr)/IP(src=ipv4Add1,dst=ipv4Add2)/UDP(sport=26,dport=40)/Raw(RandString(size=1))
        pkts.append(p)

        p=Ether(src=ether_2_addr, dst=ether_1_addr)/IP(src=ipv4Add2,dst=ipv4Add1)/UDP(sport=40,dport=26)/Raw(RandString(size=1))
        pkts.append(p)
        #iter += 1

        # FIN message
        p=Ether(src=ether_1_addr, dst=ether_2_addr)/IP(src=ipv4Add1,dst=ipv4Add2)/TCP(sport=26,dport=40,flags='F',seq=pktSeq1,ack=0)
        pkts.append(p)

        # FIN / ACK
        p=Ether(src=ether_2_addr, dst=ether_1_addr)/IP(src=ipv4Add2,dst=ipv4Add1)/TCP(sport=40,dport=26,flags='FA',seq=pktSeq2, ack=1)
        pkts.append(p)

        count += 1

def play_pcap():
    #pcap = rdpcap('incremental_length_test.pcap')
    print("Number of packets generated: " + str(len(pkts)))
    s = conf.L3socket(iface='enp3s0f0')
    for pkt in pkts:
        s.send(pkt)

def play_via_tcpreplay():
    print("Number of packets generated: " + str(len(pkts)))
    command = subprocess.Popen(["tcpreplay", "-i", "enp3s0f0", "large_incremental_length_test.pcap"], stdout=subprocess.PIPE)
    output = command.communicate()[0]

def generate_ipv4_addr():
    bits = getrandbits(32)
    addr = IPv4Address(bits)
    addr_str = str(addr)
    #print(addr_str)

    return addr_str

def generate_ipv6_addr():
    bits = getrandbits(128)
    addr = IPv6Address(bits)
    addr_str = addr.exploded
    #print(addr_str)

    return addr_str

def main():
    t0 = time.time()
    makepcap()
    wrpcap("large_incremental_length_test.pcap", pkts)
    t1 = time.time()
    print("Time taken to generate packets: " + str(t1 - t0))

    t2 = time.time()
    #play_pcap()
    play_via_tcpreplay()
    t3 = time.time()
    print("Time taken to play traffic: " + str(t3 - t2))
main()
#wrpcap("incremental_length_test.pcap", pkts)