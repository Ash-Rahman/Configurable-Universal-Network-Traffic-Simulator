#!/usr/bin/python

from scapy.all import *

from random import getrandbits
from ipaddress import IPv4Address, IPv6Address
import sys
import time
import subprocess

ether_1_addr = "90:e2:ba:aa:78:a8"
ether_2_addr = "90:e2:ba:aa:69:05"

complete_packet_list = []

def clear_complete_packet_list():
    global complete_packet_list
    complete_packet_list = []

def create_tcp_flow(number_of_flows):
    packet_list = []
    pktSeq1 = 1
    pktSeq2 = 1
    count = 0

    while (count < int(number_of_flows)):
        #ipv6Add = generate_ipv6_addr()
        ipv4Add1 = generate_ipv4_addr()
        ipv4Add2 = generate_ipv4_addr()

        # SYN message
        p=Ether(src=ether_1_addr, dst=ether_2_addr)/IP(src=ipv4Add1,dst=ipv4Add2)/TCP(sport=26,dport=40,flags='S',seq=0,ack=0)
        packet_list.extend(p)

        # SYN / ACK
        p=Ether(src=ether_2_addr, dst=ether_1_addr)/IP(src=ipv4Add2,dst=ipv4Add1)/TCP(sport=40,dport=26,flags='SA',seq=0, ack=1)
        packet_list.extend(p)

        # ACK message
        p=Ether(src=ether_1_addr, dst=ether_2_addr)/IP(src=ipv4Add1,dst=ipv4Add2)/TCP(sport=26,dport=40,flags='A',seq=1, ack=1)
        packet_list.extend(p)

        # PSH / ACK message
        p=Ether(src=ether_1_addr, dst=ether_2_addr)/IP(src=ipv4Add1,dst=ipv4Add2)/TCP(sport=26,dport=40,flags='PA',seq=pktSeq1)/Raw(RandString(size=1))
        packet_list.extend(p)
        pktSeq1 += count;

        # PSH / ACK message
        p=Ether(src=ether_2_addr, dst=ether_1_addr)/IP(src=ipv4Add2,dst=ipv4Add1)/TCP(sport=40,dport=26,flags='PA',seq=pktSeq2)/Raw(RandString(size=1))
        packet_list.extend(p)
        pktSeq2 += count;

        # FIN message
        p=Ether(src=ether_1_addr, dst=ether_2_addr)/IP(src=ipv4Add1,dst=ipv4Add2)/TCP(sport=26,dport=40,flags='F',seq=pktSeq1,ack=0)
        packet_list.extend(p)

        # FIN / ACK
        p=Ether(src=ether_2_addr, dst=ether_1_addr)/IP(src=ipv4Add2,dst=ipv4Add1)/TCP(sport=40,dport=26,flags='FA',seq=pktSeq2, ack=1)
        packet_list.extend(p)

        count += 1

    complete_packet_list.extend(packet_list)
    print("create packet: " + str(complete_packet_list))
    packet_list = []

def create_udp_flow(number_of_flows):
    packet_list = []
    count = 0

    while (count < int(number_of_flows)):
        ipv4Add1 = generate_ipv4_addr()
        ipv4Add2 = generate_ipv4_addr()

        p=Ether(src=ether_1_addr, dst=ether_2_addr)/IP(src=ipv4Add1,dst=ipv4Add2)/UDP(sport=26,dport=40)/Raw(RandString(size=1))
        packet_list.extend(p)

        p=Ether(src=ether_2_addr, dst=ether_1_addr)/IP(src=ipv4Add2,dst=ipv4Add1)/UDP(sport=40,dport=26)/Raw(RandString(size=1))
        packet_list.extend(p)

        count += 1

    complete_packet_list.extend(packet_list)
    packet_list = []

def play_pcap():
    #pcap = rdpcap('incremental_length_test.pcap')
    s = conf.L3socket(iface='enp3s0f0')
    for pkt in packet_list:
        s.send(pkt)

def play_via_tcpreplay(interface):
    print("\nPlaying pcap via tcpreplay")
    print("\nThis may take some time")
    command = subprocess.Popen(["tcpreplay", "-i", interface, "user_generated.pcap"], stdout=subprocess.PIPE)
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

def create_pcap_file():
    print ("\nCreating your Pcap, this may take some time...")
    print("user_traffic: " + str(complete_packet_list))

    if len(complete_packet_list) != 0:
        wrpcap("user_generated.pcap", complete_packet_list)
        clear_complete_packet_list()
        print ("\nPcap creation done!")
    else:
        print ("\nYou have not created any packets to save!")

'''
def make_pcap():
    t0 = time.time()
    makepcap()
    wrpcap("large_incremental_length_test.pcap", packet_list)
    t1 = time.time()
    print("Time taken to generate packets: " + str(t1 - t0))

    t2 = time.time()
    #play_pcap()
    play_via_tcpreplay()
    t3 = time.time()
    print("Time taken to play traffic: " + str(t3 - t2))
'''
