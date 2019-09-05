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

def play_pcap(interface):
    print("\nPlaying pcap via tcpreplay")
    print("\nThis may take some time")
    s = conf.L3socket(iface=interface)
    pcap = rdpcap("user_generated.pcap")
    for pkt in pcap:
        s.send(pkt)
    print("\nDone!")

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
    if len(complete_packet_list) != 0:
        print ("\nCreating your Pcap, this may take some time...")
        #print("user_traffic: " + str(complete_packet_list))
        wrpcap("user_generated.pcap", complete_packet_list)
        clear_complete_packet_list()
        print ("\nPcap creation done!")
    else:
        print ("\nYou have not created any packets to save!")
