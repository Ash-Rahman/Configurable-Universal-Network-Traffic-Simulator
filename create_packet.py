#!/usr/bin/python

from scapy.all import *

from random import getrandbits
from ipaddress import IPv4Address, IPv6Address
import sys
import time
import subprocess
import logging

ether_1_addr = "90:e2:ba:aa:78:a8"
ether_2_addr = "90:e2:ba:aa:69:05"

complete_packet_list = []

"""
Purpose: Generates a tcp flow
parameters: number_of_flows (int) takes a number of flows to generate
Returns: N/A
"""
def create_tcp_flow(ipv_type, source_address, dest_address, source_port, dest_port, packet_size, number_of_flows):
    packet_list = []
    pktSeq1 = 1
    pktSeq2 = 1
    count = 0

    while (count < int(number_of_flows)):
        if ipv_type == 4:
            if check_if_ipaddress_is_random(source_address) == True:
                ipv_x_addr1 = generate_ipv4_addr()
            else:
                ipv_x_addr1 = source_address

            if check_if_ipaddress_is_random(dest_address) == True:
                ipv_x_addr2 = generate_ipv4_addr()
            else:
                ipv_x_addr2 = dest_address
        else:
            if check_if_ipaddress_is_random(source_address) == True:
                ipv_x_addr1 = generate_ipv6_addr()
            else:
                ipv_x_addr1 = source_address

            if check_if_ipaddress_is_random(dest_address) == True:
                ipv_x_addr2 = generate_ipv6_addr()
            else:
                ipv_x_addr2 = dest_address

        # SYN message
        p=Ether(src=ether_1_addr, dst=ether_2_addr)/IP(src=ipv_x_addr1,dst=ipv_x_addr2)/TCP(sport=source_port,dport=dest_port,flags='S',seq=0,ack=0)
        packet_list.extend(p)

        # SYN / ACK
        p=Ether(src=ether_2_addr, dst=ether_1_addr)/IP(src=ipv_x_addr2,dst=ipv_x_addr1)/TCP(sport=dest_port,dport=source_port,flags='SA',seq=0, ack=1)
        packet_list.extend(p)

        # ACK message
        p=Ether(src=ether_1_addr, dst=ether_2_addr)/IP(src=ipv_x_addr1,dst=ipv_x_addr2)/TCP(sport=source_port,dport=dest_port,flags='A',seq=1, ack=1)
        packet_list.extend(p)

        # PSH / ACK message
        p=Ether(src=ether_1_addr, dst=ether_2_addr)/IP(src=ipv_x_addr1,dst=ipv_x_addr2)/TCP(sport=source_port,dport=dest_port,flags='PA',seq=pktSeq1)/Raw(RandString(size=packet_size))
        packet_list.extend(p)
        pktSeq1 += count;

        # PSH / ACK message
        p=Ether(src=ether_2_addr, dst=ether_1_addr)/IP(src=ipv_x_addr2,dst=ipv_x_addr1)/TCP(sport=dest_port,dport=source_port,flags='PA',seq=pktSeq2)/Raw(RandString(size=packet_size))
        packet_list.extend(p)
        pktSeq2 += count;

        # FIN message
        p=Ether(src=ether_1_addr, dst=ether_2_addr)/IP(src=ipv_x_addr1,dst=ipv_x_addr2)/TCP(sport=source_port,dport=dest_port,flags='F',seq=pktSeq1,ack=0)
        packet_list.extend(p)

        # FIN / ACK
        p=Ether(src=ether_2_addr, dst=ether_1_addr)/IP(src=ipv_x_addr2,dst=ipv_x_addr1)/TCP(sport=dest_port,dport=source_port,flags='FA',seq=pktSeq2, ack=1)
        packet_list.extend(p)

        count += 1

    complete_packet_list.extend(packet_list)
    logging.info("Full TCP packet list: " + str(complete_packet_list))

    packet_list = []

"""
Purpose: Generates a udp flow
parameters: number_of_flows (int) takes a number of flows to generate
Returns: N/A
"""
def create_udp_flow(ipv_type, source_address, dest_address, source_port, dest_port, packet_size, number_of_flows):
    packet_list = []
    count = 0

    while (count < int(number_of_flows)):
        if ipv_type == 4:
            if check_if_ipaddress_is_random(source_address) == True:
                ipv_x_addr1 = generate_ipv4_addr()
            else:
                ipv_x_addr1 = source_address

            if check_if_ipaddress_is_random(dest_address) == True:
                ipv_x_addr2 = generate_ipv4_addr()
            else:
                ipv_x_addr2 = dest_address
        else:
            if check_if_ipaddress_is_random(source_address) == True:
                ipv_x_addr1 = generate_ipv6_addr()
            else:
                ipv_x_addr1 = source_address

            if check_if_ipaddress_is_random(dest_address) == True:
                ipv_x_addr2 = generate_ipv6_addr()
            else:
                ipv_x_addr2 = dest_address

        p=Ether(src=ether_1_addr, dst=ether_2_addr)/IP(src=ipv_x_addr1,dst=ipv_x_addr2)/UDP(sport=source_port,dport=dest_port)/Raw(RandString(size=packet_size))
        packet_list.extend(p)

        p=Ether(src=ether_2_addr, dst=ether_1_addr)/IP(src=ipv_x_addr2,dst=ipv_x_addr1)/UDP(sport=dest_port,dport=source_port)/Raw(RandString(size=packet_size))
        packet_list.extend(p)

        count += 1

    complete_packet_list.extend(packet_list)
    logging.info("Full UDP packet list: " + str(complete_packet_list))

    packet_list = []

"""
Purpose: Transmits pcap file through interface
parameters: interface (string) takes a network interface name
Returns: N/A
"""
def transmit_traffic(interface, traffic_source, optional_pcap_name=""):
    try:
        if traffic_source == "pcap":
            pcap = rdpcap(optional_pcap_name)
            print("\nPlaying traffic from " + optional_pcap_name)
        else:
            pcap = complete_packet_list
            print("\nPlaying traffic from application memory")

        s = conf.L3socket(iface=interface)
        for pkt in pcap:
            s.send(pkt)
    except IOError as IOerror:
        print("\nERROR: " + str(IOerror))
    else:
        print("\nDone!")

"""
Purpose: Generate a random ipv4 address
parameters: N/A
Returns: (string) Ipv4 address
"""
def generate_ipv4_addr():
    bits = getrandbits(32)
    addr = IPv4Address(bits)
    addr_str = str(addr)

    return addr_str

"""
Purpose: Generate a random ipv6 address
parameters: N/A
Returns: (string) Ipv6 address
"""
def generate_ipv6_addr():
    bits = getrandbits(128)
    addr = IPv6Address(bits)
    addr_str = str(addr.exploded)

    return addr_str

"""
Purpose: Take array of flows and write to pcap.
parameters: N/A
Returns: N/A
"""
def create_pcap_file(filename):
    if len(complete_packet_list) != 0:
        print ("\nCreating your Pcap, this may take some time...")
        wrpcap(filename, complete_packet_list)
        clear_complete_packet_list()
        print ("\nFile " + filename + " created!")
    else:
        print ("\nYou have not created any packets to save!")

"""
Purpose: Clears the array of packets once the generated flows have been saved to pcap
parameters: N/A
Returns: N/A
"""
def clear_complete_packet_list():
    global complete_packet_list
    complete_packet_list = []

def check_if_ipaddress_is_random(ipAddress):
    if ipAddress == "random":
        return True
    else:
        return False