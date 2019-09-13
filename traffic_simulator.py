#!/usr/bin/python

import argparse
import sys, os
import create_packet
import numbers
import time
import string


header = "\
___________              _____  _____.__           ________                                   __                \n\
\__    ___/___________ _/ ____\/ ____\__| ____    /  _____/  ____   ____   ________________ _/  |_  ___________ \n\
  |    |  \_  __ \__  \    __\    __\|  |/ ___\  /   \  ____/ __ \ /    \_/ __ \_  __ \__  \    __\/  _ \_  __ \ \n\
  |    |   |  | \// __ \|  |   |  |  |  \  \___  \    \_\  \  ___/|   |  \  ___/|  | \// __ \|  | (  <_> )  | \/ \n\
  |____|   |__|  (____  /__|   |__|  |__|\___  >  \______  /\___  >___|  /\___  >__|  (____  /__|  \____/|__|   \n\
                      \/                     \/          \/     \/     \/     \/           \/                   \n"
def create_traffic_menu():
    print ("\nYou selected: Create traffic!")
    choice1 = raw_input("""  
                A: Create TCP flow
                B: Create UDP flow
                C: Save PCAP
                D: Return to main menu
                Please enter your choice: """)

    if choice1 == "A" or choice1 =="a":
        number_of_TCP_flows = raw_input("\nEnter number of TCP flows: ")
        ipv_type = raw_input("\nEnter IPV type (4/6): ")
        if number_of_TCP_flows.isdigit() and ipv_type.isdigit():
            create_packet.create_tcp_flow(number_of_TCP_flows, ipv_type)
            create_traffic_menu()
        else:
            print ("\nPlease Enter a valid number of flows and IPV(4/6) type!")
            create_traffic_menu()

    elif choice1 == "B" or choice1 =="b":
        number_of_UDP_flows = raw_input("\nEnter number of UDP flows: ")
        ipv_type = raw_input("\nEnter IPV type (4/6): ")
        if number_of_UDP_flows.isdigit() and ipv_type.isdigit():
            create_packet.create_udp_flow(number_of_UDP_flows, ipv_type)
            create_traffic_menu()
        else:
            print ("\nPlease Enter a valid number of flows and IPV(4/6) type!")
            create_traffic_menu()

    elif choice1 == "C" or choice1 =="c":
        filename = raw_input("\nEnter filename (e.g tcp_flow.pcap): ")
        if not filename and not filename.strip():
            print("\nEnter valid filename (Only Letters and numbers followed by .pcap)")
        else:
            create_packet.create_pcap_file(filename)
        create_traffic_menu()

    elif choice1 == "D" or choice1 =="d":
        os.system('clear')
        display_menu_screen()

    else:
        print("\nYou must only select either A, B or C")
        print("\nPlease try again")
    create_traffic_menu()

def play_traffic():
    print ("\nYou selected: Play pcap! ")
    print ("\nHere is a list of available interfaces!\n ")
    os.system('ifconfig')
    print ("\nYou can play traffic from either a pcap or what was created in the create traffic menu.\n ")
    interface = raw_input("\nEnter interface to play pcap out of: ")
    traffic_source = raw_input("\nEnter [1] to play traffic from pcap \nEnter [2] to play traffic from application")

    if int(traffic_source) == 1:
        print ("\nList of available pcaps: \n")
        os.system('ls pcaps/')
        pcap = raw_input("\nEnter name of pcap to transmit: ")
        create_packet.transmit_traffic(interface, traffic_source, pcap)
    else:
        create_packet.transmit_traffic(interface, traffic_source)
    display_menu_screen()

def display_menu_screen():
    print(header)
    print("version 0.1\n")

    choice = raw_input("""
                A: Create Traffic
                B: Play Traffic
                Q: Quit

                Please enter your choice: """)

    if choice == "A" or choice == "a":
        create_traffic_menu()
    elif choice == "B" or choice == "b":
        play_traffic()
    elif choice== "Q" or choice== "q":
        sys.exit()
    else:
        print("You must only select either A or B")
        print("Please try again")
        display_menu_screen()

def main():
    os.system('clear')
    while True:
        display_menu_screen()

if __name__ == "__main__":
    main()
