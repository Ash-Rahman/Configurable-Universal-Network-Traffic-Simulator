#!/usr/bin/python
from scapy.all import *

import argparse
import sys, os
import create_packet
import numbers

pkts = []

header = "\
___________              _____  _____.__           ________                                   __                \n\
\__    ___/___________ _/ ____\/ ____\__| ____    /  _____/  ____   ____   ________________ _/  |_  ___________ \n\
  |    |  \_  __ \__  \    __\    __\|  |/ ___\  /   \  ____/ __ \ /    \_/ __ \_  __ \__  \    __\/  _ \_  __ \ \n\
  |    |   |  | \// __ \|  |   |  |  |  \  \___  \    \_\  \  ___/|   |  \  ___/|  | \// __ \|  | (  <_> )  | \/ \n\
  |____|   |__|  (____  /__|   |__|  |__|\___  >  \______  /\___  >___|  /\___  >__|  (____  /__|  \____/|__|   \n\
                      \/                     \/          \/     \/     \/     \/           \/                   \n"
def create_pcap():
    global pkts

    print "You selected: Create pcap!"
    choice = input("""  A: Create TCP flow
                        B: Create UDP flow
                        C: Save PCAP
                        D: Return to main menu
                        Please enter your choice: """)
    if choice == "A" or choice =="a":
        number_of_TCP_flows = raw_input("Enter number of TCP flows")
        if number_of_TCP_flows.isdigit():
            tcp_flow = create_packet.create_tcp_flow(number_of_TCP_flows)
            pkts.append(tcp_flow)
            print "this is pkts print 1:" pkts
            print "TCP flow created, remember to save the pcap!"
            create_pcap()
        else:
            print "Please Enter a valid number!"
            create_pcap()
    elif choice == "B" or choice =="b":
        number_of_UDP_flows = raw_input("Enter number of UDP flows")
        if number_of_UDP_flows.isdigit():
            udp_flow = create_packet.create_udp_flow(number_of_UDP_flows)
            pkts.append(udp_flow)
            print "UDP flow created, remember to save the pcap!"
            create_pcap()
        else:
            print "Please Enter a valid number!"
            create_pcap()
    elif choice == "C" or choice =="c":
        print "Creating your Pcap, this may take some time..."
        create_packet.create_pcap_file(pkts)
        print "Pcap creation done!"
        pkts = []
    elif choice == "D" or choice =="d":
        pkts = []
        display_menu_screen()
    else:
        print("You must only select either A, B or C")
        print("Please try again")
    create_pcap()
    #raw_input("Press [Enter] to continue...")


def select_pcap():
    print "You called select_pcap()"
    #raw_input("Press [Enter] to continue...")

def play_pcap():
    print "You called play_pcap()"
    create_packet.play_via_tcpreplay()
    #raw_input("Press [Enter] to continue...")

def display_menu_screen():
    os.system('clear')
    # Print some badass ascii art header here !
    print (header)
    print "version 0.1\n"

    choice = input("""
                      A: Create Pcap
                      B: Play Pcap
                      Q: Quit/Log Out

                      Please enter your choice: """)

    if choice == "A" or choice =="a":
        create_pcap()
    elif choice == "B" or choice =="b":
        play_pcap()
    elif choice=="Q" or choice=="q":
        sys.exit
    else:
        print("You must only select either A or B")
        print("Please try again")
        display_menu_screen()

def main():
    while True:
        display_menu_screen()

if __name__ == "__main__":
    main()
