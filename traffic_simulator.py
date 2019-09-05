#!/usr/bin/python

import argparse
import sys, os
import create_packet
import numbers
import time


header = "\
___________              _____  _____.__           ________                                   __                \n\
\__    ___/___________ _/ ____\/ ____\__| ____    /  _____/  ____   ____   ________________ _/  |_  ___________ \n\
  |    |  \_  __ \__  \    __\    __\|  |/ ___\  /   \  ____/ __ \ /    \_/ __ \_  __ \__  \    __\/  _ \_  __ \ \n\
  |    |   |  | \// __ \|  |   |  |  |  \  \___  \    \_\  \  ___/|   |  \  ___/|  | \// __ \|  | (  <_> )  | \/ \n\
  |____|   |__|  (____  /__|   |__|  |__|\___  >  \______  /\___  >___|  /\___  >__|  (____  /__|  \____/|__|   \n\
                      \/                     \/          \/     \/     \/     \/           \/                   \n"
def create_pcap_menu():
    print ("\nYou selected: Create pcap!")
    choice1 = raw_input("""  
                A: Create TCP flow
                B: Create UDP flow
                C: Save PCAP
                D: Return to main menu
                Please enter your choice: """)
    if choice1 == "A" or choice1 =="a":
        number_of_TCP_flows = raw_input("\nEnter number of TCP flows: ")
        if number_of_TCP_flows.isdigit():
            create_packet.create_tcp_flow(number_of_TCP_flows)
            print ("\nTCP flow created, remember to save the pcap!")
            create_pcap_menu()
        else:
            print ("\nPlease Enter a valid number!")
            create_pcap_menu()
    elif choice1 == "B" or choice1 =="b":
        number_of_UDP_flows = raw_input("\nEnter number of UDP flows: ")
        if number_of_UDP_flows.isdigit():
            create_packet.create_udp_flow(number_of_UDP_flows)
            print ("\nUDP flow created, remember to save the pcap!")
            create_pcap_menu()
        else:
            print ("\nPlease Enter a valid number!")
            create_pcap_menu()
    elif choice1 == "C" or choice1 =="c":
        create_packet.create_pcap_file()
        create_pcap_menu()
    elif choice1 == "D" or choice1 =="d":
        os.system('clear')
        display_menu_screen()
    else:
        print("\nYou must only select either A, B or C")
        print("\nPlease try again")
    create_pcap_menu()
    #raw_input("Press [Enter] to continue...")


def select_pcap():
    print ("You called select_pcap()")
    #raw_input("Press [Enter] to continue...")

def play_pcap():
    print ("\nYou selected: Play pcap! ")
    print ("\nHere is a list of available interfaces!\n ")
    os.system('ifconfig')
    interface = raw_input("\nEnter interface to play pcap out of: ")
    create_packet.play_pcap(interface)
    display_menu_screen()


def display_menu_screen():
    #os.system('clear')
    # Print some badass ascii art header here !
    print (header)
    print "version 0.1\n"

    choice = raw_input("""
                A: Create Pcap
                B: Play Pcap
                Q: Quit

                Please enter your choice: """)

    if choice == "A" or choice =="a":
        create_pcap_menu()
    elif choice == "B" or choice =="b":
        play_pcap()
    elif choice=="Q" or choice=="q":
        sys.exit()
    else:
        print("You must only select either A or B")
        print("Please try again")
        #display_menu_screen()

def main():
    os.system('clear')
    while True:
        display_menu_screen()

if __name__ == "__main__":
    main()
