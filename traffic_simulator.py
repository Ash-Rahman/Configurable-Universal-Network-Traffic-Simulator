#!/usr/bin/python
from scapy.all import *

import argparse
import sys, os
import create_packet

header = "\
___________              _____  _____.__           ________                                   __                \n\
\__    ___/___________ _/ ____\/ ____\__| ____    /  _____/  ____   ____   ________________ _/  |_  ___________ \n\
  |    |  \_  __ \__  \    __\    __\|  |/ ___\  /   \  ____/ __ \ /    \_/ __ \_  __ \__  \    __\/  _ \_  __ \ \n\
  |    |   |  | \// __ \|  |   |  |  |  \  \___  \    \_\  \  ___/|   |  \  ___/|  | \// __ \|  | (  <_> )  | \/ \n\
  |____|   |__|  (____  /__|   |__|  |__|\___  >  \______  /\___  >___|  /\___  >__|  (____  /__|  \____/|__|   \n\
                      \/                     \/          \/     \/     \/     \/           \/                   \n"
 
colors = {
        'blue': '\033[94m',
        'pink': '\033[95m',
        'green': '\033[92m',
        }
 
def colorize(string, color):
    if not color in colors: return string
    return colors[color] + string + '\033[0m'
 
def create_pcap():
    print "You called create_pcap()"
    create_packet.makepcap()
    raw_input("Press [Enter] to continue...")
 
def select_pcap():
    print "You called select_pcap()"
    raw_input("Press [Enter] to continue...")

def play_pcap():
    print "You called play_pcap()"
    create_packet.play_via_tcpreplay()
    raw_input("Press [Enter] to continue...")

menuItems = [
    { "Create pcap": create_pcap },
    { "Play selected pcap": select_pcap },
    { "Select network interface to transmit packets": play_pcap },
    { "Exit": exit },
]

def init_menu_screen():
    os.system('clear')
    # Print some badass ascii art header here !
    print colorize(header, 'pink')
    print colorize('version 0.1\n', 'green')

def main():
    while True:
        init_menu_screen()
        for item in menuItems:
            print colorize("[" + str(menuItems.index(item)) + "] ", 'blue') + item.keys()[0]
        choice = raw_input(">> ")
        try:
            if int(choice) < 0 : raise ValueError
            # Call the matching function
            menuItems[int(choice)].values()[0]()
        except (ValueError, IndexError):
            pass
 
if __name__ == "__main__":
    main()
