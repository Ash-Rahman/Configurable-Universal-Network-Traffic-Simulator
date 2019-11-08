#!/usr/bin/python

import sys
import os
import time
import json
import logging
import errno
import threading
import traceback
import datetime

import create_packet

from optparse import OptionParser

def main():
    parser = OptionParser()
    parser.add_option(
        "-c",
        "--config",
        dest="config",
        help="Configuration JSON file",
        metavar="FILE",
        default="traffic_to_generate.json")

    (options, _) = parser.parse_args()
    print "HELLO"
    if os.path.isfile(options.config):
        with open(options.config) as trafficConfiguration:
            configuration = json.load(trafficConfiguration)

            numberOfTrafficProfiles = len(configuration["TrafficProfiles"])
            #allProfiles = configuration["TrafficProfiles"]
            profile = configuration["TrafficProfiles"]["TrafficProfile"]

            print("profile: " + profile)
            print("numOfProf: " + numberOfTrafficProfiles)
            for profile in numberOfTrafficProfiles:
                protocolType = profile["ProtocolType"]
                ipvType = profile["IPVType"]
                sourceAddress = profile["SourceAddress"]
                destAddress = profile["DestAddress"]
                sourcePort = profile["SourcePort"]
                destPort = profile["DestPort"]
                packetSize = profile["PacketSize"]
                numberOfFlows = profile["NumberOfFlows"]

                print (ipvType, sourceAddress, destAddress, sourcePort, destPort, packetSize, numberOfFlows)
                if protocolType == "TCP":
                    create_packet.create_tcp_flow(ipvType, sourceAddress, destAddress, sourcePort, destPort, packetSize, numberOfFlows)
                elif protocolType == "UDP":
                    create_packet.create_udp_flow(ipvType, sourceAddress, destAddress, sourcePort, destPort, packetSize, numberOfFlows)
