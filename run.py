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
    # set up logging to file - messages with level "DEBUG" or higher will be written to the file
    logging.basicConfig(filename='debugfile.log',
                        format='%(asctime)s| %(message)s', filemode='w', level=logging.DEBUG)
    logging.getLogger().setLevel(logging.INFO)
    console = logging.StreamHandler(sys.stdout)
    # add the hanlder to the root logger
    logging.getLogger('').addHandler(console)

    parser = OptionParser()
    parser.add_option(
        "-c",
        "--config",
        dest="config",
        help="Configuration JSON file",
        metavar="FILE",
        default="traffic_to_generate.json")

    (options, _) = parser.parse_args()

    if os.path.isfile(options.config):
        with open(options.config) as trafficConfiguration:
            configuration = json.load(trafficConfiguration)

            trafficProfile = configuration[0]['TrafficProfiles']
            profiles = len(configuration[0]['TrafficProfiles'])

            for profiles in trafficProfile:
                protocolType = profiles['ProtocolType']
                ipvType = profiles['IPVType']
                sourceAddress = profiles['SourceAddress']
                destAddress = profiles['DestAddress']
                sourcePort = profiles['SourcePort']
                destPort = profiles['DestPort']
                packetSize = profiles['PacketSize']
                numberOfFlows = profiles['NumberOfFlows']

                print str((ipvType, sourceAddress, destAddress, sourcePort, destPort, packetSize, numberOfFlows))
                if protocolType == "TCP":
                    create_packet.create_tcp_flow(ipvType, sourceAddress, destAddress, sourcePort, destPort, packetSize, numberOfFlows)
                elif protocolType == "UDP":
                    create_packet.create_udp_flow(ipvType, sourceAddress, destAddress, sourcePort, destPort, packetSize, numberOfFlows)

            

if __name__ == "__main__":
    main()