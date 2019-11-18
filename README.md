TO USE:

    1. Open traffic_to_generate.json and edit options.
    2. ./run.py

    You can use parameter -c to point at a different json file. 

Available traffic options:

	ProtocolType: TCP, UDP. #TODO: Add additional protocol types.
    IPVType: 4, 6.
    SourceAddress: Enter the IP address you want to use for a source address - use "random" to randomly generate an IP addresses, or type in a valid address.
    DestAddress: Enter the IP address you want to use for a destination address - use "random" to randomly generate an IP addresses, or type in a valid address.
    SourcePort: A port number between 1 and 65535.
    DestPort: A port number between 1 and 65535.
    PacketSize: A size up to 9000.
    NumberOfFlows: Enter how many complete flows you want of that traffic profile.

Network interface options:

    FirstInterface: Enter the network interface name that you want to tramsit traffic out of - enp1s0f1.
    #TODO: Allow use of second interface.

Pcap options:

    SaveThePcap: Select if you want a pcap saved from the generated traffic - True, False.
    PcapName: Enter the name of the pcap - udp_flows.pcap
