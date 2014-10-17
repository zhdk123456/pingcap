pingcap
=======

Go (golang) based scanning of machines via ping and packet capture via pcap to get ethernet address

It works kind of like arpscan.  But not using ARP.

Instead:

1. send out pings to a range specified by CIDR (e.g. 192.168.0.0/24)
2. use pcap to capture incoming packets to learn source ethernet
3. return list of machines on discovered with IP and Ethernet addr