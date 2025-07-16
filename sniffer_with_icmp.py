'''
This code implements a basic network packet sniffer that listens for and processes ICMP packets.
'''

import ipaddress
import struct
import os
import socket
import sys 

class IP:
    def __init__(self, buff=None):
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0x0F
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # Human-readable IP addresses
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # Map protocol constants to their names
        self.protocol_map = {1: 'ICMP', 6: "TCP", 17: "UDP"}
        self.protocol = self.protocol_map.get(self.protocol_num, f"Unknown ({self.protocol_num})")

class ICMP:
    def __init__(self, buff=None):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]


def main():
    host = '0.0.0.0'
    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sniffer.bind((host, 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        print("Sniffer started listening for packets.....")

        while True:
            raw_buffer = sniffer.recvfrom(65565)[0]
            ip_header = IP(raw_buffer[:20])
            # print(f" Source: {ip_header.src_address} | Destination: {ip_header.dst_address} | Protocol: {ip_header.protocol}")
            # if it's ICMP , we want it
            if ip_header.protocol == "ICMP":
                print("Procotol: %s %s -> %s" %(ip_header.protocol, ip_header.src_address, ip_header.dst_address))
                print(f"Version: {ip_header.ver}")
                print(f'Header Length : {ip_header.ihl} TTL : {ip_header.ttl}')

                # calculate where our ICMP start 
                offset = ip_header.ihl * 4              #This tells us where the actual data of the packet (like the ICMP data) starts, because the IP header comes before the data.
                buf = raw_buffer[offset:offset + 8]     #Now that we know where the IP header ends (from the offset), we extract the next part of the packet, which is the ICMP header.
                
                #create our ICMP structure 
                icmp_header = ICMP(buf)
                print('ICMP -> Type: %s Code: %s\n '%(icmp_header.type, icmp_header.code))


    except KeyboardInterrupt:
        print("\nExiting")

if __name__ == '__main__':
    main()



'''
Note : before run code ping any target

Output:
        ──(venv3)─(root㉿kali)-[/home/kali]
        └─# python3 sniffer_with_icmp.py
        Sniffer started listening for packets.....
        Procotol: ICMP 142.251.42.14 -> 192.168.1.33
        Version: 4
        Header Length : 5 TTL : 117
        ICMP -> Type: 0 Code: 0
        
        Procotol: ICMP 142.251.42.14 -> 192.168.1.33
        Version: 4
        Header Length : 5 TTL : 117
        ICMP -> Type: 0 Code: 0

'''
