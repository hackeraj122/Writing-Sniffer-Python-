'''
This code is a simple packet sniffer in Python, designed to capture and process raw IP packets over the network. by using struct module
'''

import ipaddress                #Provides a convenient way to handle and manipulate IP addresses, making it easier to display human-readable IP addresses.
import struct                   #Used to unpack binary data into Python data structures. Essential for extracting fields from raw packet headers.
import socket                   #Provides low-level networking interfaces, enabling raw socket programming to capture packets.

class IP:
    def __init__(self, buff=None):
        header = struct.unpack('<BBHHHBBH4s4s', buff)       # Unpacks the first 20 bytes of the buffer using the format string <BBHHHBBH4s4s
        self.ver = header[0] >> 4                           #Extracts the first 4 bits for the version.
        self.ihl = header[0] & 0x0F                         #Extracts the last 4 bits for the header length.

        self.tos = header[1]                        #Extracts the "Type of Service" field, which specifies the priority and quality of service for the packet.
        self.len = header[2]                        # Extracts the "Total Length" field, which indicates the entire length of the IP packet (header + data).      
        self.id = header[3]                         # Extracts the "Identification" field, used for uniquely identifying the packet.
        self.offset = header[4]                     # Extracts the "Fragment Offset" field, which determines the position of this packet fragment in the original data
        self.ttl = header[5]                        # Extracts the "Time to Live" field, which limits the packet's lifespan by reducing the value by 1 at each hop
        self.protocol_num = header[6]               # Extracts the "Protocol" field, indicating the protocol type used in the payload (e.g., ICMP, TCP, UDP)
        self.sum = header[7]                        # Extracts the "Header Checksum," used for error-checking the IP header
        self.src = header[8]                        # Extracts the source and destination IP addresses in binary format.
        self.dst = header[9]
         
        # human readable IP address 
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        #map protocol constants to theire names
        self.protocol_map = {1: 'ICMP', 6: "TCP", 17: "UDP"}

def main():
    host = '0.0.0.0'
    try :
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sniffer.bind((host, 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        print("Sniffer started listening for packets.....")

        while True:
            raw_buffer = sniffer.recvfrom(65565)[0]
            ip_header = IP(raw_buffer[:20])
            print(f" Source: {ip_header.src_address} | Destination: {ip_header.dst_address}")
    

    except KeyboardInterrupt :
        print("\n exiting")

if __name__ == '__main__':
    main()

''' 
   Note: Before execution code ping any target
   cmd>> ping google.com

   Output:
    python3 struct_module.py
    Sniffer started listening for packets.....
    Source: 142.251.42.46 | Destination: 192.168.1.33
    Source: 142.251.42.46 | Destination: 192.168.1.33
    Source: 142.251.42.46 | Destination: 192.168.1.33
    Source: 142.251.42.46 | Destination: 192.168.1.33

    '''
