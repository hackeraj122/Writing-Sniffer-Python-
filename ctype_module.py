'''
The purpose of this code is to create a packet sniffer that listens for network packets on the machine and extracts 
specific details from the IP headers of the captured packets. Here's a breakdown of the main functionality:
'''

from ctypes import *
import socket
import struct

# Define a class to represent the structure of an IP header
class IP(Structure):
    # Define the fields of the IP header using ctypes
    _fields_ = [
        ("version",     c_ubyte,    4),  # 4-bit field: IP version (IPv4/IPv6)
        ("ihl",         c_ubyte,    4),  # 4-bit field: Internet Header Length
        ("tos",         c_ubyte,    8),  # 8-bit field: Type of Service
        ("len",         c_ushort,   16), # 16-bit field: Total length of the packet
        ("id",          c_ushort,   16), # 16-bit field: Packet identifier
        ("offset",      c_ushort,   16), # 16-bit field: Fragment offset
        ("ttl",         c_ubyte,    8),  # 8-bit field: Time-to-Live (TTL)
        ("protocol",    c_ubyte,    8),  # 8-bit field: Protocol (e.g., TCP, UDP, ICMP)
        ("sum",         c_ushort,   16), # 16-bit field: Header checksum
        ("src",         c_uint,     32), # 32-bit field: Source IP address
        ("dst",         c_uint,     32)  # 32-bit field: Destination IP address
    ]

    # Method to create a new instance of the IP class from raw binary data
    def __new__(cls, socket_buffer=None):
        return cls.from_buffer_copy(socket_buffer)

    # Method to initialize additional attributes after creating the object
    def __init__(self, socket_buffer=None):
        # Convert the source IP address from raw bytes to human-readable format
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        # Convert the destination IP address from raw bytes to human-readable format
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))
        self.tos = self.tos
        # TTL is already a single byte integer, no need to convert to IP format
        self.ttl = self.ttl
        self.packet_length = self.len
        self.id = self.id
        self.protocol=self.protocol

# Main function to handle the packet sniffing
def main():
    # Set the host to 0.0.0.0 to listen on all network interfaces
    HOST = "0.0.0.0"

    try:
        # Create a raw socket to capture packets
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        
        # Bind the socket to the specified host and port 0 (no specific port)
        sniffer.bind((HOST, 0))

        # Set socket option to include IP headers in the captured packets
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        print("Sniffer started. Listening for packets...")

        # Infinite loop to keep capturing packets
        while True:
            # Receive raw packet data (up to 65565 bytes)
            raw_buffer = sniffer.recvfrom(65565)[0]

            # Parse the first 20 bytes of the packet as an IP header
            ip_header = IP(raw_buffer[:20])

            # Print the protocol, source, and destination of the captured packet
            print(f"Protocol: {ip_header.protocol} | Source: {ip_header.src_address} | Destination: {ip_header.dst_address}")
            #print(f"Type of Service: {ip_header.tos}, TTL: {ip_header.ttl}, Packet Length: {ip_header.packet_length} ,{ip_header.protocol}")

    # Handle keyboard interruption (Ctrl+C) to exit the program gracefully
    except KeyboardInterrupt:
        print("\nExiting...")

# Entry point of the program
if __name__ == "__main__":
    main()

'''

Note: Before execution of this program ping any target for showing result

Output:

┌──(kali㉿kali)-[~]
└─$ ping google.com                                                                                                                                                                                                                         
PING google.com (142.251.42.14) 56(84) bytes of data.
64 bytes from bom12s19-in-f14.1e100.net (142.251.42.14): icmp_seq=1 ttl=117 time=7.09 ms
64 bytes from bom12s19-in-f14.1e100.net (142.251.42.14): icmp_seq=2 ttl=117 time=8.01 ms
64 bytes from bom12s19-in-f14.1e100.net (142.251.42.14): icmp_seq=3 ttl=117 time=8.43 ms
64 bytes from bom12s19-in-f14.1e100.net (142.251.42.14): icmp_seq=4 ttl=117 time=8.10 ms


Result:
    (root㉿kali)-[/home/kali]
└─# python3 ctype_module.py
Sniffer started. Listening for packets...
Protocol: 1 | Source: 142.251.42.14 | Destination: 192.168.1.33
Type of Service: 112, TTL: 117, Packet Length: 21504 ,1
Protocol: 1 | Source: 142.251.42.14 | Destination: 192.168.1.33
Type of Service: 112, TTL: 117, Packet Length: 21504 ,1
 
 '''
