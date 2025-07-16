from ctypes import *
import socket
import struct

# Define the IP Header class
class IP(Structure):
    _fields_ = [
        ("version", c_ubyte, 4),
        ("ihl", c_ubyte, 4),
        ("tos", c_ubyte, 8),
        ("len", c_ushort, 16),
        ("id", c_ushort, 16),
        ("offset", c_ushort, 16),
        ("ttl", c_ubyte, 8),
        ("protocol", c_ubyte, 8),
        ("sum", c_ushort, 16),
        ("src", c_uint, 32),
        ("dst", c_uint, 32)
    ]

    def __init__(self, socket_buffer=None):
        if socket_buffer:
            # Copy the raw data into the structure
            memmove(addressof(self), socket_buffer, sizeof(self))
            # Convert raw IP addresses to readable format
            self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
            self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))
            self.tos = self.tos
            self.ttl = self.ttl
            self.packet_length = self.len
            self.id = self.id

# Define the UDP Header class
class UDP(Structure):
    _fields_ = [
        ("src_port", c_ushort),
        ("dst_port", c_ushort),
        ("length", c_ushort),
        ("checksum", c_ushort)
    ]

    def __init__(self, socket_buffer=None):
        if socket_buffer:
            # Copy the raw data into the structure
            memmove(addressof(self), socket_buffer, sizeof(self))
            self.src_port = self.src_port
            self.dst_port = self.dst_port
            self.length = self.length
            self.checksum = self.checksum

# Define the TCP Header class
class TCP(Structure):
    _fields_ = [
        ("src_port", c_ushort),
        ("dst_port", c_ushort),
        ("seq", c_uint),
        ("ack", c_uint),
        ("offset_reserved_flags", c_ushort),
        ("window", c_ushort),
        ("checksum", c_ushort),
        ("urgent_ptr", c_ushort)
    ]

    def __init__(self, socket_buffer=None):
        if socket_buffer:
            # Copy the raw data into the structure
            memmove(addressof(self), socket_buffer, sizeof(self))
            self.src_port = self.src_port
            self.dst_port = self.dst_port
            self.seq = self.seq
            self.ack = self.ack
            self.offset_reserved_flags = self.offset_reserved_flags
            self.window = self.window
            self.checksum = self.checksum
            self.urgent_ptr = self.urgent_ptr

# Main function to handle the packet sniffing
def main():
    HOST = "0.0.0.0"

    try:
        # Create a raw socket to capture packets
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sniffer.bind((HOST, 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        print("Sniffer started. Listening for packets...")

        while True:
            raw_buffer = sniffer.recvfrom(65565)[0]

            # Parse the first 20 bytes of the packet as an IP header
            ip_header = IP(raw_buffer[:20])

            # Display IP Header Information
            print(f"Protocol: {ip_header.protocol} | Source: {ip_header.src_address} | Destination: {ip_header.dst_address}")
            print(f"Type of Service: {ip_header.tos} | TTL: {ip_header.ttl} | Packet Length: {ip_header.packet_length} | ID: {ip_header.id}")

            # Check the protocol field in the IP header to determine if it's TCP or UDP
            if ip_header.protocol == 6:  # TCP
                # Get the starting point of the TCP segment (after the IP header)
                tcp_header = TCP(raw_buffer[20:40])
                print(f"TCP Packet: Source Port: {tcp_header.src_port} | Destination Port: {tcp_header.dst_port}")
                print(f"Sequence Number: {tcp_header.seq} | Acknowledgment Number: {tcp_header.ack}")

            elif ip_header.protocol == 17:  # UDP
                # Get the starting point of the UDP segment (after the IP header)
                udp_header = UDP(raw_buffer[20:28])
                print(f"UDP Packet: Source Port: {udp_header.src_port} | Destination Port: {udp_header.dst_port}")
                print(f"Length: {udp_header.length}")

            print("-" * 50)

    except KeyboardInterrupt:
        print("\nExiting...")

# Entry point of the program
if __name__ == "__main__":
    main()
