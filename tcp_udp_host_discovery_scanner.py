import ipaddress
import socket
import struct
import os
import sys
import threading
import time

# Subnet to scan
SUBNET = "192.168.1.0/24"
TCP_PORT = 80  # Commonly open port
UDP_PORT = 53  # Common UDP port (DNS)

# Magic message for UDP probe
MESSAGE = "PYTHONRULES!"

class IP:
    def __init__(self, buff):
        header = struct.unpack("<BBHHHBBH4s4s", buff)
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
        
        # Convert to readable IP
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

class ICMP:
    def __init__(self, buff):
        header = struct.unpack("<BBHHH", buff)
        self.type = header[0]
        self.code = header[1]

class TCP:
    def __init__(self, buff):
        header = struct.unpack("!HHLLBBHHH", buff)
        self.src_port = header[0]
        self.dst_port = header[1]
        self.seq = header[2]
        self.ack = header[3]
        self.offset_reserved_flags = header[4]
        self.flags = header[5]

class Scanner:
    def __init__(self, host):
        self.host = host
        self.host_up = set()

        if os.name == "nt":
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        self.socket.bind((host, 0))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        if os.name == "nt":
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    def sniff(self):
        try:
            while True:
                raw_buffer = self.socket.recvfrom(65535)[0]
                ip_header = IP(raw_buffer[0:20])
                
                # Process ICMP (For UDP discovery)
                if ip_header.protocol_num == 1:
                    offset = ip_header.ihl * 4
                    icmp_header = ICMP(raw_buffer[offset:offset + 8])
                    if icmp_header.type == 3 and icmp_header.code == 3:
                        tgt = str(ip_header.src_address)
                        if tgt != self.host and tgt not in self.host_up:
                            self.host_up.add(tgt)
                            print(f"Host up (UDP response): {tgt}")

                # Process TCP responses
                elif ip_header.protocol_num == 6:
                    offset = ip_header.ihl * 4
                    tcp_header = TCP(raw_buffer[offset:offset + 20])
                    tgt = str(ip_header.src_address)
                    
                    # SYN-ACK or RST means host is up
                    if tcp_header.flags in [0x12, 0x14]:
                        if tgt != self.host and tgt not in self.host_up:
                            self.host_up.add(tgt)
                            print(f"Host up (TCP SYN-ACK): {tgt}")

        except KeyboardInterrupt:
            if os.name == "nt":
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            print("\nUser interrupted. Summary:")
            for host in sorted(self.host_up):
                print(f"{host}")
            sys.exit()

def tcp_sender():
    for ip in ipaddress.ip_network(SUBNET).hosts():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((str(ip), TCP_PORT))
            if result == 0:
                print(f"Host up (TCP Connect): {ip}")
            sock.close()
        except:
            pass

def udp_sender():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for ip in ipaddress.ip_network(SUBNET).hosts():
            sender.sendto(bytes(MESSAGE, "utf8"), (str(ip), UDP_PORT))

if __name__ == "__main__":
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = "192.168.1.33"

    s = Scanner(host)
    time.sleep(2)

    # Start TCP and UDP sender threads
    t1 = threading.Thread(target=tcp_sender)
    t2 = threading.Thread(target=udp_sender)
    t1.start()
    t2.start()

    s.sniff()
