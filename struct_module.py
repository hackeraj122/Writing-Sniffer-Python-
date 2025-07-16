
import ipaddress
import struct
import socket

class IP:
    def __init__(self, buff=None):
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4
        self.ihl = header[0] 

        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
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

    
