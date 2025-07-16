'''
This Python script is a simple network packet sniffer designed to capture raw packets on the network. 
'''

import socket
import os

# host to listen on
HOST = '192.168.1.36'

def main():
    print("hello")
    #create a raw socket, bin to public interface 
    if os.name == 'nt' :                                # Check if the OS is Windows
        socket_protocol = socket.IPPROTO_IP
    else:                                               # For non-Windows systems (e.g., Linux, macOS)
        socket_protocol = socket.IPPROTO_ICMP
    
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((HOST, 0))                         #Binds the socket to the specified IP address (HOST) and port 0. The port 0 means it is not binding to a specific port.
    #include the IP header in the capture
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == 'nt':                                         #On Windows, this enables promiscuous mode, allowing the program to capture 
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)      #all packets on the network, not just those addressed to the host.
        
    #read one packet
    print(sniffer.recvfrom(65565))

    #if we are on window turn off promicious mode 
    if os.name == 'nt':
        sniffer.ioctl(socket_SIO_RCVALL, socket_RCVALL_OFF)
    
if __name__ == '__main__':
    main()

'''
Note : Before run confirm that it run on both windows and kali if run on window so run as administrator and if run 
      on kali so used sudo


Output :
        python3 sniffer.py                         
hello
(b'E\x00\x00T\xe6{\x00\x00:\x01]\xd4h\x14\x12y\xc0\xa8\x01$\x00\x00\xf2>\x00\n\x00\x10\r\x90\x91g\x00\x00\x00\x00\xa5\xdc\n\x00\x00\
    x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f 
!"#$%&\'()*+,-./01234567', ('104.20.18.121', 0))
'''
