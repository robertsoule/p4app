import argparse
import sys
import socket
import random
import struct


def main():

    addr = socket.gethostbyname(sys.argv[1])

    values = (2, 1, 2)
    packer = struct.Struct('> I I I')
    packed_data = packer.pack(*values)

                                   
    srv_addr = (sys.argv[1], int(sys.argv[2]))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 99)
    sock.sendto(packed_data + "hello", srv_addr)

if __name__ == '__main__':
    main()
