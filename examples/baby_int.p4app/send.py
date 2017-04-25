import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send
from scapy.all import Packet
from scapy.all import Ether, IP, UDP
from scapy.all import IntField, FieldListField


class MRI(Packet):
    name = "MRI"
    fields_desc = [ IntField("count", 0),
                   FieldListField("swids", [], IntField("", 0),
                                    length_from=lambda pkt:pkt.count) ]
    # def post_build(self, p, pay):
    #     if self.count is None:
    #         self.count = len(self.swids)
            
    
def main():
    
    addr = socket.gethostbyname(sys.argv[1])

    pkt = Ether() / IP(dst=addr)/ UDP(dport=8000) / MRI(count=2, swids=[3,4]) / "hello"
    pkt.show()
    sendp(pkt, iface="en0")
    
    # values = (2, 5, 7)
    # packer = struct.Struct('> I I I')
    # packed_data = packer.pack(*values)

                                   
    # srv_addr = (sys.argv[1], int(sys.argv[2]))
    # sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 99)
    # sock.sendto(packed_data, srv_addr)

if __name__ == '__main__':
    main()
