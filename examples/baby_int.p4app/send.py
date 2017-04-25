import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send
from scapy.all import Packet, IPOption
from scapy.all import Ether, IP, UDP
from scapy.all import IntField, FieldListField, FieldLenField, ShortField
from scapy.layers.inet import _IPOption_HDR

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count) ]
    # def post_build(self, p, pay):
    #     if self.count is None:
    #         self.count = len(self.swids)
            
    
def main():
    
    addr = socket.gethostbyname(sys.argv[1])

    pkt = Ether() / IP(dst=addr, options = IPOption_MRI(count=2, swids=[3,4])) / UDP(dport=8000) / "hello"
    pkt.show()
    sendp(pkt, iface="en0")
    

if __name__ == '__main__':
    main()
