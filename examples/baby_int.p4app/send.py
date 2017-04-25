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
            
    
def main():
    
    addr = socket.gethostbyname(sys.argv[1])
    iface = sys.argv[2]

    pkt = Ether() / IP(dst=addr, options = IPOption_MRI(count=2, swids=[3,4])) / UDP(dport=8000) / "hello"
    pkt.show()
    sendp(pkt, iface=iface)
    

if __name__ == '__main__':
    main()
