
from scapy.all import sniff, sendp
from scapy.all import Packet
from scapy.all import ShortField, IntField, LongField, BitField

import sys
import struct


# import socket, sys
# import struct

# sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# sock.bind(('', int(sys.argv[1])))

# while True:
#     try:
#         data, addr = sock.recvfrom(1024)
#     except KeyboardInterrupt:
#         sock.close()
#         break
#     count = struct.unpack(">I", data[0:4])[0]
#     print "count = %d" % count
#     for i in range(1,count+1):
#         lhs = 4 * i
#         rhs = lhs+4
#         swid = struct.unpack(">I", data[lhs:rhs])[0]
#         print "    swid = %d" % swid
#     lhs = 4 * count + 4
#     load = data[lhs:]
#     print "msg = %s" % load
#     sys.stdout.flush()

def handle_pkt(pkt):
    print "got a packet"
    #pkt = str(pkt)
    #print pkt
    sys.stdout.flush()


def main():
    print "sniffing on h2-eth0"
    sys.stdout.flush()
    sniff(iface = "h2-eth0",
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
