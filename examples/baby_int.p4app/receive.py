import socket, sys
import struct

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('', int(sys.argv[1])))

while True:
    try:
        data, addr = sock.recvfrom(1024)
    except KeyboardInterrupt:
        sock.close()
        break
    count = struct.unpack(">I", data[0:4])[0]
    print "count = %d" % count
    for i in range(1,count+1):
        lhs = 4 * i
        rhs = lhs+4
        swid = struct.unpack(">I", data[lhs:rhs])[0]
        print "    swid = %d" % swid
    lhs = 4 * count + 4
    load = data[lhs:]
    print "msg = %s" % load
    sys.stdout.flush()

    #print addr, data
    #sock.sendto(data, addr)
