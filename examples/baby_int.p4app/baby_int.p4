
#include <core.p4>
#include <v1model.p4>

const bit<8>  UDP_PROTOCOL = 0x11;
const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
 *********************** H E A D E R S  ***********************************
 *************************************************************************/

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

header babyint_t {
    bit<8>  count;
}

header switch_t {
    bit<8>  swid;
}

struct ingress_metadata_t {
    bit<32> nhop_ipv4;
}

struct parser_metadata_t {
    bit<8>  remaining;
}

struct metadata {
  ingress_metadata_t   ingress_metadata;
  parser_metadata_t   parser_metadata;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    babyint_t    babyint;
    switch_t[10] swids;
}

/*************************************************************************
 *********************** P A R S E R  ***********************************
 *************************************************************************/

parser ParserImpl(packet_in packet,
       		  out headers hdr,
		  inout metadata meta,
		  inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
	transition accept;
	// transition select(hdr.ipv4.protocol) {
        //     UDP_PROTOCOL : parse_udp;
        //     default: accept;
        // }

    }
    
    state parse_udp {
        packet.extract(hdr.udp);
	transition accept;
    }

    state parse_babyint {
         packet.extract(hdr.babyint);
	 meta.parser_metadata.remaining = hdr.babyint.count;
         transition select(hdr.babyint.count) {
             0 : accept;
             default: parse_swid;
	 }
    }

    state parse_swid {
         packet.extract(hdr.swids.next);
	 meta.parser_metadata.remaining = meta.parser_metadata.remaining  - 1;
         transition select(meta.parser_metadata.remaining) {
             0 : accept;
             default: parse_swid;
	 }
    }
    
}


/*************************************************************************
 ************   C H E C K S U M    V E R I F I C A T I O N   *************
 *************************************************************************/

control verifyChecksum(in headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("_drop") action _drop() {
        mark_to_drop();
    }
    @name("add_int") action add_int() {
      hdr.babyint.count = hdr.babyint.count + 1;
      hdr.swids.push_front(1);
      hdr.swids[0].swid = 50;
    }
    @name("set_nhop") action set_nhop(bit<32> nhop_ipv4, bit<9> port) {
        meta.ingress_metadata.nhop_ipv4 = nhop_ipv4;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
    }
    @name("set_dmac") action set_dmac(bit<48> dmac) {
        hdr.ethernet.dstAddr = dmac;
    }

    @name("ipv4_lpm") table ipv4_lpm {
        actions = {
            _drop;
            set_nhop;
            NoAction;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 1024;
        default_action = NoAction();
    }
    @name("forward") table forward {
        actions = {
            set_dmac;
            _drop;
            NoAction;
        }
        key = {
            meta.ingress_metadata.nhop_ipv4: exact;
        }
        size = 512;
        default_action = NoAction();
    }
    apply {
        if (hdr.ipv4.isValid()) {
          ipv4_lpm.apply();
          forward.apply();
        }
    }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("rewrite_mac") action rewrite_mac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }
    @name("_drop") action _drop() {
        mark_to_drop();
    }
    @name("send_frame") table send_frame {
        actions = {
            rewrite_mac;
            _drop;
            NoAction;
        }
        key = {
            standard_metadata.egress_port: exact;
        }
        size = 256;
        default_action = NoAction();
    }
    apply {
        if (hdr.ipv4.isValid()) {
          send_frame.apply();
        }
    }
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/
 
control computeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
 ***********************  D E P A R S E R  *******************************
 *************************************************************************/

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        //packet.emit(hdr.udp);
	//packet.emit(hdr.babyint);
	//packet.emit(hdr.swids);			
    }
}

/*************************************************************************
 ***********************  S W I T C H  *******************************
 *************************************************************************/

V1Switch(
 ParserImpl(),
 verifyChecksum(),
 ingress(),
 egress(),
 computeChecksum(),
 DeparserImpl()
 ) main;
