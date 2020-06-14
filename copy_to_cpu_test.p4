#include <core.p4>
#include <tna.p4>

const bit<32> I2E_CLONE_SESSION_ID = 5;
const bit<48> TELEMTRY_MAC_SRC = 0x1;
const bit<48> TELEMTRY_MAC_DST = 0x2;
const bit<32> TELEMTRY_IP_SRC = 0xC0A86401;
const bit<32> TELEMTRY_IP_DST = 0xC0A86402;
const bit<16> TELEMETRY_CONTENT_LENGTH = 20;

header Ethernet_h {
    bit<48> dst;
    bit<48> src;
    bit<16> typ;
}

header IPv4_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  tos;
    bit<16> total_len;
    bit<16> id;
    bit<3>  flags;
    bit<13> offset;
    bit<8>  ttl;
    bit<8>  proto;
    bit<16> checksum;
    bit<32> src;
    bit<32> dst;
}

header IPv6_h {
    bit<4>  version;
    bit<8>  traffic_class;
    bit<20>  flow_label;
    bit<16> payload_len;
    bit<8> next_header;
    bit<8>  hop_limit;
    bit<128> src;
    bit<128>  dst;
}

header UDP_h {
    bit<16> sport;
    bit<16> dport;
    bit<16> length;
    bit<16> checksum;
}


/*header telemetry {
    bit<128> src;
    bit<128> dst;
}*/

struct metadata_t {}
struct egress_metadata_t {}

struct header_t {
    Ethernet_h ethernet;
    IPv4_h     ipv4;
    IPv6_h     ipv6;
    UDP_h      udp;
}

parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.typ) {
            0x0800: parse_ipv4;
            0x86dd: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
	transition select(hdr.ipv4.tos) {
            0x11: parse_udp;
	    default: accept;
	}
    }

    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
	transition select(hdr.ipv6.next_header) {
            0x11: parse_udp;
	    default: accept;
	}
    }

    state parse_udp {
	pkt.extract(hdr.udp);
	transition accept;
    }
}

control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    apply {
         pkt.emit(hdr);
    }
}

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in    ingress_intrinsic_metadata_t ig_intr_md,
        in    ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    action set_egress(bit<9> port) {
        ig_tm_md.ucast_egress_port = port;
    }

    action drop_packet() {
        ig_dprsr_md.drop_ctl = 0x1; // Drop packet.
    }

    table port_forwarding {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            set_egress;
            drop_packet;
        }
        default_action = drop_packet();
    }

    apply {
        port_forwarding.apply();
	ig_tm_md.copy_to_cpu = 1;
        /*ig_tm_md.bypass_egress = 1;*/
    }
}

parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out egress_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        pkt.extract(eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.typ) {
            0x0800: parse_ipv4;
            0x86dd: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
	transition select(hdr.ipv4.tos) {
            0x11: parse_udp;
	    default: accept;
        }
    }

    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
	transition select(hdr.ipv6.next_header) {
            0x11: parse_udp;
	    default: accept;
        }
    }

    state parse_udp {
	pkt.extract(hdr.udp);
	transition accept;
    }

}

control SwitchEgress(
        inout header_t hdr,
        inout egress_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

    action create_telemetry_packet() {
	/*        hdr.telemetry.setValid();
        hdr.telemetry.src_addr = hdr.ipv4.src_addr;
        hdr.telemetry.dst_addr = hdr.ipv4.dst_addr;
        hdr.telemetry.sport = hdr.udp.sport;
        hdr.telemetry.dport = hdr.udp.dport;
        hdr.ethernet.src_addr=TELEMTRY_MAC_SRC;
        hdr.ethernet.dst_addr=TELEMTRY_MAC_DST;
        hdr.ipv4.src_addr=TELEMTRY_IP_SRC;
        hdr.ipv4.dst_addr=TELEMTRY_IP_DST;
        hdr.udp.length = TELEMETRY_CONTENT_LENGTH;
        hdr.udp.checksum = 0;
        hdr.ipv4.total_len = hdr.ipv4.total_len + 12;*/
	hdr.ipv4.src = 0x0a010103;
    }

    apply {
//	if (eg_intr_md.egress_rid_first == 1) {
//	    hdr.ipv4.src = 0x0a010103;
//	}
	hdr.ipv4.src = (bit<32>) eg_intr_md.egress_port;
	hdr.ipv4.dst = (bit<32>) eg_intr_md.egress_rid;
    }
}

control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in egress_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {

    apply {
        pkt.emit(hdr);
    }
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;
