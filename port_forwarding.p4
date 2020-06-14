#include <core.p4>
#include <tna.p4>

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

struct metadata_t {}
struct egress_metadata_t {}

struct header_t {
    Ethernet_h ethernet;
    IPv4_h     ipv4;
    IPv6_h     ipv6;
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
            // TODO: Need to test what happens if no match.
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }

    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
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
        ig_tm_md.bypass_egress = 1;
    }
}

parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out egress_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        pkt.extract(eg_intr_md);
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
    apply {
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
