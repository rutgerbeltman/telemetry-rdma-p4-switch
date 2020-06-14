#include <core.p4>
#include <tna.p4>

const bit<48> TELEMETRY_MAC_SRC = 0x1;
const bit<48> TELEMETRY_MAC_DST = 0x00154d1306b2;
const bit<32> TELEMETRY_LEN = 36;

header Ethernet_h {
    bit<48>  dst;
    bit<48>  src;
    bit<16>  typ;
}

header IPv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   tos;
    bit<16>  total_len;
    bit<16>  id;
    bit<3>   flags;
    bit<13>  offset;
    bit<8>   ttl;
    bit<8>   proto;
    bit<16>  checksum;
    bit<32>  src;
    bit<32>  dst;
}

header IPv6_h {
    bit<4>   version;
    bit<8>   traffic_class;
    bit<20>  flow_label;
    bit<16>  payload_len;
    bit<8>   next_header;
    bit<8>   hop_limit;
    bit<128> src;
    bit<128> dst;
}

header UDP_h {
    bit<16>  sport;
    bit<16>  dport;
    bit<16>  length;
    bit<16>  checksum;
}

header GRH_h {
    bit<4>   version;
    bit<8>   class;
    bit<20>  flow_lab;
    bit<16>  pay_len;
    bit<8>   next_hdr;
    bit<8>   hop_lim;
    bit<128> src_gid;
    bit<128> dst_gid;
}

header BTH_h {
    bit<8>   opcode;
    bit<1>   event;
    bit<1>   miqreq;
    bit<2>   pad_cnt;
    bit<4>   hdr_version;
    bit<16>  part_key;
    bit<8>   resv1;
    bit<24>  dst_qp;
    bit<1>   ack;
    bit<7>   resv2;
    bit<24>  seq_num;
}

header RETH_h {
    bit<64>  virt_addr;
    bit<32>  r_key;
    bit<32>  dma_len;
}

header inv_crc_h {
    bit<32>  crc;
}

header tel_h {
    bit<128> src;
    bit<128> dst;
    bit<16>  sport;
    bit<16>  dport;
}

header crc_values_t {
    bit<64>  lrh;
    bit<8>   class;
    bit<20>  fl;
    bit<8>   hl;
    bit<8>   resv8a;
    bit<4>   left;
}

struct metadata_t {}
struct egress_metadata_t {}

struct header_t {
    Ethernet_h ethernet;
    IPv4_h     ipv4;
    IPv6_h     ipv6;
    UDP_h      udp;
    GRH_h      grh;
    BTH_h      bth;
    RETH_h     reth;
    tel_h      telemetry;
    inv_crc_h  crc;
    crc_values_t crc_values;
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
	const entries = {
	    0: set_egress(128);
	    128: set_egress(0);
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
	
    bit<32> tmp1 = 0;
    bit<32> tmp2 = 0;
    bit<32> tmp3 = 0;
    bit<32> tmp4 = 0; 

    CRCPolynomial<bit<32>>(
	coeff = 0x04C11DB7,
	reversed = true,
	msb = false,
	extended = false,
	init = 0xFFFFFFFF,
	xor = 0xFFFFFFFF) poly;

    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly) crc_hash;


/*    Register<vr_addr_t>(1) mem_address;
    Register<rm_key_t>(1) keys;

    RegisterAction<bit<64>, vr_addr_t>(mem_address) virtual_address = {
	void apply(inout bit<64> register1_data, out bit<64> result1) {
	    result1 = register1_data;
    };

    RegisterAction<bit<32>, rm_key_t>(keys) remote_key = {
	void apply(inout bit<32> register2_data, out bit<32> result2) {
	    result2 = register2_data;
	}
    };*/

    action create_telemetry_data() {
	hdr.telemetry.setValid();
        hdr.telemetry.sport      = hdr.udp.sport;
        hdr.telemetry.dport      = hdr.udp.dport;
        hdr.ethernet.src         = TELEMETRY_MAC_SRC;
        hdr.ethernet.dst         = TELEMETRY_MAC_DST;
    }
    
    action telemetry_ipv4_data() {
        hdr.telemetry.src        = (bit<128>) hdr.ipv4.src;
        hdr.telemetry.dst        = (bit<128>) hdr.ipv4.dst;
    
    }

    action telemetry_ipv6_data() {
        hdr.telemetry.src        = hdr.ipv6.src;
        hdr.telemetry.dst        = hdr.ipv6.dst;
    }

    action assign_grh_fields() {
	hdr.grh.setValid(); 
        hdr.grh.version          = 0x6;
        hdr.grh.class            = 0;
        hdr.grh.flow_lab         = 0;
        hdr.grh.pay_len          = 94;
        hdr.grh.next_hdr         = 0x1B;
        hdr.grh.hop_lim          = 0x40;
        hdr.grh.src_gid          = 0xFFFFFFFF;
        hdr.grh.dst_gid          = 0xFFFFFFFF;
    }
    
    action assign_bth_fields() {
	hdr.bth.setValid();
        hdr.bth.opcode = 0x0A;
        hdr.bth.event = 0;
        hdr.bth.miqreq = 1;
	hdr.bth.pad_cnt = 0;
        hdr.bth.hdr_version = 0x4;
        hdr.bth.part_key = 0xFFFF;
        hdr.bth.resv1 = 0;
        hdr.bth.dst_qp = 1;
        hdr.bth.ack = 0;
	hdr.bth.resv2 = 0;
	hdr.bth.seq_num = 1;
    }

    action assign_reth_fields() {
	hdr.reth.setValid();
	hdr.reth.virt_addr = 1;
	hdr.reth.r_key = 1;
	hdr.reth.dma_len = TELEMETRY_LEN;
    } 

    action check_crc() {
	    hdr.crc_values.lrh = 0xFFFFFFFFFFFFFFFF;
	    hdr.grh.version = 0x6;
	    hdr.crc_values.class = 0xFF;
	    hdr.crc_values.fl = 0xFFFFF;
	    hdr.grh.pay_len = 0x0044;
	    hdr.grh.next_hdr = 0x1B;
	    hdr.crc_values.hl = 0xFF;
	    hdr.grh.src_gid = 0xFFFF0a010201;
	    hdr.grh.dst_gid = 0xFFFF0a010202;
	    hdr.bth.opcode = 0x0a;
	    hdr.bth.event = 0;
	    hdr.bth.miqreq = 1;
    	    hdr.bth.pad_cnt = 0;
	    hdr.bth.hdr_version = 0;
	    hdr.bth.part_key = 0xFFFF;
	    hdr.bth.dst_qp = 0x91C;
	    hdr.crc_values.resv8a = 0xFF;
	    hdr.bth.ack = 1;
	    hdr.bth.resv2 = 0;
	    hdr.bth.seq_num = 0;
	    hdr.reth.virt_addr = 0x01535360;
            hdr.reth.r_key = 0x01aa66;
	    hdr.reth.dma_len = 0x24;
	    //hdr.telemetry.src = 0x19cfbdb81bc590daaeabe164e88a3198;
	    hdr.telemetry.src = 0x6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C;
	    hdr.telemetry.dst = 0x6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C;
	    hdr.telemetry.sport = 0x6C6C;
	    hdr.telemetry.dport = 0x6C00;
    }

    action calculate_crc() {
	hdr.crc.setValid();
	hdr.crc.crc = crc_hash.get({
	    hdr.crc_values.lrh,
	    hdr.grh.version,
	    hdr.crc_values.class,
	    hdr.crc_values.fl,
	    hdr.grh.pay_len,
	    hdr.grh.next_hdr,
	    hdr.crc_values.hl,
	    hdr.grh.src_gid,
	    hdr.grh.dst_gid,
	    hdr.bth.opcode,
	    hdr.bth.event,
	    hdr.bth.miqreq,
    	    hdr.bth.pad_cnt,
	    hdr.bth.hdr_version,
	    hdr.bth.part_key,
	    hdr.crc_values.resv8a,
	    hdr.bth.dst_qp,
	    hdr.bth.ack,
	    hdr.bth.resv2,
	    hdr.bth.seq_num,
	    hdr.reth.virt_addr,
	    hdr.reth.r_key,
	    hdr.reth.dma_len,
	    hdr.telemetry.src,
	    hdr.telemetry.dst,
	    hdr.telemetry.sport,
	    hdr.telemetry.dport
	});
    }	

    action swap_crc() {
	tmp1 = hdr.crc.crc & 0x000000FF;
	tmp2 = hdr.crc.crc & 0x0000FF00;
	tmp3 = hdr.crc.crc & 0x00FF0000;
	tmp4 = hdr.crc.crc & 0xFF000000;
    }

    action swap2_crc() {
	tmp1 = tmp1 << 24;
	tmp2 = tmp2 << 8;
	tmp3 = tmp3 >> 8;
	tmp4 = tmp4 >> 24;
    }

    action swap3_crc() {
	tmp1 = tmp1 | tmp2;
	tmp3 = tmp3 | tmp4;
    }

    action swap4_crc() {
	hdr.crc.crc = tmp1 | tmp3;
    }

    apply {
	if (eg_intr_md.egress_port == 0x3C) {
	    hdr.ethernet.typ = 0x8915;
	    assign_grh_fields();
	    assign_bth_fields();
	    assign_reth_fields();

	    hdr.ipv4.setInvalid();
	    hdr.ipv6.setInvalid();
	    hdr.udp.setInvalid();

	    create_telemetry_data();
    	    if (hdr.ipv4.isValid()) {
		telemetry_ipv4_data();
	    } else {
		telemetry_ipv6_data();
	    }  
	    check_crc();
	    calculate_crc();
	    swap_crc();
	    swap2_crc();
	    swap3_crc();
	    swap4_crc();
	}
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


