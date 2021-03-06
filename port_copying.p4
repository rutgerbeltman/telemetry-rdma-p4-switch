#include <core.p4>
#include <tna.p4>

const bit<48> TELEMETRY_MAC_SRC = 0xb8599f9aa190;
const bit<48> TELEMETRY_MAC_DST = 0x98039b98ac46;
const bit<32> TELEMETRY_LEN = 44;
const bit<64> TELEMETRY_LEN_64 = 44;
const bit<3>  DIGEST_TYPE = 1;

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

header TCP_h {
    bit<16>  sport;
    bit<16>  dport;
    bit<32>  seq_num;
    bit<32>  ack;
    bit<4>   hdr_len;
    bit<12>  flags;
    bit<16>  wndw;
    bit<16>  crc;
    bit<16>  urg;
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

header immDt_h {
    bit<32> value;
}

header inv_crc_h {
    bit<32>  crc;
}

header tel_h {
    bit<128> src;
    bit<128> dst;
    bit<16>  sport;
    bit<16>  dport;
    bit<32>  seq_num;
    bit<32>  ack;
}

header crc_values_t {
    bit<64>  lrh;
    bit<28>  classandfl;
    bit<8>   hl;
    bit<8>   resv8a;
    bit<4>   left;
}

struct metadata_t {
    bit<32>  counter;
}

struct egress_metadata_t {}

struct header_t {
    Ethernet_h ethernet;
    IPv4_h     ipv4;
    IPv6_h     ipv6;
    UDP_h      udp;
    TCP_h      tcp;
    GRH_h      grh;
    BTH_h      bth;
    RETH_h     reth;
    immDt_h    immediate;
    tel_h      telemetry;
    inv_crc_h  crc;
    crc_values_t crc_values;
}

struct digest_signal_t {
    bit<32>    count;
}

parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition md_init;
    }

    state md_init {
	ig_md.counter = 0;
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
	    0x06: parse_tcp;
	    default: accept;
	} 
    }

    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
	transition select(hdr.ipv6.next_header) {
            0x11: parse_udp;
	    0x06: parse_tcp;
	    default: accept;
	}
    }
    
    state parse_udp {
	pkt.extract(hdr.udp);
	transition accept;
    }

    state parse_tcp {
	pkt.extract(hdr.tcp);
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
	    0: set_egress(1);
	    1: set_egress(0);
	}
        default_action = drop_packet();
    }

    apply {
        port_forwarding.apply();
        if(ig_intr_md.ingress_port < 2 && hdr.tcp.isValid())
	{
            ig_tm_md.copy_to_cpu = 1;
        }
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
	    0x06: parse_tcp;
	    default: accept;
	} 
    }

    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
	transition select(hdr.ipv6.next_header) {
            0x11: parse_udp;
	    0x06: parse_tcp;
	    default: accept;
	}
    }
    
    state parse_udp {
	pkt.extract(hdr.udp);
	transition accept;
    }

    state parse_tcp {
	pkt.extract(hdr.tcp);
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
    bit<64> tmp5 = 0;

    CRCPolynomial<bit<32>>(
	coeff = 0x04C11DB7,
	reversed = true,
	msb = false,
	extended = false,
	init = 0xFFFFFFFF,
	xor = 0xFFFFFFFF) poly;

    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly) crc_hash;

    Register<bit<16>, bit<16>>(1) seqnum;
    Register<bit<64>, bit<16>>(1) offset_va;
    Register<bit<32>, bit<16>>(1) seqnum_exp;

    RegisterAction<bit<16>, bit<16>, bit<16>>(seqnum) get_seqnum = {
	void apply(inout bit<16> register_data, out bit<16> result) {
	    result = register_data;
	    register_data = register_data + 1;
   	}
    };

    RegisterAction<bit<64>, bit<16>, bit<64>>(offset_va) get_va_offset = {
	void apply(inout bit<64> data, out bit<64> offset) {
	    offset = data;
	    data = data + TELEMETRY_LEN_64;
	}
    };

    RegisterAction<bit<32>, bit<16>, bit<32>>(seqnum_exp) get_seq_exp = {
	void apply(inout bit<32> register_data, out bit<32> result) {
	    result = register_data;
	    register_data = register_data + 1;
	}
    };

    action create_telemetry_data() {
	hdr.telemetry.setValid();
        hdr.telemetry.sport       = hdr.tcp.sport;
        hdr.telemetry.dport       = hdr.tcp.dport;
	hdr.telemetry.seq_num     = hdr.tcp.seq_num;
	hdr.telemetry.ack	  = hdr.tcp.ack;
        hdr.immediate.setValid();
        hdr.immediate.value = 0x41414141; //get_seq_exp.execute(0);
        hdr.ethernet.src          = TELEMETRY_MAC_SRC;
        hdr.ethernet.dst          = TELEMETRY_MAC_DST;
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
        hdr.grh.pay_len          = 0x50;
        hdr.grh.next_hdr         = 0x1B;
        hdr.grh.hop_lim          = 0x40;
        hdr.grh.src_gid          = 0xFFFF0a010101;
        hdr.grh.dst_gid          = 0xFFFF0a010102;
    }
    
    action assign_bth_fields() {
	hdr.bth.setValid();
        hdr.bth.opcode = 0x0B;
        hdr.bth.event = 0;
        hdr.bth.miqreq = 1;
	hdr.bth.pad_cnt = 0;
        hdr.bth.hdr_version = 0x0;
        hdr.bth.part_key = 0xFFFF;
        hdr.bth.resv1 = 0;
        hdr.bth.ack = 1;
	hdr.bth.resv2 = 0;
	hdr.bth.seq_num = (bit<24>) get_seqnum.execute(0);
    }

    action assign_reth_fields() {
	hdr.reth.setValid();
        hdr.reth.virt_addr = get_va_offset.execute(0);
	hdr.reth.dma_len = TELEMETRY_LEN;
    } 

    action assign_crc_values(){
        hdr.crc_values.lrh = 0xFFFFFFFFFFFFFFFF;
        hdr.crc_values.classandfl= 0xFFFFFFF;
        hdr.crc_values.hl = 0xFF;
        hdr.crc_values.resv8a = 0xFF;
    }
    
    action calculate_crc() {
	hdr.crc.setValid();
	hdr.crc.crc = crc_hash.get({
	    hdr.crc_values.lrh,
	    hdr.grh.version,
	    hdr.crc_values.classandfl,
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
            hdr.immediate.value,
	    hdr.telemetry.src,
	    hdr.telemetry.dst,
	    hdr.telemetry.sport,
	    hdr.telemetry.dport,
            hdr.telemetry.seq_num,
	    hdr.telemetry.ack
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


    action set_qp_vr_rk_action(bit<24> qp, bit<64> vr, bit<32> rk) { 
        hdr.bth.dst_qp = qp;
        hdr.reth.virt_addr = hdr.reth.virt_addr + vr;
        hdr.reth.r_key = rk;
    }
    
    table set_qp_vr_rk {
        key = {
            eg_intr_md.egress_port : exact;
        }
        actions = {
            set_qp_vr_rk_action;
        }
    }

    apply {
	if (eg_intr_md.egress_port == 0x80 && hdr.tcp.isValid()) {
	    hdr.ethernet.typ = 0x8915;
	    assign_grh_fields();
	    assign_bth_fields();
	    assign_reth_fields();

	    hdr.ipv4.setInvalid();
	    hdr.ipv6.setInvalid();
	    hdr.udp.setInvalid();
	    hdr.tcp.setInvalid();

	    create_telemetry_data();
    	    if (hdr.ipv4.isValid()) {
		telemetry_ipv4_data();
	    } else {
		telemetry_ipv6_data();
	    }  
            set_qp_vr_rk.apply();
            assign_crc_values();
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


