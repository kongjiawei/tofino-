

parser start {
    return parse_ethernet;
}

/*
 * Ethernet
 */

#define ETHERTYPE_IPV4 0x0800
#define VLAN           0x8100
header ethernet_t ethernet;
header vlan_tag_t vlan_tag;
parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        VLAN           : parse_vlan_tag;
        default : ingress;
    }
}

parser parse_vlan_tag {
    extract(vlan_tag);
    return select(latest.etherType) {
        0x800 : parse_ipv4;
        default : ingress;
    }
}

/*
 * IPv4
 */

header ipv4_t ipv4;
header tcp_t                                    tcp;
header udp_t                                    udp;
header int_shim_header_t                        int_shim_header;
header int_header_t                             int_header;
header int_switch_id_header_t                   int_switch_id_header;
header int_q_occupancy_header_t                 int_q_occupancy_header;
header int_ingress_tstamp_header_t              int_ingress_tstamp_header;
header int_egress_tstamp_header_t               int_egress_tstamp_header;
header int_port_id_header_t                     int_port_id_header;
header int_hop_latency_header_t                 int_hop_latency_header;
header int_drop_counter_header_t                int_drop_counter_header;
header int_optical_ocm_header_t                 int_optical_ocm_header;
header int_optical_osa_header_t                 int_optical_osa_header;
header int_optical_power_header_t               int_optical_power_header;
header int_optical_osnr_header_t                int_optical_osnr_header;
#define MAX_INT_INFO                            24
header int_value_t                              int_value[MAX_INT_INFO];

#define IP_PROTOCOLS_TCP 0x06
#define PROTOCOLS_INT 0x5c

#define IP_PROTOCOLS_UDP 0x11
parser parse_ipv4 {
    extract(ipv4);
    set_metadata(i2e_metadata.totalLen,latest.totalLen);
    return select(latest.protocol) {
        IP_PROTOCOLS_TCP : parse_tcp;
        IP_PROTOCOLS_UDP : parse_udp;

        default : ingress;
    }
}
parser parse_int_shim_header {
    extract(int_shim_header);
    return parse_int_header;
}

parser parse_int_header {
    extract(int_header);
    set_metadata(int_metadata.int_inst_cnt,latest.ins_cnt);
    return select (latest.rsvd1,latest.total_hop_cnt) {

        // reserved bits = 0 and total_hop_cnt == 0
        // no int_values are added by upstream
        0x000 mask 0xFFF : ingress;
        // parse INT val headers added by upstream devices (total_hop_cnt != 0)
        // reserved bits must be 0
        0x000 mask 0xF00 : parse_int_val;

        // never transition to the following state
        default: parse_all_int_meta_value_dummy;
    }
}

parser parse_int_val {
    extract(int_value[next]);
    return select(latest.bos) {
        0 : parse_int_val;
        default : ingress;
    }
}

parser parse_tcp {
    extract(tcp);

    return select(ipv4.dscp) {
        PROTOCOLS_INT : parse_int_shim_header;
        default : ingress;
    }

}
parser parse_udp {
    extract(udp);

    return select(ipv4.dscp) {
        PROTOCOLS_INT : parse_int_shim_header;
        default : ingress;
    }

}
parser parse_all_int_meta_value_dummy {
    // bogus state.. just extract all possible int headers in the
    // correct order to build
    // the correct parse graph for deparser (while adding headers)

    //extract(int_drop_counter_header);
    //extract(int_optical_power_t);
    extract(int_switch_id_header);
    extract(int_port_id_header);
//    extract(int_optical_ocm_header);
//    extract(int_optical_osa_header);
    extract(int_optical_power_header);
    extract(int_optical_osnr_header);
    extract(int_q_occupancy_header);
    extract(int_ingress_tstamp_header);
    extract(int_egress_tstamp_header);
    extract(int_hop_latency_header);

    return parse_int_val;
}



//field_list_calculation

field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.dscp;
        //ipv4.ecn;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}
/*
field_list tcp_checksum_list {


}
*/
