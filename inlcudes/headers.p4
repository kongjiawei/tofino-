//for barefoot
header_type intrinsic_metadata_t {
    fields {
        ingress_global_timestamp : 32;
        current_global_timestamp : 32;
    }
}

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type vlan_tag_t {
    fields {
        pri     : 3;
        cfi     : 1;
        vlan_id : 12;
        etherType : 16;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        dscp : 8;
        //ecn : 2;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

header_type udp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        length_ : 16;
        checksum : 16;
    }
}

header_type int_shim_header_t {
    fields {
        int_type : 8;
        rsvd1    : 8;
        len      : 8;
        dscp     : 6;
        rsvd2    : 2;

    }

}

header_type int_header_t {
    fields {
        ver : 2;
        rep : 2;
        c   : 1;
        e   : 1;
        m   : 1;
        rsvd1 : 4;
        ins_cnt     : 5;
        max_hop_cnt : 8;
        total_hop_cnt :8;
        instruction_mask_0001 : 4;
        instruction_mask_0002 : 4;
        instruction_mask_0003 : 4;
        instruction_mask_0004 : 4;
        rsvd3 : 16;

    }
}

// INT meta-value headers - different header for each value type
// bos is index of parser to parse int_value or protocol_value
header_type int_switch_id_header_t {
    fields {
        bos : 1;
        op  : 1;
        switch_id : 30;
    }
}


header_type int_ingress_port_header_t {
    fields {
        bos : 1;
        ingress_port : 31;
    }
}
header_type int_egress_port_header_t {
    fields {
        bos : 1;
        egress_port : 31;
    }
}

header_type int_port_id_header_t {
    fields {
        bos : 1;
        _pad_1 : 6;
        ingress_port_id : 9;
        _pad_2 : 7;
        egress_port_id  : 9;
    }
}

header_type int_hop_latency_header_t {
    fields {
        bos : 1;
        hop_latency : 31;
    }
}

header_type int_q_occupancy_header_t {
    fields {
        bos                 : 1;
        rsvd                : 2;
        qid                 : 5;
        q_occupancy         : 24;
    }
}
header_type int_ingress_tstamp_header_t {
    fields {
        bos                 : 1;
        ingress_tstamp      : 31;
    }
}
header_type int_egress_tstamp_header_t {
    fields {
        bos                 : 1;
        egress_tstamp       : 31;
    }
}

header_type int_optical_power_header_t {
    fields {
        bos : 1;
        flag : 1;
        optical_power : 30;
    }

}
header_type int_optical_osnr_header_t {
    fields {
        bos : 1;
        flag : 1;
        optical_osnr : 30;
    }

}

header_type int_optical_ocm_header_t {
    fields {
        bos : 1;
        flag_1 : 1;
        optical_power : 14;
        flag_2 : 1;
        optical_osnr : 15;
    }

}

header_type int_optical_osa_header_t {
    fields {
        bos : 1;
        flag_1 : 1;
        optical_power : 14;
        flag_2 : 1;
        optical_osnr : 15;
    }
}

header_type int_drop_counter_header_t {
    fields {
        bos : 1;
        low :31;

    }
}
//generic int value (info) header for extraction
header_type int_value_t {
    fields {
        bos : 1;
        value : 31;
    }
}
header_type tcp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset :4;
        res : 3;
        ecn : 3;
        ctrl : 6;
        window : 16;
        checksum : 16;
        urgentPtr : 16;

    }

}

header_type tcp_length_meta_t {
    fields {
        tcpLength : 16;
    }

}
metadata tcp_length_meta_t tcp_length_meta;


header_type sampling_metadata_t {
    fields {
        chosen : 1;

        rate : 31;
    }
}
metadata sampling_metadata_t sampling_metadata;
header_type int_sampling_metadata_t {
    fields {
        int_chosen : 32;

    }

}
metadata int_sampling_metadata_t int_sampling_metadata;
header_type i2e_metadata_t {
    fields {
        ingress_global_tstamp : 32;
        totalLen : 16;
    }
}
header_type e2e_metadata_t {
    fields {
        egress_global_tstamp : 32;
    }
}
metadata i2e_metadata_t i2e_metadata;
metadata e2e_metadata_t e2e_metadata;

header_type int_metadata_t {
    fields {
        remaining_hop_cnt : 16;
        int_inst_cnt : 16;
    }
}

metadata int_metadata_t int_metadata;

header_type header_length_t {
    fields {
        int_length : 16;
        pkt_length : 16;
    }

}
metadata header_length_t header_length;

header_type pkt_length_checking_metadata_t {
    fields {
        _padding : 7;
        checking_bit : 1;
    }
}
metadata pkt_length_checking_metadata_t pkt_length_checking_metadata;

header_type mirror_session_t {
    fields {
        session_id : 32;
    }
}
metadata mirror_session_t mirror_session;

header_type int_index_t {
    fields {
        index : 8;
    }
}
metadata int_index_t int_index;
/*
header_type cen_fre_metadata_t {
    fields {
        fre : 32;
    }
}
metadata cen_fre_metadata_t cen_fre_metadata;

header_type rand_metadata_t {
    fields {
        random_num : 16;
    }
}
metadata rand_metadata_t rand_meta;

header_type md_t {
    fields {
        sport:16;
        dport:16;
    }
}

metadata md_t md;
*/