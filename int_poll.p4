//for barefoot


#include "includes/headers.p4"
#include "includes/parser.p4"
#include "includes/rand.p4"
#include "includes/meter.p4"
#include "includes/global_config.p4"
#include <tofino/intrinsic_metadata.p4>
#include <tofino/constants.p4>
#include <tofino/primitives.p4>

/*
 * not INT case, we just drop and count
 */

action meter_action (idx) {
    execute_meter(meter_0, idx, local_metadata.color);
}

action do_forward(espec,int_idx) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, espec);
    modify_field(int_index.index,int_idx);
	//meter_action(idx);
}

action do_drop() {
    drop();
}

@pragma command_line --no-dead-code-elimination
table tbl_forward {
    reads {
        ipv4.dstAddr : lpm;

    }
    actions {
        do_forward;
        do_drop;
    }
    default_action : do_drop;
    size : 512;
}



table tbl_meter_policy {

    reads {
        local_metadata.color : exact;

    }
    actions {

        do_drop;
    }
	size : 256;
}

action int_set_header_drop_counter() {
    add_header(int_drop_counter_header);
    add_to_field(ipv4.totalLen,4);
    add_to_field(int_header.ins_cnt,1);

}

action int_set_header_instruction_0(power_ocm,power_ocm_flag,osnr_ocm,osnr_ocm_flag,
                                    power_osa,power_osa_flag,osnr_osa,osnr_osa_flag) {
    add_header(int_switch_id_header);
    modify_field(int_switch_id_header.switch_id, SWITCH_ID);
    add_header(int_port_id_header);
    modify_field(int_port_id_header.ingress_port_id,
                    ig_intr_md.ingress_port);
    modify_field(int_port_id_header.egress_port_id,
                    eg_intr_md.egress_port);

        //ocm
    add_header(int_optical_ocm_header);
    modify_field(int_optical_ocm_header.flag_1,power_ocm_flag);
    modify_field(int_optical_ocm_header.optical_power, power_ocm);
    modify_field(int_optical_ocm_header.optical_osnr,osnr_ocm);
    modify_field(int_optical_ocm_header.flag_2,osnr_ocm_flag);

    //osa
    add_header(int_optical_osa_header);
    modify_field(int_optical_osa_header.flag_1,power_osa_flag);
    modify_field(int_optical_osa_header.optical_power,power_osa);
    modify_field(int_optical_osa_header.flag_2,osnr_osa_flag);
    modify_field(int_optical_osa_header.optical_osnr,osnr_osa);

    modify_field(int_switch_id_header.op,1);

    add_to_field(ipv4.totalLen,16);
    add_to_field(int_header.ins_cnt,4);
}

action int_set_header_instruction_1(power_ocm,power_ocm_flag,osnr_ocm,osnr_ocm_flag,
                                    power_osa,power_osa_flag,osnr_osa,osnr_osa_flag) {
    add_header(int_switch_id_header);
    modify_field(int_switch_id_header.switch_id, SWITCH_ID);

    add_header(int_hop_latency_header);
	//bit_and(int_hop_latency_header.hop_latency,eg_intr_md.deq_timedelta,0x1FFFF);
    modify_field(int_hop_latency_header.hop_latency,
    eg_intr_md.deq_timedelta);
    //subtract(int_hop_latency_header.hop_latency,
    //e2e_metadata.egress_global_tstamp,i2e_metadata.ingress_global_tstamp);


    add_header(int_q_occupancy_header);

    modify_field(int_q_occupancy_header.qid, eg_intr_md.egress_qid);
    modify_field(int_q_occupancy_header.q_occupancy,
                 eg_intr_md.enq_qdepth);

        //ocm
    add_header(int_optical_ocm_header);
    modify_field(int_optical_ocm_header.flag_1,power_ocm_flag);
    modify_field(int_optical_ocm_header.optical_power, power_ocm);
    modify_field(int_optical_ocm_header.optical_osnr,osnr_ocm);
    modify_field(int_optical_ocm_header.flag_2,osnr_ocm_flag);

    //osa
    add_header(int_optical_osa_header);
    modify_field(int_optical_osa_header.flag_1,power_osa_flag);
    modify_field(int_optical_osa_header.optical_power,power_osa);
    modify_field(int_optical_osa_header.flag_2,osnr_osa_flag);
    modify_field(int_optical_osa_header.optical_osnr,osnr_osa);

    modify_field(int_switch_id_header.op,1);

    add_to_field(ipv4.totalLen,20);
    add_to_field(int_header.ins_cnt,5);
}

action int_set_header_instruction_2(power_ocm,power_ocm_flag,osnr_ocm,osnr_ocm_flag,
                                    power_osa,power_osa_flag,osnr_osa,osnr_osa_flag) {
    add_header(int_switch_id_header);
    modify_field(int_switch_id_header.switch_id, SWITCH_ID);

    add_header(int_port_id_header);
    modify_field(int_port_id_header.ingress_port_id,
                    ig_intr_md.ingress_port);
    modify_field(int_port_id_header.egress_port_id,
                    eg_intr_md.egress_port);


    add_header(int_hop_latency_header);
	//bit_and(int_hop_latency_header.hop_latency,eg_intr_md.deq_timedelta,0x1FFFF);
    modify_field(int_hop_latency_header.hop_latency,
    eg_intr_md.deq_timedelta);
    //subtract(int_hop_latency_header.hop_latency,
    //e2e_metadata.egress_global_tstamp,i2e_metadata.ingress_global_tstamp);


    add_header(int_q_occupancy_header);

    modify_field(int_q_occupancy_header.qid, eg_intr_md.egress_qid);
    modify_field(int_q_occupancy_header.q_occupancy,
                 eg_intr_md.enq_qdepth);

        //ocm
    add_header(int_optical_ocm_header);
    modify_field(int_optical_ocm_header.flag_1,power_ocm_flag);
    modify_field(int_optical_ocm_header.optical_power, power_ocm);
    modify_field(int_optical_ocm_header.optical_osnr,osnr_ocm);
    modify_field(int_optical_ocm_header.flag_2,osnr_ocm_flag);

    //osa
    add_header(int_optical_osa_header);
    modify_field(int_optical_osa_header.flag_1,power_osa_flag);
    modify_field(int_optical_osa_header.optical_power,power_osa);
    modify_field(int_optical_osa_header.flag_2,osnr_osa_flag);
    modify_field(int_optical_osa_header.optical_osnr,osnr_osa);

    modify_field(int_switch_id_header.op,1);

    add_to_field(ipv4.totalLen,24);
    add_to_field(int_header.ins_cnt,6);
}

table tbl_set_int_instance {
    reads {
        int_header.instruction_mask_0001 : exact;
    }
    actions {
        int_set_header_instruction_0;
        int_set_header_instruction_1;
        int_set_header_instruction_2;
    }
}

action int_set_header_switch_id() {
    add_header(int_switch_id_header);
    modify_field(int_switch_id_header.switch_id, SWITCH_ID);


    add_to_field(ipv4.totalLen,4);
    add_to_field(int_header.ins_cnt,1);
}
action int_set_header_port_id() {
    add_header(int_port_id_header);

    #ifdef SRC
    modify_field(int_header.instruction_mask_0001,0);
    #endif
    #ifdef INTERMEDIATE
        modify_field(int_header.instruction_mask_0002,0);
    #endif

    modify_field(int_port_id_header.ingress_port_id,
                    ig_intr_md.ingress_port);
    modify_field(int_port_id_header.egress_port_id,
                    eg_intr_md.egress_port);
    add_to_field(ipv4.totalLen,4);
    add_to_field(int_header.ins_cnt, 1);

}

action int_set_header_optical_data(power_ocm,power_ocm_flag,osnr_ocm,osnr_ocm_flag,
                                    power_osa,power_osa_flag,osnr_osa,osnr_osa_flag) {
    //ocm
    add_header(int_optical_ocm_header);
    modify_field(int_optical_ocm_header.flag_1,power_ocm_flag);
    modify_field(int_optical_ocm_header.optical_power, power_ocm);
    modify_field(int_optical_ocm_header.optical_osnr,osnr_ocm);
    modify_field(int_optical_ocm_header.flag_2,osnr_ocm_flag);

    //osa
    add_header(int_optical_osa_header);
    modify_field(int_optical_osa_header.flag_1,power_osa_flag);
    modify_field(int_optical_osa_header.optical_power,power_osa);
    modify_field(int_optical_osa_header.flag_2,osnr_osa_flag);
    modify_field(int_optical_osa_header.optical_osnr,osnr_osa);

    modify_field(int_switch_id_header.op,1);
    add_to_field(ipv4.totalLen,8);
    add_to_field(int_header.ins_cnt,2);

}

action int_set_header_hop_latency() {
    add_header(int_hop_latency_header);

	//bit_and(int_hop_latency_header.hop_latency,eg_intr_md.deq_timedelta,0x1FFFF);
    modify_field(int_hop_latency_header.hop_latency,
    eg_intr_md.deq_timedelta);
    //subtract(int_hop_latency_header.hop_latency,
    //e2e_metadata.egress_global_tstamp,i2e_metadata.ingress_global_tstamp);
    #ifdef SRC
    modify_field(int_header.instruction_mask_0001,1);
    #endif
    #ifdef INTERMEDIATE
        modify_field(int_header.instruction_mask_0002,1);
    #endif
    add_to_field(ipv4.totalLen,4);
    add_to_field(int_header.ins_cnt,1);
}
action int_set_header_q_occupancy() {
    add_header(int_q_occupancy_header);
    //modify_field(int_header.instruction_mask_0001,2);
	
    #ifdef SRC
    modify_field(int_header.instruction_mask_0001,2);
    #endif
    #ifdef INTERMEDIATE
        modify_field(int_header.instruction_mask_0002,2);
    #endif
    //add_to_field(ipv4.totalLen,4);
    modify_field(int_q_occupancy_header.qid, eg_intr_md.egress_qid);
    modify_field(int_q_occupancy_header.q_occupancy,
                 eg_intr_md.enq_qdepth);
    add_to_field(ipv4.totalLen,4);
    add_to_field(int_header.ins_cnt,1);
}

action int_set_header_optical_power(power,flag) {
    add_header(int_optical_power_header);
    //modify_field(int_header.instruction_mask_0001,2);
	
    #ifdef SRC
    modify_field(int_header.instruction_mask_0001,2);
    #endif
    #ifdef INTERMEDIATE
        modify_field(int_header.instruction_mask_0002,2);
    #endif
    add_to_field(ipv4.totalLen,4);
	modify_field(int_optical_power_header.optical_power,power);
	modify_field(int_optical_power_header.flag,flag);
	add_to_field(int_header.ins_cnt,1);
}

action int_set_header_optical_osnr(osnr,flag) {
    add_header(int_optical_osnr_header);
    //modify_field(int_header.instruction_mask_0001,2);
	
    #ifdef SRC
    modify_field(int_header.instruction_mask_0001,3);
    #endif
    #ifdef INTERMEDIATE
        modify_field(int_header.instruction_mask_0002,3);
    #endif
    add_to_field(ipv4.totalLen,4);
	modify_field(int_optical_osnr_header.optical_osnr,osnr);
	modify_field(int_optical_osnr_header.flag,flag);
	add_to_field(int_header.ins_cnt,1);
}
action set_i2e() {
    bit_and(ig_intr_md_from_parser_aux.ingress_global_tstamp,ig_intr_md_from_parser_aux.ingress_global_tstamp,0xFFFFFFFF);
    //modify_field(i2e_metadata.ingress_global_tstamp,ig_intr_md_from_parser_aux.ingress_global_tstamp);
}
action set_e2e() {
    bit_and(ig_intr_md_from_parser_aux.ingress_global_tstamp,eg_intr_md_from_parser_aux.egress_global_tstamp,0xFFFFFFFF);

    //modify_field(e2e_metadata.egress_global_tstamp,eg_intr_md_from_parser_aux.egress_global_tstamp);
}
action int_set_header_ingress_tstamp() {
    add_header(int_ingress_tstamp_header);
    modify_field(int_ingress_tstamp_header.ingress_tstamp,
                 i2e_metadata.ingress_global_tstamp);
    add_to_field(ipv4.totalLen,4);
    add_to_field(int_header.ins_cnt,1);
}


action int_set_header_egress_tstamp() {
    add_header(int_egress_tstamp_header);
    modify_field(int_egress_tstamp_header.egress_tstamp,
                 eg_intr_md_from_parser_aux.egress_global_tstamp);
    add_to_field(ipv4.totalLen,4);
    add_to_field(int_header.ins_cnt,1);
}

action int_set_header_switch_id_and_port_id() {
    //modify_field(int_header.instruction_mask_0002, 0);
    //add_header(int_switch_id_header);
    //modify_field(int_switch_id_header.switch_id, SWITCH_ID);


    //add_to_field(ipv4.totalLen,16);
    //add_to_field(int_header.ins_cnt,1);

    modify_field(int_header.instruction_mask_0001, 0);
    modify_field(int_header.instruction_mask_0002, 0);

    add_header(int_port_id_header);
    //modify_field(int_port_id_header.bos,1);
    modify_field(int_port_id_header.ingress_port_id,
                    ig_intr_md.ingress_port);
    modify_field(int_port_id_header.egress_port_id,
                    0);
    add_to_field(ipv4.totalLen,4);
    add_to_field(int_header.ins_cnt, 1);
}

action int_set_header_switch_id_and_latency() {

    //modify_field(int_header.instruction_mask_0002, 0);
    //add_header(int_switch_id_header);
    //modify_field(int_switch_id_header.switch_id, SWITCH_ID);
    //add_to_field(ipv4.totalLen,4);
    //add_to_field(int_header.ins_cnt,1);

    modify_field(int_header.instruction_mask_0001, 1);
    modify_field(int_header.instruction_mask_0002, 1);

    add_header(int_hop_latency_header);
	//bit_and(int_hop_latency_header.hop_latency,eg_intr_md.deq_timedelta,0x1FFFF);
    modify_field(int_hop_latency_header.hop_latency,
    eg_intr_md.deq_timedelta);
    //subtract(int_hop_latency_header.hop_latency,
    //e2e_metadata.egress_global_tstamp,i2e_metadata.ingress_global_tstamp);
    add_to_field(ipv4.totalLen,4);
    add_to_field(int_header.ins_cnt,1);

    //modify_field(int_hop_latency_header.bos,1);
}

action int_set_header_switch_id_and_power(power,flag) {
    modify_field(int_header.instruction_mask_0002, 1);
    //add_header(int_switch_id_header);
    //modify_field(int_switch_id_header.switch_id, SWITCH_ID);


    //add_to_field(ipv4.totalLen,4);
    //add_to_field(int_header.ins_cnt,1);

    add_header(int_optical_power_header);
    modify_field(int_optical_power_header.flag,flag);
    modify_field(int_optical_power_header.optical_power, power);
    //modify_field(int_switch_id_header.op,1);
    add_to_field(ipv4.totalLen,4);
    add_to_field(int_header.ins_cnt,1);
    //modify_field(int_optical_power_header.bos,1);
}

action int_set_header_switch_id_and_osnr(osnr,flag) {
    modify_field(int_header.instruction_mask_0002, 2);
 //   add_header(int_switch_id_header);
 //   modify_field(int_switch_id_header.switch_id, SWITCH_ID);

    //add_to_field(ipv4.totalLen,4);
    //add_to_field(int_header.ins_cnt,1);

    add_header(int_optical_osnr_header);
    modify_field(int_optical_osnr_header.flag,flag);
    modify_field(int_optical_osnr_header.optical_osnr, osnr);
    //modify_field(int_switch_id_header.op,1);
    add_to_field(ipv4.totalLen,4);
    add_to_field(int_header.ins_cnt,1);
    //modify_field(int_optical_osnr_header.bos,1);

}

action int_set_header_switch_id_and_port_id_2() {
    modify_field(int_header.instruction_mask_0001, 0);
    modify_field(int_header.instruction_mask_0002, 2);
    //add_header(int_switch_id_header);


    //add_header(int_port_id_header);
    //set_tdelta();

    //modify_field(int_hop_latency_header.hop_latency,
    //intrinsic_metadata.current_global_timestamp - intrinsic_metadata.ingress_global_timestamp);

    //modify_field(int_switch_id_header.switch_id, SWITCH_ID);

    //add_to_field(ipv4.totalLen,4);
    //add_to_field(int_header.ins_cnt,1);

    //modify_field(int_port_id_header.ingress_port_id,
    //                standard_metadata.ingress_port);
    //modify_field(int_port_id_header.egress_port_id,
    //               0);
    //add_to_field(ipv4.totalLen,4);
    //add_to_field(int_header.ins_cnt,1);



    //modify_field(int_port_id_header.bos,1);

}


table tbl_int_instance_set_switch_id_and_port_id {
    actions {
        int_set_header_switch_id_and_port_id;
    }

}

table tbl_int_instance_set_switch_id_and_port_id_2 {
    actions {
        int_set_header_switch_id_and_port_id_2;
    }
}

table tbl_int_instance_set_switch_id_and_latency {
    actions {
        int_set_header_switch_id_and_latency;
    }
}


action int_set_bos_switch_id() {
    modify_field(int_switch_id_header.bos, 1);
}

action int_set_bos_optical_ocm() {
    modify_field(int_optical_ocm_header.bos,1);
}
action int_set_bos_optical_osa() {
    modify_field(int_optical_ocm_header.bos,1);
}
action int_set_header_no_optical_data() {
    modify_field(int_switch_id_header.op,0);
}
action int_set_bos_port_id() {
    modify_field(int_port_id_header.bos,1);
}
action int_set_bos_hop_latency() {

    modify_field(int_hop_latency_header.bos,1);
}
action int_set_bos_q_occupancy() {
    modify_field(int_q_occupancy_header.bos,1);
}
action int_set_bos_optical_power() {
    modify_field(int_optical_power_header.bos,1);
}
action int_set_bos_optical_osnr() {

    modify_field(int_optical_osnr_header.bos,1);
}
/*
table tbl_int_instance_set_switch_id_and_port_id {
    actions {
        int_set_header_switch_id_and_port_id;
    }
}
table tbl_int_instance_set_switch_id_and_latency {
    actions {
        int_set_header_switch_id_and_latency;
    }
}
*/
table tbl_int_instance_set_switch_id_and_power {
    actions {
        int_set_header_switch_id_and_power;
    }
}
table tbl_int_instance_set_switch_id_and_osnr {
    actions {
        int_set_header_switch_id_and_osnr;
    }
}

table tbl_int_instance_set_optical_data {
    reads {
        ig_intr_md.ingress_port : exact;

    }
    actions {
        int_set_header_optical_data;
    }
    size : 4;
}

table tbl_int_instance_set_switch_id {
//    reads {
//        cen_fre_metadata.fre : exact;
//    }
    actions {
        int_set_header_switch_id;
    }
}
table tbl_int_instance_set_port_id {
    actions {
        int_set_header_port_id;
    }
}

table tbl_set_i2e {
    actions {
        set_i2e;
    }
}
table tbl_set_e2e {
    actions {
        set_e2e;
    }
}
table tbl_int_instance_set_ingress_tstamp {
    actions {
        int_set_header_ingress_tstamp;
    }
}
table tbl_int_instance_set_egress_tstamp {
    actions {
        int_set_header_egress_tstamp;
    }
}
table tbl_int_instance_set_q_occupancy {
    actions {
        int_set_header_q_occupancy;
    }
}
table tbl_int_instance_set_hop_latency {
    actions {
        int_set_header_hop_latency;
    }
}
table tbl_int_instance_set_power {
	actions {
		int_set_header_optical_power;
	}
}
table tbl_int_instance_set_osnr {
	actions {
		int_set_header_optical_osnr;
	}
}

table tbl_int_instance_set_bos_switch_id {
    actions {
        int_set_bos_switch_id;
    }
}

table tbl_int_instance_set_bos_optical_power {
    actions {
        int_set_bos_optical_power;
    }
}
table tbl_int_instance_set_bos_optical_osnr {
    actions {
        int_set_bos_optical_osnr;
    }
}
table tbl_int_instance_set_bos_port_id {
    actions {
        int_set_bos_port_id;
    }
}
table tbl_int_instance_set_bos_latency {
    actions {
        int_set_bos_hop_latency;
    }
}
table tbl_int_instance_set_bos_q_occupancy{
    actions {
        int_set_bos_q_occupancy;
    }
}

action int_set_header() {

    modify_field(ipv4.dscp,PROTOCOLS_INT);
    add_header(int_shim_header);
    add_header(int_header);

    add_to_field(ipv4.totalLen,12);
}
action int_update_header_source() {
    modify_field(int_shim_header.int_type,1);
    modify_field(int_shim_header.len,8);
    modify_field(int_header.ver,1);
    modify_field(int_header.rep,0);
    modify_field(int_header.c,0);
    modify_field(int_header.m,0);
    modify_field(int_header.e,0);
    modify_field(int_header.ins_cnt,0);
    modify_field(int_header.total_hop_cnt,1);
    modify_field(int_header.max_hop_cnt,8);

}
action int_update_header_intermediate() {

    add_to_field(int_header.total_hop_cnt,1);
}
action int_update_header_sink() {
    add_to_field(int_header.total_hop_cnt,1);
}

action int_insert_err_e() {

    modify_field(int_header.e,1);
}
action int_insert_err_m() {
    modify_field(int_header.m,1);
}
table int_instance_insert_err_e {
    actions {
       int_insert_err_e;
    }
}

table int_instance_insert_err_m {
    actions {
       int_insert_err_m;
    }
}
table int_instance_insert_header_source {
    actions {
        int_set_header;
    }
}
table int_instance_update_header_source {
    actions {
        int_update_header_source;
    }
}
table int_instance_update_header_intermediate {
    actions {
        int_update_header_intermediate;
    }
}
table int_instance_update_header_sink {
    actions {
        int_update_header_sink;
    }
}

field_list copy_to_cpu_fields {

    mirror_session.session_id;
    ig_intr_md.ingress_port;
    eg_intr_md.egress_port;
    i2e_metadata.ingress_global_tstamp;
}

action mirror(session_id) {
    modify_field(mirror_session.session_id,session_id);
    clone_ingress_pkt_to_egress(session_id,copy_to_cpu_fields);



}
table tbl_mirror {
    actions {
        mirror;
    }
}

action remove_int_header() {
    remove_header(int_header);
    remove_header(int_shim_header);
    modify_field(ipv4.dscp, 0);
    remove_header(int_value[0]);
    remove_header(int_value[1]);
    remove_header(int_value[2]);
    remove_header(int_value[3]);
    remove_header(int_value[4]);
    remove_header(int_value[5]);
    remove_header(int_value[6]);
    remove_header(int_value[7]);
    remove_header(int_value[8]);
    remove_header(int_value[9]);
    remove_header(int_value[10]);
    remove_header(int_value[11]);
    remove_header(int_value[12]);
    remove_header(int_value[13]);
    remove_header(int_value[14]);
    remove_header(int_value[15]);
    remove_header(int_value[16]);
    remove_header(int_value[17]);
    remove_header(int_value[18]);
    remove_header(int_value[19]);
    remove_header(int_value[20]);
    remove_header(int_value[21]);
    remove_header(int_value[22]);
    remove_header(int_value[23]);

}
table tbl_remove_int_header {
    actions {
        remove_int_header;
    }
}

action get_length() {
#ifndef SRC
    shift_left(header_length.int_length,int_header.ins_cnt,2);
    add(header_length.pkt_length,header_length.int_length,ipv4.totalLen);
#endif
#ifdef SRC
    add(header_length.pkt_length,0,i2e_metadata.totalLen);
#endif

}
table tbl_get_length {
    actions {
        get_length;
    }

}

register pkt_length_checking_reg {
    width : 16;
    static : tbl_pkt_length_checker;
    instance_count : 1024;

}
blackbox stateful_alu pkt_length_checking_alu {
    reg : pkt_length_checking_reg;
    initial_register_lo_value : 0;
    condition_lo : header_length.pkt_length - 1454 > 0 ;
    update_lo_1_predicate : condition_lo;
    update_lo_1_value : 1;
    update_lo_2_predicate : not condition_lo;
    update_lo_2_value : 0;
    output_value : register_lo;
    output_dst : pkt_length_checking_metadata.checking_bit;

}
action pkt_length_checking(index) {
    pkt_length_checking_alu.execute_stateful_alu(index);
}
table tbl_pkt_length_checker {
    actions {
        pkt_length_checking;
    }
    default_action : pkt_length_checking;

}


control ingress {
#ifdef SINK
if (valid(int_header)) {
    apply(tbl_mirror);
}
#endif
    apply(tbl_set_i2e);
    apply(tbl_forward);
    //forward();
    apply(tbl_meter_policy);
    //apply(tbl_set_sampling_rate);
    //apply(tbl_sip_sampler);
#ifdef SRC
#endif
    apply(tbl_get_length);
    apply(tbl_pkt_length_checker);

}
control source_node {
    apply(tbl_run_ext_alu);
	
    apply(tbl_run_flow_count);
    if (int_md.ext_chosen == 1) {
        if (pkt_length_checking_metadata.checking_bit == 0) {
            //apply(tbl_set_rand_select_1);
            //apply(tbl_set_rand_select_2);
        /*

            if (int_sampling_metadata.int_chosen == 0 or int_sampling_metadata.int_chosen == 2) {
                apply(tbl_int_instance_set_switch_id_and_port_id);
            }
            if (int_sampling_metadata.int_chosen == 1) {
                apply(tbl_int_instance_set_switch_id_and_latency);
            }

            if (int_sampling_metadata.int_chosen == 2) {
                //apply(tbl_int_instance_set_switch_id_and_port_id_2);
                apply(tbl_int_instance_set_optical_data);

            }
        */
            apply(tbl_run_int_alu);
            apply(int_instance_insert_header_source);
            apply(int_instance_update_header_source);
            apply(tbl_int_instance_set_switch_id);
            //apply(tbl_int_instance_set_bos_switch_id);
            if (int_md.int_chosen == 1) {
                apply(tbl_int_instance_set_port_id);
                apply(tbl_int_instance_set_bos_port_id);

            }

            if (int_md.int_chosen == 2) {

                apply(tbl_int_instance_set_hop_latency);
                apply(tbl_int_instance_set_bos_latency);
            }
            if (int_md.int_chosen == 3) {
                apply(tbl_int_instance_set_q_occupancy);
                apply(tbl_int_instance_set_bos_q_occupancy);
            }



    #ifdef OP
            //apply(tbl_int_instance_set_optical_data);

    #endif
            //apply(tbl_int_instance_set_q_occupancy);


        } else {
            apply(int_instance_insert_err_m);
        }
    }

}
control intermediate_node {
//    apply(tbl_set_e2e);
    apply(tbl_run_flow_count);
    if (valid (int_header)) {
        apply(tbl_run_int_alu);

        if (int_header.e != 1 and int_header.max_hop_cnt != int_header.total_hop_cnt) {
            if (int_header.m != 1 and pkt_length_checking_metadata.checking_bit == 0) {
                apply(tbl_int_instance_set_switch_id);
				apply(int_instance_update_header_intermediate);
				

//                apply(tbl_int_instance_set_hop_latency);
//                apply(tbl_int_instance_set_bos_latency);
                
                if (int_md.int_chosen == 1) {
                    apply(tbl_int_instance_set_port_id);
                    apply(tbl_int_instance_set_bos_port_id);

                }

                if (int_md.int_chosen == 2) {

                    apply(tbl_int_instance_set_hop_latency);
                    apply(tbl_int_instance_set_bos_latency);
                }
                //if (int_md.int_chosen == 3) {
                //    apply(tbl_int_instance_set_q_occupancy);
                //    apply(tbl_int_instance_set_bos_q_occupancy);
               // }
			   //
			   if (int_md.int_chosen == 3) {
			   apply(tbl_int_instance_set_power);
			   apply(tbl_int_instance_set_bos_optical_power);
			   }
			   if(int_md.int_chosen == 4) {
				   apply(tbl_int_instance_set_osnr);
				   apply(tbl_int_instance_set_bos_optical_osnr);
			   }
              
            } else {
                apply(int_instance_insert_err_m);
            }
        } else {
            apply(int_instance_insert_err_e);
        }


    }

}
control sink_node {


}
control egress  {
#ifdef SRC
    source_node();
#endif
#ifdef INTERMEDIATE
    intermediate_node();
#endif

#ifdef SINK
    sink_node();
#endif

}

