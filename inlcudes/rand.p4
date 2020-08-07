//for barefoot
#include "tofino/stateful_alu_blackbox.p4"
#define RANDOM_NUM_BIT_WIDTH 32
#include <tofino/intrinsic_metadata.p4>
/*
action set_rand_select_1() {
    modify_field_rng_uniform(rand_meta.random_num,
                             0,
                             255);
}
table tbl_set_rand_select_1 {
    actions {
        set_rand_select_1;
        //set_rand_select_2;
    }
    default_action : set_rand_select_1;
    size : 1;


}

field_list rand_hash_fields {
    rand_meta.random_num;
}

field_list_calculation rand_hash {
    input {
        rand_hash_fields;
    }
    algorithm : crc32;
    output_width : 8;
}
action set_rand_select_2() {


    //
    //sampling_random_num = base + rand_hash % cnt
    modify_field_with_hash_based_offset(rand_meta.random_num,
                                        0,
                                        rand_hash,
                                        2);


}



table tbl_set_rand_select_2 {
    actions {
        set_rand_select_2;
        //set_rand_select_2;
    }
    default_action : set_rand_select_2;
    size : 1;


}

register sampling_cntr {
    width : 32;
    static: tbl_sip_sampler;
    instance_count : 1024;
}

blackbox stateful_alu sampling_alu {
    reg: sampling_cntr;
    initial_register_lo_value: 1;
    condition_lo: register_lo - sampling_metadata.rate  < 0;
    condition_hi: ig_intr_md_for_tm.copy_to_cpu != 0;
    update_lo_1_predicate: not condition_lo;
    update_lo_1_value: 1;
    update_lo_2_predicate: condition_lo;
    update_lo_2_value: register_lo + 1;
    output_predicate: not condition_lo and not condition_hi;
    output_value : predicate;
    output_dst : sampling_metadata.chosen;
}
action sample(index) {
    sampling_alu.execute_stateful_alu(index);
}

table tbl_sip_sampler {
    actions {
        sample;
    }
    default_action : sample;
}

action set_sampling_rate(rate) {
    modify_field(sampling_metadata.rate,rate);
}
table tbl_set_sampling_rate {
    actions {
        set_sampling_rate;
    }
    default_action : set_sampling_rate;
    size : 1;
}



register int_sampling_cntr {
    width : 32;
    static: tbl_int_sip_sampler;
    instance_count : 1024;
}

blackbox stateful_alu int_sampling_alu {
    reg: int_sampling_cntr;
    initial_register_lo_value: 0;
    condition_lo: register_lo - 2 < 0;
    //condition_hi: ig_intr_md_for_tm.copy_to_cpu != 0;
    update_lo_1_predicate: not condition_lo;
    update_lo_1_value: 0;
    update_lo_2_predicate: condition_lo;
    update_lo_2_value: register_lo + 1;
    output_predicate: condition_lo or not condition_lo;
    output_value : register_lo;
    output_dst : int_sampling_metadata.int_chosen;
}
action int_sample(index) {
    int_sampling_alu.execute_stateful_alu(index);
}

table tbl_int_sip_sampler {


    actions {
        int_sample;
    }
    default_action : int_sample;
}


*/
header_type int_md_t {
    fields {
        ext_chosen : 8;
        int_chosen : 8;
    }
}
metadata int_md_t int_md;

register ext_reg {
    width : 8;
    static : tbl_run_ext_alu ;
    instance_count : 64;
}

blackbox stateful_alu ext_alu {
    reg : ext_reg;
    initial_register_lo_value : 0;
    condition_lo : register_lo - 2 < 0;
    update_lo_1_predicate : condition_lo;
    update_lo_1_value : register_lo + 1;
    update_lo_2_predicate : not condition_lo;
    update_lo_2_value : 1;
    output_value : alu_lo;
    output_dst : int_md.ext_chosen;
}
action run_ext_alu() {
    ext_alu.execute_stateful_alu(int_index.index);

}

table tbl_run_ext_alu {

    actions {
        run_ext_alu;
    }
}
register int_reg {
    width : 8;
    static : tbl_run_int_alu;
    instance_count : 64;
}
blackbox stateful_alu int_alu {
    reg : int_reg;
    initial_register_lo_value : 0;
    condition_lo : register_lo - 4 < 0;
    update_lo_1_predicate : condition_lo;
    update_lo_1_value : register_lo + 1;
    update_lo_2_predicate : not condition_lo;
    update_lo_2_value : 1;
    output_value : alu_lo;
    output_dst : int_md.int_chosen;


}
action run_int_alu() {
    int_alu.execute_stateful_alu(int_index.index);

}

table tbl_run_int_alu {
    actions {
        run_int_alu;
    }
}
counter flow_counter {
    type : packets;
    instance_count : 64;
}
action flow_count() {
    count(flow_counter,int_index.index);
}
table tbl_run_flow_count {
    actions {
        flow_count;
    }
}
