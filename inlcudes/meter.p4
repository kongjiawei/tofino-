#include "tofino/meter_blackbox.p4"

header_type local_metadata_t {
    fields {

        color : 8;
    }
}
metadata local_metadata_t local_metadata;


meter meter_0 {
    type : bytes;
    static : tbl_forward;
    result : local_metadata.color;
    instance_count : 500;
}

