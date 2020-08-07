#include "sbuf.h"
#include <pcap.h>
#include <stdint.h>
#include <mysql/mysql.h>
#include <sys/signal.h>
#include <zconf.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include<stdio.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<stdlib.h>
#include<netdb.h>
#include<sys/types.h>
#include<pthread.h>

static pcap_t *pcap = NULL;
static sbuf_t *sp = NULL;
int sClient;
#define  __attribute_unused__ __attribute__((unused))

#define FORCE_FLUSH_THRESH 10
#define OUTPUT_TIME_INTERVAL 200000 //us
#define MYPORT 8887
#define MAX_CONNECT_NUM 10
#define MAX_HOP 3

static volatile int force_quit = 1;
FILE *fp_port;
FILE *fp_latency;
FILE *fp_osnr;
FILE *fp_power;
FILE *fp_all; //Save the data to this file
int flag_time = 1;
double start_time;
double now_time;
double relative_time;
int device_array[MAX_HOP];
int latency_array[MAX_HOP];
int power_array[MAX_HOP];
int osnr_array[MAX_HOP];

typedef struct{
    int device;
    int latency_sta;
    int optical_power_sta;
    int optical_osnr_sta;
}needSend;
static unsigned long long last_port_time = 0;
static unsigned long long last_latency_time = 0;
static unsigned long long last_power_time = 0;
static unsigned long long last_osnr_time = 0;
int16_t optical_osa_power_value = 0;
int16_t optical_ocm_power_value = 0;
int16_t optical_osa_osnr_value = 0;
int16_t optical_ocm_osnr_value = 0;
typedef struct data {
     int cnt1;
     int cnt2;
     int cnt3;
     int cnt4;
     int cnt5;
     int tofino_cnt6;
     float sum1;
     float sum2;
     float sum3;
     float sum4;
     float sum5;
     float counter;
     float tofino_hop_latency_sum6;
     float tofino_q_occupancy_sum6;
     float optical_power_sum1;
     float optical_power_sum2;
     float optical_power_sum3;
     float optical_power_sum4;
     float optical_power_sum5;
     float optical_power_sum6;

     float optical_osnr_sum1;
     float optical_osnr_sum2;
     float optical_osnr_sum3;
     float optical_osnr_sum4;
     float optical_osnr_sum5;
     float optical_osnr_sum6;
     pthread_mutex_t mutex;
}data;
static data data1 = {
    .sum1 = 0,
    .sum2 = 0,
    .sum3 = 0,
    .sum4 = 0,
    .sum5 = 0,
    .optical_power_sum6 = 0,
    .optical_osnr_sum6 = 0,
    .cnt1 = 0,
    .cnt2 = 0,
    .cnt3 = 0,
    .cnt4 = 0,
    .cnt5 = 0,
    .tofino_cnt6 = 0,
    .tofino_hop_latency_sum6 = 0,
    .tofino_q_occupancy_sum6 = 0
};
uint8_t total_int_header = 0;
uint8_t instructions3 = 0;
uint8_t instructions2 = 0;
/* Grab the packet from the specified physical network card using pacp */
static int init_pcap() {
    int snaplen = 1518;
    int promisc = 1;
    char *iface = "vf0_0";
    char errbuf[PCAP_ERRBUF_SIZE];
    if ((pcap = pcap_open_live(iface, snaplen, promisc, 0, errbuf)) == NULL) {
        printf("pcap_open_live(%s) error, %s\n", iface, errbuf);
        pcap = pcap_open_offline(iface, errbuf);
        if (pcap == NULL) {
            printf("pcap_open_offline(%s): %s\n", iface, errbuf);
        } else {

            printf("Reading packets from pcap file %s...\n", iface);
        }

    } else {

        printf("Capturing live traffic from device %s...\n", iface);
    }
    if (pcap_setdirection(pcap, PCAP_D_INOUT) < 0) {
        printf("pcap_setdirection error: '%s'\n", pcap_geterr(pcap));
    } else {

        printf("Succesfully set direction to '%s'\n", "PCAP_D_INOUT");
    }
    return 0;
}

__attribute_unused__ static inline unsigned long long rp_get_us(void) {
    struct timeval tv = {0};
    gettimeofday(&tv, NULL);
    return (unsigned long long) (tv.tv_sec * 1000000L + tv.tv_usec);
}

__attribute_unused__ static void print_pkt(uint32_t pkt_len, uint8_t *pkt){
//    printf("pkt6 is %d\n", pkt[6]);
    uint32_t i = 0;
    for (i = 0; i < pkt_len; ++i) {
//        printf(" pkt %d is  %02x", i, pkt[i]);
        printf("%02x ", pkt[i]);
        if ((i+1) % 8 == 0) {
            printf("\t");
        }
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
}


int force_flush = 0;
static void process_int_pkt(unsigned char __attribute_unused__*a,
        const struct pcap_pkthdr __attribute_unused__*pkthdr,
        const uint8_t *pkt) {              //pkt is defined as eight bits

#define ETH_HEADER_LEN              14
#define IPV4_HEADER_LEN             20
#define TCP_HEADER_LEN              20
#define INT_SHIM_HEADER_LEN         4
#define UDP_HEADER_LEN              8
#define INT_HEADER_LEN              8    // Byte


    uint8_t protocol = pkt[ETH_HEADER_LEN + IPV4_HEADER_LEN - 11];

    uint8_t instructions = 0;
    uint8_t instructions1 = 0;


    uint8_t pos = 0;
  //  printf("i am in\n");
    if(flag_time == 1)
    {
        start_time = rp_get_us();
        flag_time = 0;
    }
    if (protocol == 0x06) {

        total_int_header = pkt[ETH_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN + INT_SHIM_HEADER_LEN + 3]; // Number of hops experienced
        instructions = pkt[ETH_HEADER_LEN+IPV4_HEADER_LEN+TCP_HEADER_LEN+INT_SHIM_HEADER_LEN+4];
        instructions1 = (instructions & 0xF0) >> 4;
        instructions2 = (instructions & 0x0F);
        pos = (uint8_t)(ETH_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN + INT_SHIM_HEADER_LEN + INT_HEADER_LEN);
    }
    if (protocol == 0x11) {
        total_int_header = pkt[ETH_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN + INT_SHIM_HEADER_LEN + 3];
        instructions = pkt[ETH_HEADER_LEN+IPV4_HEADER_LEN+UDP_HEADER_LEN+INT_SHIM_HEADER_LEN+4];
        instructions1 = (instructions & 0xF0) >> 4;
        instructions2 = (instructions & 0x0F);
        pos = (uint8_t)(ETH_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN + INT_SHIM_HEADER_LEN + INT_HEADER_LEN);

    }
//     int* latency_array = (int*)malloc((total_int_header - 1) * sizeof(int));
//    int* power_array = (int*)malloc((total_int_header - 1) * sizeof(int));
//    int* osnr_array = (int*)malloc((total_int_header - 1) * sizeof(int)); //alloc the array ,total_int_header = 3
   // printf("%d\n", protocol);
    uint32_t last_counter;
    uint32_t switch_id;
    uint32_t ingress_port_id = -1;
    uint32_t egress_port_id = -1;
    uint32_t port_id;
    uint32_t tofino_hop_latency;
    uint32_t smartnic_hop_latency;
    uint8_t qid;
    uint32_t q_occupancy;
#ifdef DEBUG
    uint32_t ingress_tstamp;
    uint32_t egress_tstamp;
#endif
    uint32_t retval = 0;
    uint32_t pkt_len = 0;
#ifdef COUNTER
    uint32_t counter;
#endif
    uint32_t telemetry_optical_exist;
    uint32_t flag_1;
    uint32_t optical_osa_raw;
    uint32_t optical_ocm_raw;

    uint32_t flag_2;

    int32_t t = 0;
    for (int i = 0; i < total_int_header; i++) {


#ifdef TX
        retval = (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];
        pkt_len = (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];
#endif
        switch_id = (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];
        //printf("switchId is %x\n",switch_id);
        telemetry_optical_exist = (switch_id & 0x40000000) >> 30;
        switch_id = switch_id & 0x3FFFFFFF;
      //  printf("switch:%d\n",switch_id);
        if(switch_id == 3) // last hop and dont need t collect
        {
            device_array[total_int_header - 1 - i] = switch_id;
            pos = pos + 4;
            continue;
        }
    //    printf("swithid is: %x\n",switch_id);
    // printf("total int header:%x\n",total_int_header);
    //    printf("inst:%x\n",instructions);
    //    printf("inst2:%x\n",instructions2);


        if (switch_id > INT8_MAX) {//Barefoot Tofino
          //  printf("tofino switch id:%x\n",switch_id);
          //  printf("intru2:%d\n",instructions2);
            device_array[total_int_header - 1 - i] = switch_id;
            if (instructions2 == 0) {

                port_id = (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];
                egress_port_id = port_id & 0x000001FF;
                ingress_port_id = (port_id & 0x01FF0000) >> 16;
                unsigned long long now = rp_get_us();
                if ( now - last_port_time > 200000) {
                    //fprintf(fp_port,"tofino egress_port_id:%d\t, ingress_port_id:%d\n",egress_port_id,ingress_port_id);
                    last_port_time = now;
                }

            }

            if (instructions2 == 1) {

                tofino_hop_latency = ((pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++]) & 0x1FFFF;
                latency_array[total_int_header - 1 - i] = tofino_hop_latency;
               // printf("tofino latency array:%d\n", latency_array[1]);
                unsigned long long now = rp_get_us();
                if ( now - last_latency_time > 0) {
                   // fprintf(fp_latency,"tofino:%d\n",hop_latency);
                   // printf("tofino latency:%d\n",tofino_hop_latency);
                    last_latency_time = now;
                }
            }

            if(instructions2 == 2) {

                optical_ocm_raw = ((pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++]);
                flag_1 = (optical_ocm_raw & 0x40000000) >> 30;
                optical_ocm_power_value = ((optical_ocm_raw & 0x3FFFFFFF)) * (flag_1 == 1 ? -1 : 1);
                power_array[(total_int_header - 1 - i)] = optical_ocm_power_value;
                unsigned long long now = rp_get_us();
               // fprintf(fp_power,"OCM_power:%d\n",optical_ocm_power_value);
                if (now - last_power_time > 200000) {
                    last_power_time = now;
                }

            }
            if (instructions2 == 3) {
                optical_ocm_raw = ((pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++]);
              //  printf("optical ocm raw:%x\n",optical_ocm_raw);
                flag_2 = (optical_ocm_raw & 0x40000000) >> 30;
             //   printf("flag:%x\n",flag_2);
                optical_ocm_osnr_value = (optical_ocm_raw & 0x3FFFFFFF) * (flag_2 == 1? -1 : 1);
                osnr_array[(total_int_header - 1 - i)] = optical_ocm_osnr_value;
             //   printf("ocm osnr:%d\n",optical_ocm_osnr_value);
                unsigned long long now = rp_get_us();
//                printf("last_osnr_time:%d\n",last_osnr_time);
//                printf("now us:%d\n",now);

                if (now - last_osnr_time > OUTPUT_TIME_INTERVAL) {
//                    printf("kjwcollect");

//                    fprintf(fp_all,"%f %f %f %f %f %f %f %f\n",smartnic_hop_latency,optical_osa_power_value,
//                           optical_osa_osnr_value,tofino_hop_latency,optical_ocm_power_value,optical_ocm_osnr_value );
                    now_time = rp_get_us();
                    relative_time = (now_time - start_time)/1000000.0;
                    force_flush++;
                  //  fprintf(fp_all,"     1\t %6d\t %5d\t %6d\t %6.3f\n     2\t %6d\t %5d\t %6d\t %6.3f\n",smartnic_hop_latency*16/633, optical_osa_power_value,
                   //         optical_osa_osnr_value,relative_time,tofino_hop_latency,optical_ocm_power_value,optical_ocm_osnr_value,relative_time);

                    //send the data


//                    needSend *SendData = (needSend*)malloc(sizeof(needSend));
//                    char *sendbuffer = (char*)malloc(sizeof(needSend));
//                //    printf("ok\n");
//                    for(int i = 0; i <(total_int_header - 1); i++) {
//                        SendData->device = device_array[i];
//                        SendData->latency_sta = latency_array[i];
//                        SendData->optical_power_sta = power_array[i];
//                        SendData->optical_osnr_sta = osnr_array[i];
//                     //   printf("senddata:%d\n",SendData->optical_power_sta);
//                        memcpy(sendbuffer, SendData, sizeof(needSend));
//               //         printf("%d",sizeof(needSend));
//                        if(send(sClient, sendbuffer, sizeof(needSend), 0) < 0)
//                        {
//                            printf("send error");
//
//                        }
//                    }
//
//                    last_osnr_time = now;
//                    if (force_flush > FORCE_FLUSH_THRESH) {
//                        fflush(fp_all);
//                        force_flush = 0;
//                    }
                }
            }

            /*
            //printf("optical exist %x\n",telemetry_optical_exist);
            if (telemetry_optical_exist) {
//                optical_power_raw = ((pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++]);
//                flag_1 = (optical_power_raw & 0x40000000) >> 30;
//                optical_power_raw = optical_power_raw & 0x0FFFFFFF;
//                optical_power_value = optical_power_raw * (flag_1 == 1 ? -1 : 1);
//                optical_osnr_raw = ((pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++]);
//                flag_2 = (optical_power_raw & 0x80000000) >> 30;
//                optical_osnr_raw = optical_osnr_raw & 0x0FFFFFFF;
//                optical_osnr_value = optical_osnr_raw * (flag_2 == 1? -1 : 1);

                optical_osa_raw = ((pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++]);
                flag_1 = (optical_osa_raw & 0x40000000) >> 30;
                optical_osa_power_value = ((optical_osa_raw & 0x3FFF0000) >> 16) * (flag_1 == 1 ? -1 : 1);
                flag_2 = (optical_osa_raw & 0x00008000) >> 30;
                optical_osa_osnr_value = (optical_osa_raw & 0x00007FFF) * (flag_2 == 1? -1 : 1);
                optical_ocm_raw = ((pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++]);
                //printf("optical_ocm_raw = %x\n",optical_ocm_raw);
                flag_1 = (optical_ocm_raw & 0x40000000) >> 30;

                optical_ocm_power_value = ((optical_ocm_raw & 0x3FFF0000) >> 16) * (flag_1 == 1 ? -1 : 1);
                //printf("optical_ocm_raw = %x\n",optical_ocm_raw);

                flag_2 = (optical_ocm_raw & 0x00008000) >> 30;
                optical_ocm_osnr_value = (optical_ocm_raw & 0x00007FFF) * (flag_2 == 1? -1 : 1);
                //printf("optical_ocm_power = %d, optical_ocm_osnr = %d\n",optical_ocm_power_value,optical_ocm_osnr_value);

//                printf("optical_power_value%d\n",optical_power_value);
//                printf("optical_osnr_value%d\n",optical_osnr_value);
            } else {
                optical_osa_power_value = 0;
                optical_osa_osnr_value = 0;
                optical_ocm_power_value = 0;
                optical_ocm_osnr_value = 0;
            }
            //qid = pkt[pos++];
            //q_occupancy = ((pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++]) & 0xFFFFFFFF;
#ifdef DEBUG
            ingress_tstamp = (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];
            egress_tstamp = (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];
#endif
            //hop_latency = ((pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++]) & 0x1FFFF;
*/
        } else {//SmartNic
#ifdef COUNTER
            counter = (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];
            //printf("counter == %d\n",counter);
#endif
           // printf("smartnic1 switch id:%x\n",switch_id);
           // printf("i come here\n");
            //printf("instrusions1:%x\n",instructions1);
            device_array[total_int_header - 1 - i] = switch_id;
            if (instructions1 == 0) {
                port_id = (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];
                egress_port_id = port_id & 0x0000FFFF;
                ingress_port_id = (port_id & 0x7FFF0000) >> 16;
                unsigned long long now = rp_get_us();
                if ( now - last_port_time > 200000) {
                   // fprintf(fp_port,"smartnic egress_port_id:%x\t, ingress_port_id:%x\n",egress_port_id,ingress_port_id);
                    last_port_time = now;
                }
            }
            if (instructions1 == 1) {
                smartnic_hop_latency = ((pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++]) &  0x7FFFFFFF;
                latency_array[total_int_header - 1 - i] = smartnic_hop_latency * 16 /633;
             //   printf("smartnic_hop_latency:%x",smartnic_hop_latency);
                unsigned long long now = rp_get_us();
                if ( now - last_latency_time > 200000) {
                  //  printf("smartnic hop latency:%x\n",smartnic_hop_latency);
                    //fprintf(fp_latency,"smartnic:%x\n",smartnic_hop_latency);
                    last_latency_time = now;
                }
            }
            if (instructions1 == 2) {
                optical_osa_raw = ((pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++]);
                flag_1 = (optical_osa_raw & 0x40000000) >> 30;
                optical_osa_power_value = ((optical_osa_raw & 0x3FFFFFFF)) * (flag_1 == 1 ? -1 : 1);
                power_array[(total_int_header - 1 - i)] = optical_osa_power_value;
                unsigned long long now = rp_get_us();
                //fprintf(fp_power,"OSA_power:%d\n",optical_osa_power_value);
                if (now - last_power_time > 200000) {
                    last_power_time = now;
                }
            }
            if (instructions1 == 3) {
                optical_osa_raw = ((pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++]);
                flag_1 = (optical_osa_raw & 0x40000000) >> 30;
                optical_osa_osnr_value = ((optical_osa_raw & 0x3FFFFFFF)) * (flag_1 == 1 ? -1 : 1);
                osnr_array[(total_int_header - 1 - i)] = optical_osa_osnr_value;
                unsigned long long now = rp_get_us();
                if (now - last_osnr_time > 200000) {
                    //fprintf(fp_osnr,"OSA_osnr:%x\n",optical_osa_osnr_value );
                    last_power_time = now;
                }
            }
            /*
            if (telemetry_optical_exist) {
//                optical_power_raw = ((pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++]);
//                flag_1 = (optical_power_raw & 0x40000000) >> 30;
//                optical_power_raw = optical_power_raw & 0x0FFFFFFF;
//                optical_power_value = optical_power_raw * (flag_1 == 1 ? -1 : 1);
//                optical_osnr_raw = ((pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++]);
//                flag_2 = (optical_power_raw & 0x80000000) >> 30;
//                optical_osnr_raw = optical_osnr_raw & 0x0FFFFFFF;
//                optical_osnr_value = optical_osnr_raw * (flag_2 == 1? -1 : 1);
                optical_ocm_raw = ((pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++]);
                flag_1 = (optical_ocm_raw & 0x40000000) >> 30;
                optical_ocm_power_value = optical_ocm_raw & 0x3FFF0000 >> 16 * (flag_1 == 1 ? -1 : 1);
                flag_2 = (optical_ocm_raw & 0x00008000) >> 30;
                optical_ocm_osnr_value = optical_ocm_raw & 0x00007FFF * (flag_2 == 1? -1 : 1);
                optical_osa_raw = ((pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++]);
                flag_1 = (optical_osa_raw & 0x40000000) >> 30;
                optical_osa_power_value = optical_osa_raw & 0x3FFF0000 >> 16 * (flag_1 == 1 ? -1 : 1);
                flag_2 = (optical_osa_raw & 0x00008000) >> 30;
                optical_osa_osnr_value = optical_osa_raw & 0x00007FFF * (flag_2 == 1? -1 : 1);


//                printf("optical_power_value%d\n",optical_power_value);
//                printf("optical_osnr_value%d\n",optical_osnr_value);
            } else {
                optical_osa_power_value = 0;
                optical_osa_osnr_value = 0;
                optical_ocm_power_value = 0;
                optical_ocm_osnr_value = 0;
            }

            qid = 0;
            q_occupancy = 0;
#ifdef DEBUG
            ingress_tstamp = 0;
            egress_tstamp = 0;
#endif
             */
        }

#ifdef DEBUG
        printf("ingress_port_id %d\n",ingress_port_id);
        printf("egress_port_id %d\n", egress_port_id);
        printf("hop_latency %x\n",hop_latency);
        printf("switch_id %d\n",switch_id);
                printf("switch_id %d, ingress_port_id %d, egress_port_id %d, optical_power_value %d, hop_latency %d, qid %d, "
               "q_occupancy %d, ingress_tstamp %d, egress_tstamp %d\n", switch_id, ingress_port_id, egress_port_id,
               optical_power_raw, hop_latency, qid, q_occupancy, ingress_tstamp, egress_tstamp);
#endif
//        item_t item = {
//                .pkt_len = pkt_len,
//                .retval = retval,
//                .switch_id = switch_id,
//                .ingress_port_id = ingress_port_id,
//                .egress_port_id = egress_port_id,
//                .optical_osa_power_value = optical_osa_power_value,
//                .optical_osa_osnr_value = optical_osa_osnr_value,
//                .optical_ocm_power_value = optical_ocm_power_value,
//                .optical_ocm_osnr_value = optical_ocm_osnr_value,
//             //   .hop_latency = hop_latency,
//                .qid = qid,
#ifdef DEBUG
                .ingress_tstamp = ingress_tstamp,
                .egress_tstamp = egress_tstamp,
#endif
              //  .q_occupancy = q_occupancy,
#ifdef COUNTER
                .counter = counter
#endif

       // };

        //sbuf_insert(sp, item);
    }

}

static void cal(int *cnt, float *sum,item_t item) {
    *cnt = *cnt + 1;
    *sum += (item.hop_latency) * 16.0 / 633;
#ifdef TX
    *nic_tx += ((item.pkt_len)*8*1000000L) / ((item.retval) * 16 / 633) / 1024 / 1024;
#endif

}
static void cal_tofino(int *cnt, float *sum_1, float *sum_2,
        float *optical_power_sum, float *optical_osnr_sum,
        float *optical_osa_power_sum, float  *optical_osa_osnr_sum,
        float *counter,
        item_t item) {
    *cnt = *cnt + 1;
    *sum_1 += (item.q_occupancy);
    *sum_2 += (item.hop_latency);
    if (item.optical_ocm_power_value != 0) {
        *optical_power_sum += item.optical_ocm_power_value;
    }
    if (item.optical_ocm_osnr_value != 0) {
        *optical_osnr_sum += item.optical_ocm_osnr_value;
    }
    if(item.optical_osa_osnr_value != 0) {
        *optical_osa_osnr_sum += item.optical_osa_osnr_value;
    }
    if(item.optical_osa_power_value != 0) {
        *optical_osa_power_sum += item.optical_osa_power_value;
    }
#ifdef COUNTER
    counter += item.counter;
#endif
}
static void *write_data(void) {
    while (force_quit) {
        item_t item = sbuf_remove(sp);
     //   printf("---force_quit is %d\n",force_quit);
        switch (item.switch_id) {
            case 1:
                if (item.ingress_port_id == 0 && item.egress_port_id == 1) {
                    pthread_mutex_lock(&data1.mutex);
                    cal(&data1.cnt1,&data1.sum1,item);
                    pthread_mutex_unlock(&data1.mutex);
                }
                break;
            case 2:
                if (item.ingress_port_id == 0 && item.egress_port_id == 1) {
                    pthread_mutex_lock(&data1.mutex);
                    cal(&data1.cnt2,&data1.sum2,item);
                    pthread_mutex_unlock(&data1.mutex);
                }
                break;
            case 3:
                if (item.ingress_port_id == 0 && item.egress_port_id == 0x0300) {
                    pthread_mutex_lock(&data1.mutex);
                    cal(&data1.cnt3,&data1.sum3,item);
                    pthread_mutex_unlock(&data1.mutex);
                }
                break;
            case 4:
                if (item.ingress_port_id == 0 && item.egress_port_id == 4) {
                    pthread_mutex_lock(&data1.mutex);
                    cal(&data1.cnt4,&data1.sum4,item);
                    pthread_mutex_unlock(&data1.mutex);
                }
                if (item.ingress_port_id == 1 && item.egress_port_id == 4) {
                    pthread_mutex_lock(&data1.mutex);
                    cal(&data1.cnt5,&data1.sum5,item);
                    pthread_mutex_unlock(&data1.mutex);
                }
            case 0x000000F1:
                //Barefoot Tofino
                if (item.ingress_port_id == 160 && item.egress_port_id == 36) {
                    pthread_mutex_lock(&data1.mutex);
                    cal_tofino(&data1.tofino_cnt6,&data1.tofino_q_occupancy_sum6,&data1.tofino_hop_latency_sum6,
                            &data1.optical_power_sum6,&data1.optical_osnr_sum6,
                            &data1.optical_power_sum5,&data1.optical_osnr_sum5,&data1.counter,item);
                    pthread_mutex_unlock(&data1.mutex);
                }

                break;
            default:
                break;
        }
    }
    printf("force_quit is %d write exit\n",force_quit);
    return NULL;
}

static void *print_func(void) {
    while(force_quit) {
 //       printf("force_quit is %d\n",force_quit);
        usleep(200000L);
        pthread_mutex_lock(&data1.mutex);

        //printf("--switch,0x01,avgs,latency(0,1) %f\n", data1.sum1 / data1.cnt1);
        //printf("--switch 0x02 avgs latency(0,1) %f\n", data1.sum2 / data1.cnt2);
        //printf("--switch,0x03,avgs,latency(0,v0.0) %f\n", data1.sum3 / data1.cnt3);
        //printf("--switch 0x03 avgs drop(0,v0.0) %f\n", data1.counter / data1.cnt3);
        //printf("--switch 0x04 avgs latency(0,4) %f\n", data1.sum4 / data1.cnt4);
        //printf("--switch 0x04 avgs latency(1,4) %f\n", data1.sum5 / data1.cnt5);
#ifdef TX
        printf("--switch 0x01 avgs tx(1,4) %f\n", data1.nic_tx_1 / data1.cnt1);
        printf("--switch 0x02 avgs tx(1,4) %f\n", data1.nic_tx_2 / data1.cnt2);
        printf("--switch 0x03 avgs tx(0,4) %f\n", data1.nic_tx_3 / data1.cnt3);
        printf("--switch 0x04 avgs tx(1,4) %f\n", data1.nic_tx_4 / data1.cnt4);
        printf("--switch 0x04 avgs tx(1,4) %f\n", data1.nic_tx_5 / data1.cnt5);
#endif
       // printf("--tofino,0xF1,avg,latency(160,36) %f\n", data1.tofino_hop_latency_sum6 / data1.tofino_cnt6);
        //printf("--tofino,0xF1,avg,occupancy(160,36) %f\n", data1.tofino_q_occupancy_sum6 / data1.tofino_cnt6);
//
//
        //printf("--tofino,0xF1,optical,OCM,avg,power(0,1)%f\n", data1.optical_power_sum6 / data1.tofino_cnt6);
//
        //printf("--tofino,0xF1,optical,OCM,avg,osnr(0,1)%f\n", data1.optical_osnr_sum6 / data1.tofino_cnt6);
        //printf("--tofino,0xF1,optical,OSA,avg,osnr(0,1)%f\n", data1.optical_osnr_sum5 / data1.tofino_cnt6);
        //printf("--tofino,0xF1,optical,OSA,avg,osnr(0,1)%f\n", data1.optical_osnr_sum5 / data1.tofino_cnt6);

        //printf("%10f,%10f\n",data1.optical_power_sum6 / data1.tofino_cnt6,data1.optical_osnr_sum6 / data1.tofino_cnt6);
        //tofino latency | tofino queue size | nic1 latency | nic2 latency | ocm power | ocm osnr | osa power | osa osnr
        printf("%f %f %f %f %f %f %f %f\n",data1.tofino_hop_latency_sum6 / data1.tofino_cnt6,
                data1.tofino_q_occupancy_sum6 / data1.tofino_cnt6,data1.sum1/data1.cnt1,data1.sum3/data1.cnt3,
                data1.optical_power_sum6/data1.tofino_cnt6,data1.optical_osnr_sum6/data1.tofino_cnt6,
                data1.optical_power_sum5/data1.tofino_cnt6,data1.optical_osnr_sum5/data1.tofino_cnt6);
        memset(&data1, 0, sizeof(struct data));
        pthread_mutex_unlock(&data1.mutex);
    }
    printf("force_quit is %d print exit\n",force_quit);

    return NULL;
}

void free_func(int sig) {
    if (sig == SIGINT) {
       // fflush(fp_all);
        force_quit = 0;
    }
}

unsigned  long long last_time = 0;
void thread_senddata(void) //send data by this socket
{

    int slisten = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); //TCP
    if (slisten == -1)
    {
        printf("socket error");
    }

    //bind ip and port
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(MYPORT);
    sin.sin_addr.s_addr = inet_addr("192.168.108.40");
    if (bind(slisten, (struct sockaddr*)&sin, sizeof(sin)) == -1)
    {
        printf("bind error");
    }

    //listen
    if (listen(slisten, MAX_CONNECT_NUM) == -1)
    {
        printf("listen error");
    }

    //accept

    struct sockaddr_in remoteAddr; //
    int nAddrlen = sizeof(remoteAddr);
    printf("wati to connect...\n");

    sClient = accept(slisten, (struct sockaddr *)&remoteAddr, &nAddrlen);
    if (sClient == -1)
    {
        printf("accept error");
    }

    printf("receive a connector :%s \r\n", inet_ntoa(remoteAddr.sin_addr));

    printf("thread\n");
    sleep(1);
    unsigned  long long during_kjw ;
    unsigned  long long start_kjw = rp_get_us();
    while(1) {
        unsigned long long now = rp_get_us();
        if ((instructions2 == 3)&&(now - last_time > 10000)) {
            now = rp_get_us();
            needSend *SendData = (needSend *) malloc(sizeof(needSend));
            char *sendbuffer = (char *) malloc(sizeof(needSend));
            //  printf("%d\n", total_int_header);
            for (int i = 0; i < (total_int_header - 1); i++) {

                unsigned  long long now_kjw = rp_get_us();

                during_kjw = now_kjw - start_kjw;
                if(i != 0) {                    
                    fprintf(fp_all, "%d\t%d\t%d\t%d\t%f\n", device_array[i], latency_array[i], power_array[i],
                            osnr_array[i], during_kjw / 1000000.0);
                }
                force_flush++;
                if (force_flush > FORCE_FLUSH_THRESH) {
                    fflush(fp_all);
                    force_flush = 0;
                }
                SendData->device = device_array[i];
                SendData->latency_sta = latency_array[i];
                SendData->optical_power_sta = power_array[i];
                SendData->optical_osnr_sta = osnr_array[i];
                //   printf("senddata:%d\n",SendData->optical_power_sta);
                memcpy(sendbuffer, SendData, sizeof(needSend));
                // printf("%s",*sendbuffer);
                //  printf("%d",sizeof(needSend));
                int length = send(sClient, sendbuffer, sizeof(needSend), 0);
                if (length < 0) {
                    printf("send error\n");

                }
                else{

                }
                last_time = now;
            }
        }
    }
}

void thread_senddata(void);
int main(int __attribute_unused__ argc, char __attribute_unused__ **argv) {
    //while(1){
    //    unsigned long long  now = rp_get_us();
    //    printf("now:%d\n",now);
     //   sleep(1);
    //}
//free
//socket

  //initialize socket



    fp_all =fopen("kjwcollect.txt","w+");
    signal(SIGINT,free_func);
    signal(SIGTERM,free_func);
    init_pcap();
    unsigned char *pkt = NULL;
    struct pcap_pkthdr pcap_hdr;
   // sbuf_t s;
   // sp = &s;
   // sbuf_init(sp, sizeof(item_t)*1024L);
   // printf("%d\n",force_quit);
    //fprintf(fp_all,"devices\t latency\t power\t osnr\t time\n");
    //thread
    pthread_t  pthread1;
    int ret = pthread_create(&pthread1, NULL, (void*)thread_senddata, NULL);
    if(ret!=0)
    {
        printf("Create pthread error!\n");
    }
   // printf("success1\n");
#ifdef TEST
    while (1) {
        while((pkt = (unsigned char * )pcap_next( pcap, &pcap_hdr))!=NULL) {
            process_int_pkt((unsigned char*)mysql, NULL, pkt);
            unsigned long long time1 = rp_get_us();
            printf("---BEGIN: %ld us\n",time1);
        }
    }
#else
    while (force_quit && (pkt = (unsigned char *)pcap_next( pcap, &pcap_hdr)) != NULL) {

       // print_pkt(128, pkt);
        process_int_pkt(NULL, NULL, pkt);
       // printf("123\n");
    }
#endif
  //  sbuf_free(sp);
  //  printf("sbuf is cleaned\n");
    if (pcap) {
        pcap_close(pcap);
        printf("pcap is closed\n");
    }
    printf("Ending\n");
    fclose(fp_all);
    exit(EXIT_SUCCESS);
}
