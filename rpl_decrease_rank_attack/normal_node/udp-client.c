#include "contiki.h"
#include "lib/random.h"
#include "sys/etimer.h"
#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ip/uip-udp-packet.h"
#include "net/rpl/rpl.h"

#if CONTIKI_TARGET_Z1
#include "dev/uart0.h"
#else
#include "dev/uart1.h"
#endif
#include "collect-common.h"
#include "collect-view.h"

#include <stdio.h>
#include <string.h>

#include "dev/serial-line.h"
#include "net/ipv6/uip-ds6-route.h"

#define UDP_CLIENT_PORT 1234
#define UDP_SERVER_PORT 4321

#define DEBUG DEBUG_FULL
#include "net/ip/uip-debug.h"

#define SEND_INTERVAL (30 * CLOCK_SECOND)
#define SEND_TIME (random_rand() % (SEND_INTERVAL))

static struct uip_udp_conn *client_conn;
static uip_ipaddr_t server_ipaddr;

/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "UDP client process");
AUTOSTART_PROCESSES(&udp_client_process);
/*---------------------------------------------------------------------------*/
void collect_common_set_sink(void) {
    /* A UDP client can never become sink */
}
/*---------------------------------------------------------------------------*/
void collect_common_net_print(void) {
    
    rpl_dag_t *dag;
    uip_ds6_route_t *r;

    /* Let's suppose we have only one instance */
    dag = rpl_get_any_dag();
    if(dag->preferred_parent != NULL) {
        PRINTF("Preferred parent: ");
        PRINT6ADDR(rpl_get_parent_ipaddr(dag->preferred_parent));
        PRINTF("\n");
    }
    for(r = uip_ds6_route_head();
        r != NULL;
        r = uip_ds6_route_next(r)) {
            PRINT6ADDR(&r->ipaddr);
    } 
    PRINTF("---\n");
}
/*---------------------------------------------------------------------------*/
void collect_common_send(void) {
    static uint8_t seqno;
    struct {
        uint8_t seqno;
        uint8_t for_alignment;
        struct collect_view_data_msg msg;
    } msg;
    
    uint8_t parent_etx;
    uint8_t rtmetric;
    uint16_t num_neighbors;
    uint16_t beacon_interval;
    rpl_parent_t *preferred_parent;
    linkaddr_t parent;
    rpl_dag_t *dag;
    
    if(client_conn == NULL) {
        return;
    }
    memset(&msg, 0, sizeof(msg));
    seqno++;
    if(seqno == 0) {
        /* Wrap to 128 to identify restarts */
        seqno = 128;
    } 

    msg.seqno = seqno;

    linkaddr_copy(&parent, &linkaddr_null);
    parent_etx = 0;

    /* Let's suppose we have only one instance */
    dag = rpl_get_any_dag();
    if(dag != NULL){
        preferred_parent = dag->preferred_parent;
        if(preferred_parent != NULL) {
            uip_ds6_nbr_t *nbr;
            nbr = uip_ds6_nbr_lookup(rpl_get_parent_ipaddr(preferred_parent));
            if(nbr != NULL) {
                /* Use parts of the IPv6 address as the parent address, in resersed byte order. */
                parent.u8[LINKADDR_SIZE - 1] = nbr->ipaddr.u8[sizeof(uip_ipaddr_t) - 2];
                parent.u8[LINKADDR_SIZE - 2] = nbr->ipaddr.u8[sizeof(uip_ipaddr_t) - 1];
                parent_etx = rpl_get_parent_rank((uip_lladdr_t *)uip_ds6_nbr_get_ll(nbr)) / 2;
            }
        }
        rtmetric = dag->rank;
        beacon_interval = (uint16_t) ((2L << dag->instance->dio_intcurrent) / 1000);
        num_neighbors = uip_ds6_nbr_num();
    }
    else {
        rtmetric = 0;
        beacon_interval = 0;
        num_neighbors = 0;
    }

    collect_view_construct_message(&msg.msg, &parent,
                                   parent_etx, rtmetric,
                                   num_neighbors, beacon_interval);

    uip_udp_packet_sendto(client_conn, &msg, sizeof(msg),
                          &server_ipaddr, UIP_HTONS(UDP_SERVER_PORT));
}
/*---------------------------------------------------------------------------*/
void collect_common_net_init(void) {
    
#if CONTIKI_TARGET_Z1  
    uart0_set_input(serial_line_input_byte);
#else
    uart1_set_input(serial_line_input_byte);
#endif
    serial_line_init();
}
/*---------------------------------------------------------------------------*/

static void print_parrent_ipaddr(void) {
    rpl_dag_t *dag;
    dag = rpl_get_any_dag();
    if(dag != NULL) {
        rpl_parent_t *preferred_parrent;
        preferred_parrent = dag->preferred_parent;
        if(preferred_parrent != NULL) {
            PRINTF("Parrent's ip address: ");
            PRINT6ADDR(rpl_get_parent_ipaddr(preferred_parrent));
            PRINTF("\n");
        }
    }
}
/*---------------------------------------------------------------------------*/
static void print_local_addresses(void) {
    int i;
    uint8_t state;
    PRINTF("Client IPv6 addresses: ");
    for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
        state = uip_ds6_if.addr_list[i].state;
        if(uip_ds6_if.addr_list[i].isused && 
            (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
                PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
                PRINTF("\n");
                if(state == ADDR_TENTATIVE) {
                    uip_ds6_if.addr_list[i].state = ADDR_PREFERRED;
                }
        }
    }
}
/*---------------------------------------------------------------------------*/
static void set_global_address(void) {

    uip_ipaddr_t ipaddr;
    
    uip_ip6addr(&ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 0);
    uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
    uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

/*
    The choice of server address determines its 6LowPAN header compression.
    (Our address will be compressed Mode 3 since it is derived from our
    link-local address)
    Obviously the choice made here must also be selected in udp-server.c.

    For correct Wireshark decoding using a sniffer, and the /64 prefix to the
    6LowPAN protocol preferences,
    e.g. set Context 0 to fd00::. At present Wireshark copies Context/128 and
    then overwrites it.
    (Setting Context 0 to fd00::1111:2222:3333:4444 will report a 16 bit
    compressed address of fd00::1111:22ff:fe33:xxxx)

    Note the ICMPv6 checksum verification depends on the correct uncompressed
    addresses.
*/
// #if 0
// /* Mode 1 - 64 bits inline */
//     uip_ip6addr(&server_ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 1);
// #elif 1
// /* Mode 2 - 16 bits inline */
//     uip_ip6addr(&server_ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0x00ff, 0xfe00, 1);
// #else
// /* Mode 3 - derived from server link-local (MAC) address */
//     uip_ip6addr(&server_ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0x0250, 0xfea8, 0xcd1a);   //redbee-econotag
// #endif
    uip_ip6addr(&server_ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 1);
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data) {
    
    static struct etimer period_timer, send_timer;

    PROCESS_BEGIN();

    PROCESS_PAUSE();

    set_global_address();

    PRINTF("UDP client process started nbr:%d routes %d\n",
            NBR_TABLE_CONF_MAX_NEIGHBORS, UIP_CONF_MAX_ROUTES);
    print_local_addresses();

    /* new connection with remote host */
    client_conn = udp_new(NULL, UIP_HTONS(UDP_SERVER_PORT), NULL);
    if(client_conn == NULL) {
        PRINTF("No UDP connection available, exiting the process!");
        PROCESS_EXIT();
    }
    udp_bind(client_conn, UIP_HTONS(UDP_CLIENT_PORT));

    PRINTF("Created a connection with the server ");
    PRINT6ADDR(&client_conn->ripaddr);
    PRINTF(" local/remote port %u/%u\n",
            UIP_HTONS(client_conn->lport), UIP_HTONS(client_conn->rport));

    etimer_set(&period_timer, SEND_INTERVAL);

    while(1) {
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&period_timer));
        etimer_reset(&period_timer);
        etimer_set(&send_timer, SEND_TIME);
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&send_timer));
        print_parrent_ipaddr();
    }

    PROCESS_END();
}