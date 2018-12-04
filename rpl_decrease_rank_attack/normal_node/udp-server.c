#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ip/uip.h"     // uip_newdata()
#include "net/rpl/rpl.h"
#include "net/linkaddr.h"

// for collect-view
#include "dev/serial-line.h"
#if CONTIKI_TARGET_Z1
#include "dev/uart0.h"
#else
#include "dev/uart1.h"
#endif
#include "collect-common.h"
#include "collect-view.h"

#include "net/netstack.h"
#include "dev/button-sensor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

// Data-link layer -> IEEE 802.15.4(MAC) -> MAC header length = 14
#define UIP_IP_BUF ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])

#define UDP_CLIENT_PORT 1234
#define UDP_SERVER_PORT 4321


static struct uip_udp_conn *server_conn;

/*
    PROCESS(name, strname);

    Every process should be defined via the PROCESS macro. PROCESS has two arguments:
    the variable of the process structure, and a human readable string name, which is
    used when debugging.
        + name: The variable name of the process structure
        + strname: The string representation of the process name  
*/
PROCESS(udp_server_process, "UDP SERVER PROCESS");

/*
    AUTOSTART_PROCEsS(struct process &);

    AUTOSTART_PROCESSES automatically starts the process(es) given in the argument(s)
    when the module boots
        + &name: Reference to the process name
*/
AUTOSTART_PROCESSES(&udp_server_process, &collect_common_process);
/*---------------------------------------------------------------------------*/
void collect_common_set_sink(void) {
    printf("I am sink!\n");
}
/*---------------------------------------------------------------------------*/
void collect_common_net_print(void) {
    printf("I am sink!\n");
}
void collect_common_send(void) {
    // Server never sends
}
void collect_common_net_init(void) {
#if CONTIKI_TARGET_Z1
    uart0_set_input(serial_line_input_byte);
#else  
    uart1_set_input(serial_line_input_byte);
#endif 
    serial_line_init();
    PRINTF("I am sink!\n");
}
/*---------------------------------------------------------------------------*/
static void tcpip_handler(void) {
    uint8_t *appdata;
    linkaddr_t sender;
    uint8_t seqno;
    uint8_t hops;
    
    if(uip_newdata()) { // Is new incoming data availabel?
        // for collect-view
        appdata = (uint8_t *)uip_appdata;
        sender.u8[0] = UIP_IP_BUF->srcipaddr.u8[15];
        sender.u8[1] = UIP_IP_BUF->srcipaddr.u8[14];
        seqno = *appdata;
        hops = uip_ds6_if.cur_hop_limit - UIP_IP_BUF->ttl + 1;
        collect_common_recv(&sender, seqno, hops, appdata + 2, uip_datalen() - 2);
    }
}
/*---------------------------------------------------------------------------*/
static void print_local_addresses(void) {
    int i;
    uint8_t state;
    PRINTF("Server IPv6 addresses: \n");
    for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
        state = uip_ds6_if.addr_list[i].state;
        if(state == ADDR_TENTATIVE || state == ADDR_PREFERRED){
            PRINTF("Address No %d: ", i);
            PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
            PRINTF("\n");
            if(state == ADDR_TENTATIVE) {
                uip_ds6_if.addr_list[i].state == ADDR_PREFERRED;
            }
        }
    }
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_server_process, ev, data) {
    uip_ipaddr_t ipaddr;
    struct uip_ds6_addr *root_if;

    PROCESS_BEGIN();

    PROCESS_PAUSE();

    SENSORS_ACTIVATE(button_sensor);

    PRINTF("UDP server started. nbr: %d routes: %d\n", NBR_TABLE_CONF_MAX_NEIGHBORS, UIP_CONF_MAX_ROUTES);

#if UIP_CONF_ROUTER
/*
    The choice of server address determines its 6LoWPAN header compression.
    Obviously the choice make here must also be selected in udp-client.c

    For correct Wireshark decoding using a sniffer, add the /64 prefix to the
    6LowPAN protocol preferences,
    e.g. set Context o to fd00::. At present Wireshark copies Context/128 and
    then overwrites it.
    (Setting Context 0 to fd00::1111:2222:3333:4444 will report a 16 bit
    compressed address of fd00:1111:22ff:fe33:xxxx)
    Note Wireshark's ICMPv6 checksum verification depends on the correct
    uncompressed addresses.
/* Mode 2 - 16 bits inline */
    uip_ip6addr(&ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 1);
    uip_ds6_addr_add(&ipaddr, 0, ADDR_MANUAL);
    root_if = uip_ds6_addr_lookup(&ipaddr);
    if(root_if != NULL) {
        rpl_dag_t *dag;
        dag = rpl_set_root(RPL_DEFAULT_INSTANCE, (uip_ip6addr_t *)&ipaddr);
        uip_ip6addr(&ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 0);
        rpl_set_prefix(dag, &ipaddr, 64);
        PRINTF("created a new RPL dag\n");
    }
    else {
        PRINTF("failed to create a new RPL DAG\n");
    }
#endif /* UIP_CONF_ROUTER */

    print_local_addresses();

    /* The data sink runs with a 100% duty cycle in order to ensure high
        packet reception rates. */
    NETSTACK_RDC.off(1);

    server_conn = udp_new(NULL, UIP_HTONS(UDP_CLIENT_PORT), NULL);
    udp_bind(server_conn, UIP_HTONS(UDP_SERVER_PORT));

    PRINTF("Created a server connection with remote address ");
    PRINT6ADDR(&server_conn->ripaddr);
    PRINTF(" local/remote port %u/%u\n", UIP_HTONS(server_conn->lport),
            UIP_HTONS(server_conn->rport));
    
    while(1) {
        PROCESS_YIELD();
        if(ev == tcpip_event) {
            tcpip_handler();
        }
        else if (ev = sensors_event && data == &button_sensor) {
            PRINTF("Initiating global repair\n");
            rpl_repair_root(RPL_DEFAULT_INSTANCE);
        }
    }

    PROCESS_END();
}
