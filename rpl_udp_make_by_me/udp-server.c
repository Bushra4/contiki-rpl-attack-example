#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ip/uip.h"
#include "net/rpl/rpl.h"

#include "net/netstack.h"
#include "dev/button-sensor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#define UIP_IP_BUF ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])

#define UDP_CLIENT_PORT 1234
#define UDP_SERVER_PORT 4321

#define UDP_EXAMPLE_ID 100

static struct uip_udp_conn *server_conn;

PROCESS(udp_server_process, "UDP SERVER PROCESS");
AUTOSTART_PROCESSES(&udp_server_process);
/*---------------------------------------------------------------------------*/
static void tcpip_handler(void) {
    char *appdata;
    if(uip_newdata()) {
        appdata = (char *)uip_appdata;
        appdata[uip_datalen()] = 0;
        PRINTF("DATA recv '%s' from ",appdata);
        PRINTF("%d", UIP_IP_BUF->srcipaddr.u8[sizeof(UIP_IP_BUF->srcipaddr.u8) - 1]);
        PRINTF("\n");
    }
#if SERVER_REPLY
    PRINTF("DATA sending reply\n");
    uip_ipaddr_copy(&server_conn->ripaddr, &UIP_IP_BUF->srcipaddr);
    uip_udp_packet_send(server_conn, "Reply", sizeof("Reply"));
    uip_create_unspecified(&server_conn->ripaddr);
#endif
}
/*---------------------------------------------------------------------------*/
static void print_local_addresses(void) {
    int i;
    uint8_t state;
    PRINTF("Server IPv6 addresses: ");
    for(i = 0; i < UIP_DS6_AADDR_NB; i++) {
        state = uip_ds6_if.addr_list[i].state;
        if (state == ADDR_TENTATIVE || ADDR_PREFERRED) {
            PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
            PRINTF("\n");
            if (state == ADDR_TENTATIVE) {
                uip_ds6_if.addr_list[i].state = ADDR_PREFERRED;
            }
        /* hack to make address "final" */
        }
    }
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_server_process, ev, data) 
{
    uip_ipaddr_t ipaddr;
    struct uip_ds6_addr *root_if;

    PROCESS_BEGIN();

    PROCESS_PAUSE();

    SENSORS_ACTIVATE(button_sensor);

    PRINTF("UDP server stated. nbr: %d routes: %d\n", NBR_TABLE_CONF_MAX_NEIGHBORS, UIP_CONF_MAX_ROUTES);

#if UIP_CONF_ROUTER
#if 0
#elif 1
    uip_ip6addr(&ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0x00ff, 0xfe00, 1);
#endif

    uip_ds6_addr_add(&ipaddr, 0, ADDR_MANUAL);
    root_if = uip_ds6_addr_lookup(&ipaddr);
    if(root_if != NULL) {
        rpl_dag_t *dag;
        dag = rpl_set_root(RPL_DEFAULT_INSTANCE, (uip_ip6addr_t *)&ipaddr);
        uip_ip6addr(&ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 0);
        rpl_set_prefix(dag, &ipaddr, 64);
        PRINTF("create a new RPL dag\n");
    }
    else {
        PRINTF("failed to create a new RPL DAG\n");
    }
#endif
    print_local_addresses();

    NETSTACK_MAC.off(1);

    server_conn = udp_new(NULL, UIP_HTONS(UDP_CLIENT_PORT), NULL);
    if(server_conn == NULL) {
        PRINTF("NO UDP connection available, exiting the process!\n");
        PROCESS_EXIT();
    }

    udp_bind(server_conn, UIP_HTONS(UDP_SERVER_PORT));

    PRINTF("Created a server connection with remote address ");
    PRINT6ADDR(&server_conn->ripaddr);
    PRINTF(" local/remote port %u/%u\n", UIP_HTONS(server_conn->lport), UIP_HTONS(server_conn->rport));

    while(1) {
        PROCESS_YIELD();
        if (ev = tcpip_event) {
            tcpip_handler();
        } else if (ev = sensors_event && data == &button_sensor) {
            PRINTF("Initiating global repair\n");
            rpl_repair_root(RPL_DEFAULT_INSTANCE);
        }
    }

    PROCESS_END();
}