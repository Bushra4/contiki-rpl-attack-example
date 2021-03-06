#include "contiki.h"
#include "lib/random.h"
#include "sys/ctimer.h"
#include "sys/etimer.h"
#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ip/uip-debug.h"

#include "sys/node-id.h"
#include "simple-udp.h"
#include "servreg-hack.h"

#include <stdio.h>
#include <string.h>

#define UDP_PORT 1234
#define SERVICE_ID 190

#define SEND_INTERVAL (60 * CLOCK_SECOND)
#define SEND_TIME (random_rand() % (SEND_INTERVAL))

static struct simple_udp_connection unicast_connection;

/*---------------------------------------------------------------------------*/
PROCESS(unicast_sender_process, "Unicast sender example process");
AUTOSTART_PROCESSES(&unicast_sender_process);
/*---------------------------------------------------------------------------*/
static void receiver(struct simple_udp_connection *c,
                        const uip_ipaddr_t *sender_addr,
                        uint16_t sender_port,
                        const uip_ipaddr_t *receiver_addr,
                        uint16_t receiver_port,
                        const uint8_t *data,
                        uint16_t datalen)
{
    printf("Data received on port %d from port %d with length %d\n",
            receiver_port, sender_port, datalen);
}

static void set_global_address(void) {
    
    uip_ipaddr_t ipaddr;
    int i;
    uint8_t state;

    // Construct an IPv6 address from eight 16-bits words
    uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
    // Set the last 64 bits of an IPv6 address based on the MAC address
    uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
    uip_ds6_addr_add(&ipaddr, 0,ADDR_AUTOCONF);

    printf("IPv6 addresses: ");
    for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
        state = uip_ds6_if.addr_list[i].state;
        if(uip_ds6_if.addr_list[i].isused && 
            (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
                uip_debug_ipaddr_print(&uip_ds6_if.addr_list[i].ipaddr);
                printf("\n");
        }
    }
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(unicast_sender_process, ev, data) {
    static struct etimer periodic_timer;
    static struct etimer send_timer;
    uip_ipaddr_t *addr;

    PROCESS_BEGIN();

    servreg_hack_init();

    set_global_address();

    simple_udp_register(&)
}