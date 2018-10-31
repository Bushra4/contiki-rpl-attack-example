#ifndef COLLECT_COMMON_H_
#define COLLECT_COMMON_H_

#include "contiki.h"
#include "net/linkaddr.h"

void collect_common_net_init(void);
void collect_common_net_print(void);
void collect_common_set_sink(void);
void collect_common_send(void);
void collect_common_recv(const linkaddr_t *originator, uint8_t seqno,
                         uint8_t hops,
                         uint8_t *payload,
                         uint16_t payload_len);
void collect_common_set_send_active(int active);

PROCESS_NAME(collect_common_process);
#endif