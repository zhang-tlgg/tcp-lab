#ifndef __LWIP_COMMON_H__
#define __LWIP_COMMON_H__

#include "lwip/netif.h"

extern struct netif netif;

// netif output handler
err_t netif_output(struct netif *netif, struct pbuf *p,
                   const ip4_addr_t *ipaddr);

// setup netif
void setup_lwip(const char *ip);
err_t netif_init_callback(struct netif *netif);

// create ip_addr_t from string
ip_addr_t ip4_from_string(const char *addr);

// yield until next timeout or 50ms
void loop_yield();

#endif