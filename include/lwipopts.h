#ifndef __LWIP_OPTS_H__
#define __LWIP_OPTS_H__

// enabled features:
#define LWIP_IPV4 1
#define LWIP_ARP 1
#define LWIP_TCP 1
#define LWIP_ICMP 1
#define LWIP_DHCP 1

// disabled features:
#define LWIP_SOCKET 0
#define LWIP_NETCONN 0
#define LWIP_IPV6 0
#define IP_FRAG 0

// debugging
#define LWIP_DEBUG 1
#define LWIP_DEBUG_TIMERNAMES 1
#define HTTPD_DEBUG LWIP_DBG_ON
#define HTTPC_DEBUG LWIP_DBG_ON
#define TCP_DEBUG LWIP_DBG_ON
#define TCP_WND_DEBUG LWIP_DBG_ON
#define TCP_OUTPUT_DEBUG LWIP_DBG_ON
#define TCP_RST_DEBUG LWIP_DBG_ON
#define TCP_INPUT_DEBUG LWIP_DBG_ON

// system related settings
#define SYS_LIGHTWEIGHT_PROT 0
#define MEM_LIBC_MALLOC 1
#define NO_SYS 1

#endif