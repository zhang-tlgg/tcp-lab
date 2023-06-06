#ifndef __IP_H__
#define __IP_H__

#include "common.h"

// taken from linux header netinet/ip.h
struct IPHeader {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  unsigned int ip_hl : 4; /* header length */
  unsigned int ip_v : 4;  /* version */
#endif
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  unsigned int ip_v : 4;  /* version */
  unsigned int ip_hl : 4; /* header length */
#endif
  uint8_t ip_tos;        /* type of service */
  be16_t ip_len;         /* total length */
  be16_t ip_id;          /* identification */
  be16_t ip_off;         /* fragment offset field */
  uint8_t ip_ttl;        /* time to live */
  uint8_t ip_p;          /* protocol */
  be16_t ip_sum;         /* checksum */
  be32_t ip_src, ip_dst; /* source and dest address */
};

// client address 10.0.0.2
const static be32_t client_ip = htonl(0x0a000002);
const static char *client_ip_s = "10.0.0.2";
// server address 10.0.0.1
const static be32_t server_ip = htonl(0x0a000001);
const static char *server_ip_s = "10.0.0.1";

// process received IP
void process_ip(const uint8_t *data, size_t size);

// update IP header checksum
void update_ip_checksum(IPHeader *ip_hdr);

// verify IP header checksum
bool verify_ip_checksum(const IPHeader *ip_hdr);

#endif