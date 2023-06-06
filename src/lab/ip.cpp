#include "ip.h"
#include "tcp.h"
#include <stdio.h>

void process_ip(const uint8_t *data, size_t size) {
  struct IPHeader *ip = (struct IPHeader *)data;
  if (ip->ip_v != 4) {
    printf("Unsupported IP version: %d\n", ip->ip_v);
    return;
  }

  if (ip->ip_hl * 4 > size) {
    printf("IP header length too large: %d > %zu\n", ip->ip_hl * 4, size);
    return;
  }

  if (!verify_ip_checksum(ip)) {
    printf("Bad IP header checksum\n");
    return;
  }

  if (ip->ip_off & 0x20) {
    printf("Got fragmented IP, not supported\n");
    return;
  }

  if (ip->ip_p == 6) {
    // TCP
    size_t header_size = ip->ip_hl * 4;
    process_tcp(ip, data + header_size, size - header_size);
  }
}

void update_ip_checksum(IPHeader *ip) {
  uint32_t checksum = 0;
  uint8_t *data = (uint8_t *)ip;
  ip->ip_sum = 0;
  for (int i = 0; i < ip->ip_hl * 2; i++) {
    checksum += (((uint32_t)data[i * 2]) << 8) + data[i * 2 + 1];
  }
  while (checksum >= 0x10000) {
    checksum -= 0x10000;
    checksum += 1;
  }
  // update
  ip->ip_sum = htons(~checksum);
}

bool verify_ip_checksum(const IPHeader *ip_hdr) {
  uint32_t checksum = 0;
  uint8_t *data = (uint8_t *)ip_hdr;
  for (int i = 0; i < ip_hdr->ip_hl * 2; i++) {
    checksum += (((uint32_t)data[i * 2]) << 8) + data[i * 2 + 1];
  }
  while (checksum >= 0x10000) {
    checksum -= 0x10000;
    checksum += 1;
  }
  return checksum == 0xffff;
}