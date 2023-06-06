#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "common.h"
#include "ip.h"
#include "lwip/apps/httpd.h"
#include "lwip/arch.h"
#include "lwip/dhcp.h"
#include "lwip/etharp.h"
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/opt.h"
#include "lwip/timeouts.h"
#include "lwip_common.h"

int main(int argc, char *argv[]) {
  set_ip(server_ip_s, client_ip_s);
  parse_argv(argc, argv);

  // init lwip
  setup_lwip(server_ip_s);

  httpd_init();

  const size_t buffer_size = 2048;
  u8_t buffer[buffer_size];
  while (1) {
    ssize_t size = recv_packet(buffer, buffer_size);
    if (size >= 0) {
      // got data
      struct pbuf *p = pbuf_alloc(PBUF_RAW, size, PBUF_POOL);
      memcpy(p->payload, buffer, size);

      if (netif.input(p, &netif) != ERR_OK) {
        pbuf_free(p);
      }
    }
    fflush(stdout);
    sys_check_timeouts();
    loop_yield();
  }
  return 0;
}
