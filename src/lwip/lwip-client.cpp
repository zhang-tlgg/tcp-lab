#include <errno.h>
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
#include "lwip/apps/http_client.h"
#include "lwip/arch.h"
#include "lwip/dhcp.h"
#include "lwip/etharp.h"
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/opt.h"
#include "lwip/timeouts.h"
#include "lwip_common.h"

// callbacks
err_t httpc_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {

  printf("HTTP Got Body:\n");

  // p might have next, don't use payload directly
  u8_t *buffer = (u8_t *)malloc(p->tot_len);
  pbuf_copy_partial(p, buffer, p->tot_len, 0);
  fwrite(buffer, p->tot_len, 1, stdout);

  free(buffer);
  return ERR_OK;
}

err_t httpc_headers_done(httpc_state_t *connection, void *arg, struct pbuf *hdr,
                         u16_t hdr_len, u32_t content_len) {
  printf("HTTP Got Headers:\n");

  // p might have next, don't use payload directly
  u8_t *buffer = (u8_t *)malloc(hdr->tot_len);
  pbuf_copy_partial(hdr, buffer, hdr->tot_len, 0);
  fwrite(buffer, hdr->tot_len, 1, stdout);

  printf("Header Length: %d\n", hdr_len);
  printf("Content Length: %d\n", hdr_len);

  free(buffer);
  return ERR_OK;
}

bool exiting = false;
void httpc_result(void *arg, httpc_result_t httpc_result, u32_t rx_content_len,
                  u32_t srv_res, err_t err) {
  printf("Server Result: %d\n", srv_res);
  printf("Content Length: %d\n", rx_content_len);
  printf("Exiting\n");
  exiting = true;
}

int main(int argc, char *argv[]) {
  set_ip(client_ip_s, server_ip_s);
  parse_argv(argc, argv);

  // init lwip
  setup_lwip(client_ip_s);

  ip_addr_t server_addr = ip4_from_string(server_ip_s);
  httpc_connection_t settings{0};
  settings.result_fn = httpc_result;
  settings.headers_done_fn = httpc_headers_done;
  httpc_get_file(&server_addr, 80, "/index.html", &settings, httpc_recv, NULL,
                 NULL);

  const size_t buffer_size = 2048;
  u8_t buffer[buffer_size];
  while (!exiting) {
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
