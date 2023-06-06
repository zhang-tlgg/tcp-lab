#include <assert.h>
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
#include "tcp.h"
#include "timers.h"

struct write_response {
  int fd;
  int index = 0;
  size_t offset = 0;
  const char *data[5] = {
      "HTTP/1.1 200 OK\r\n",
      "Content-Length: 13\r\n",
      "Content-Type: text/plain; charset=utf-8\r\n",
      "\r\n",
      "Hello World!\n",
  };

  size_t operator()() {
    // write HTTP request line by line every 1s
    const char *p = data[index];
    size_t len = strlen(p);
    ssize_t res = tcp_write(fd, (const uint8_t *)p + offset, len - offset);
    if (res > 0) {
      printf("Write '%s' to tcp\n", p);
      offset += res;

      // write completed
      if (offset == len) {
        index++;
        offset = 0;
      }
    }

    // next data
    if (index < 5) {
      return 100;
    } else {
      // done, closing
      printf("Closing socket %d\n", fd);
      tcp_close(fd);
      return -1;
    }
  }
};

struct server_handler {
  int new_fd;
  std::vector<uint8_t> read_http_request;
  size_t operator()() {
    uint8_t buffer[1024];
    ssize_t res = tcp_read(new_fd, buffer, sizeof(buffer));
    if (res > 0) {
      printf("Read '");
      fwrite(buffer, res, 1, stdout);
      printf("' from tcp\n");

      // parse http request header
      read_http_request.insert(read_http_request.end(), &buffer[0],
                               &buffer[res]);
      // find consecutive \r\n\r\n
      for (size_t i = 0; i + 3 < read_http_request.size(); i++) {
        if (read_http_request[i] == '\r' && read_http_request[i + 1] == '\n' &&
            read_http_request[i + 2] == '\r' &&
            read_http_request[i + 3] == '\n') {
          // send response
          write_response write_fn;
          write_fn.fd = new_fd;
          TIMERS.schedule_job(write_fn, 1000);
          return 0;
        }
      }
    }

    // next data
    return 100;
  }
};

int main(int argc, char *argv[]) {
  set_ip(server_ip_s, client_ip_s);
  parse_argv(argc, argv);

  int listen_fd = tcp_socket();
  tcp_bind(listen_fd, server_ip, 80);
  tcp_listen(listen_fd);
  printf("Listening on 80 port\n");

  timer_fn accept_fn = [=]() {
    int new_fd = tcp_accept(listen_fd);
    if (new_fd >= 0) {
      printf("Got new TCP connection: fd=%d\n", new_fd);

      server_handler server_fn;
      server_fn.new_fd = new_fd;

      TIMERS.schedule_job(server_fn, 1000);
    }

    // next accept
    return 100;
  };
  TIMERS.schedule_job(accept_fn, 1000);

  // main loop
  const size_t buffer_size = 2048;
  uint8_t buffer[buffer_size];
  while (1) {
    ssize_t size = recv_packet(buffer, buffer_size);
    if (size >= 0) {
      // got data
      process_ip(buffer, size);
    }
    fflush(stdout);
    TIMERS.trigger();
  }
  return 0;
}