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

// gracefully close socket and exit when closed
struct close_and_exit {
  int fd;
  size_t operator()() {
    TCPState state = tcp_state(fd);
    // gracefully shutdown
    if (state == TCPState::CLOSED) {
      tcp_close(fd);
      exit(0);
      return -1;
    } else {
      tcp_shutdown(fd);
      return 100;
    }
  }
};

// read http response
struct read_http_response {
  int fd;
  // output file
  FILE *fp;
  // parsing state
  bool http_response_header_done = false;
  std::vector<uint8_t> read_http_response;
  int content_length = -1;
  int read_body_length = 0;

  int operator()() {
    char buffer[1024];
    ssize_t res = tcp_read(fd, (uint8_t *)buffer, sizeof(buffer) - 1);
    if (res > 0) {
      printf("Read '");
      fwrite(buffer, 1, res, stdout);
      printf("' from tcp\n");

      read_http_response.insert(read_http_response.end(), &buffer[0],
                                &buffer[res]);
      if (!http_response_header_done) {
        // find consecutive \r\n\r\n
        for (size_t i = 0; i + 3 < read_http_response.size(); i++) {
          if (read_http_response[i] == '\r' &&
              read_http_response[i + 1] == '\n' &&
              read_http_response[i + 2] == '\r' &&
              read_http_response[i + 3] == '\n') {
            http_response_header_done = true;
            std::string resp((char *)read_http_response.data(),
                             read_http_response.size());

            // find content length
            std::string content_length_header = "Content-Length: ";
            size_t pos = resp.find(content_length_header);
            assert(pos != std::string::npos);
            sscanf(&resp[pos + content_length_header.length()], "%d",
                   &content_length);
            printf("Content Length is %d\n", content_length);
            assert(content_length >= 0);

            // check if body is long enough
            int body_size = read_http_response.size() - i - 4;
            read_body_length += body_size;
            fwrite(&read_http_response[i + 4], 1, body_size, fp);

            break;
          }
        }
      } else {
        // write to file
        read_body_length += res;
        fwrite(buffer, 1, res, fp);
      }
      fflush(fp);

      if (read_body_length >= content_length && content_length != -1) {
        // done
        close_and_exit fn;
        fn.fd = fd;
        TIMERS.schedule_job(fn, 0);
        return -1;
      }
    }

    // try to read next data
    return 100;
  }
};

int main(int argc, char *argv[]) {
  set_ip(client_ip_s, server_ip_s);
  parse_argv(argc, argv);

  // create socket and connect to server port 80
  int tcp_fd = tcp_socket();
  tcp_connect(tcp_fd, server_ip, 80);

  // always try to read from tcp
  // and write to stdout & file
  FILE *fp = fopen("index.html", "w");
  assert(fp);
  char *pwd = getenv("PWD");
  printf("Writing http response body to %s/index.html\n", pwd);

  read_http_response read_fn;
  read_fn.fd = tcp_fd;
  read_fn.fp = fp;
  TIMERS.schedule_job(read_fn, 1000);

  // write HTTP request line by line every 1s
  const char *data[] = {
      "GET /index.html HTTP/1.1\r\n",
      "Accept: */*\r\n",
      "Host: 10.0.0.1\r\n",
      "Connection: Close\r\n",
      "\r\n",
  };
  int index = 0;
  size_t offset = 0;
  timer_fn write_fn = [&] {
    if (tcp_state(tcp_fd) == TCPState::CLOSED) {
      printf("Connection closed\n");
      return -1;
    }
    if (tcp_state(tcp_fd) != TCPState::ESTABLISHED) {
      printf("Waiting for connection establishment\n");
      return 1000;
    }

    const char *p = data[index];
    size_t len = strlen(p);
    ssize_t res = tcp_write(tcp_fd, (const uint8_t *)p + offset, len - offset);
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
      return -1;
    }
  };
  TIMERS.schedule_job(write_fn, 1000);

  // main loop
  const size_t buffer_size = 2048;
  uint8_t buffer[buffer_size];
  while (1) {
    ssize_t size = recv_packet(buffer, buffer_size);
    if (size >= 0) {
      // got data
      process_ip(buffer, size);
    }
    TIMERS.trigger();
  }
  return 0;
}
