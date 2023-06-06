#ifndef __COMMON_H__
#define __COMMON_H__

#include <arpa/inet.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

// assume interface MTU is 1500 bytes
#define MTU 1500

// helper macros
#define UNIMPLEMENTED()                                                        \
  do {                                                                         \
    printf(RED "UNIMPLEMENTED at %s:%d\n" RESET, __FILE__, __LINE__);                    \
    exit(1);                                                                   \
  } while (0);

#define UNIMPLEMENTED_WARN()                                                   \
  do {                                                                         \
    printf(YEL "WARN: UNIMPLEMENTED at %s:%d\n" RESET, __FILE__, __LINE__);              \
  } while (0);

// useful types to mark endianness
// conversion between be{32,16}_t and other must use htons or ntohs
typedef uint32_t be32_t;
typedef uint16_t be16_t;

// domain socket to send ip packets
extern struct sockaddr_un remote_addr;
extern int socket_fd;
extern FILE *pcap_fp;

// configurable packet drop rate
// can be set in command line
extern double recv_drop_rate;
extern double send_drop_rate;

// configurable packet send delay in ms
extern double send_delay_min;
extern double send_delay_max;

// configurable congestion control algorithm
enum CongestionControlAlgorithm {
  Default,
  NewReno,
  CUBIC,
  BBR,
};
extern CongestionControlAlgorithm current_cc_algo;

// set socket to blocking/non-blocking
bool set_socket_blocking(int fd, bool blocking);

// create sockaddr_un from path
struct sockaddr_un create_sockaddr_un(const char *path);

// setup unix socket
int setup_unix_socket(const char *path);

// setup tun device
int open_device(std::string tun_name);

// set local/remote ip
void set_ip(const char *local_ip, const char *remote_ip);

// taken from https://wiki.wireshark.org/Development/LibpcapFileFormat
typedef struct pcap_header_s {
  uint32_t magic_number;
  uint16_t version_major;
  uint16_t version_minor;
  uint32_t thiszone;
  uint32_t sigfigs;
  uint32_t snaplen;
  uint32_t network;
} pcap_header_t;

typedef struct pcap_packet_header_s {
  uint32_t tv_sec;
  uint32_t tv_usec;
  uint32_t caplen;
  uint32_t len;
} pcap_packet_header_t;

// create pcap file
FILE *pcap_create(const char *path);

// write packet to pcap file
void pcap_write(FILE *fp, const uint8_t *data, size_t size);

// send packet to remote
void send_packet(const uint8_t *data, size_t size);

// recv packet from remote
ssize_t recv_packet(uint8_t *buffer, size_t buffer_size);

static inline size_t min(size_t a, size_t b) { return a > b ? b : a; }

template <size_t N> struct RingBuffer {
  // ring buffer from [begin, begin+size)
  uint8_t buffer[N];
  size_t begin;
  size_t size;

  RingBuffer() { begin = size = 0; }

  // write data to ring buffer
  size_t write(const uint8_t *data, size_t len) {
    size_t bytes_left = N - size;
    size_t bytes_written = min(bytes_left, len);
    // first part
    size_t part1_index = (begin + size) % N;
    size_t part1_size = min(N - part1_index, bytes_written);
    memcpy(&buffer[part1_index], data, part1_size);
    // second part if wrap around
    if (N - part1_index < bytes_written) {
      memcpy(&buffer[0], &data[part1_size], bytes_written - part1_size);
    }
    size += bytes_written;
    return bytes_written;
  }

  // read data from ring buffer
  size_t read(uint8_t *data, size_t len) {
    size_t bytes_read = min(size, len);
    // first part
    size_t part1_size = min(N - begin, bytes_read);
    memcpy(data, &buffer[begin], part1_size);
    // second part if wrap around
    if (N - begin < bytes_read) {
      memcpy(&data[part1_size], buffer, bytes_read - part1_size);
    }
    size -= bytes_read;
    begin = (begin + bytes_read) % N;
    return bytes_read;
  }

  size_t free_bytes() const { return N - size; }
};

void parse_argv(int argc, char *argv[]);

// ref: https://stackoverflow.com/a/3586005/2148614
// you can use these to colorize your output
#define RED "\x1B[31m"
#define GRN "\x1B[32m"
#define YEL "\x1B[33m"
#define BLU "\x1B[34m"
#define MAG "\x1B[35m"
#define CYN "\x1B[36m"
#define WHT "\x1B[37m"
#define RESET "\x1B[0m"

#endif