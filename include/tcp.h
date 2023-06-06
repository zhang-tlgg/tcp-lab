#ifndef __TCP_H__
#define __TCP_H__

#include "common.h"
#include "ip.h"
#include <map>
#include <queue>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <vector>

// default MSS is MTU - 20 - 20 for TCP over IPv4
#define DEFAULT_MSS (MTU - 20 - 20)

// taken from linux source include/uapi/linux/tcp.h
// RFC793 Page 15
struct TCPHeader {
  be16_t source;
  be16_t dest;
  be32_t seq;
  be32_t ack_seq;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  unsigned int res1 : 4;
  unsigned int doff : 4;
  unsigned int fin : 1;
  unsigned int syn : 1;
  unsigned int rst : 1;
  unsigned int psh : 1;
  unsigned int ack : 1;
  unsigned int urg : 1;
  unsigned int ece : 1;
  unsigned int cwr : 1;
#endif
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  unsigned int doff : 4;
  unsigned int res1 : 4;
  unsigned int cwr : 1;
  unsigned int ece : 1;
  unsigned int urg : 1;
  unsigned int ack : 1;
  unsigned int psh : 1;
  unsigned int rst : 1;
  unsigned int syn : 1;
  unsigned int fin : 1;
#endif
  be16_t window;
  be16_t checksum;
  be16_t urg_ptr;
};

// RFC793 Page 21
// https://www.rfc-editor.org/rfc/rfc793.html#page-21
enum TCPState {
  LISTEN,
  SYN_SENT,
  SYN_RCVD,
  ESTABLISHED,
  FIN_WAIT_1,
  FIN_WAIT_2,
  CLOSE_WAIT,
  CLOSING,
  LAST_ACK,
  TIME_WAIT,
  CLOSED,
};

const size_t RECV_BUFF_SIZE = 10240;
const size_t SEND_BUFF_SIZE = 10240;

// Transmission Control Block
// rfc793 Page 10 Section 3.2
struct TCP {
  // (local_ip, remote_ip, local_port, remote_port) tuple
  // 0 means wildcard
  be32_t local_ip;
  be32_t remote_ip;
  uint16_t local_port;
  uint16_t remote_port;
  TCPState state;

  // send & recv buffers
  // ring buffers from [begin, begin+size)
  RingBuffer<SEND_BUFF_SIZE> send;
  RingBuffer<RECV_BUFF_SIZE> recv;

  // mss(maximum segment size): maximum of TCP payload(excluding TCP and IP
  // headers). default: 536. max(ipv4): mtu - 20(ipv4) - 20(tcp). max(ipv6): mtu
  // - 40(ipv6) - 20(tcp). only advertised in SYN packet. see rfc6691.
  uint16_t local_mss;
  uint16_t remote_mss;

  // see rfc793 page 20 fig 4 send sequence space
  // https://www.rfc-editor.org/rfc/rfc793.html#page-20
  // acknowledged: seq < snd_una
  // sent but not acknowledged: snd_una <= seq < snd_nxt
  // allowed for new data transmission: snd_nxt <= seq < snd_una+snd_wnd
  uint32_t snd_una;
  uint32_t snd_nxt;
  uint32_t snd_wnd; // constrained by remote
  uint32_t snd_wl1;
  uint32_t snd_wl2;
  uint32_t iss; // initial send sequence number

  // see rfc793 page 20 fig 5 recv sequence space
  // https://www.rfc-editor.org/rfc/rfc793.html#page-20
  uint32_t rcv_nxt;
  // when out of order is unsupported,
  // rcv_wnd always equals to this->recv.free_bytes()
  uint32_t rcv_wnd;
  uint32_t irs; // initial recv sequence number

  // pending accept queue
  std::deque<int> accept_queue;

  // slow start and congestion avoidance
  uint32_t cwnd;
  uint32_t ssthresh;

  TCP() { state = TCPState::CLOSED; }

  // state transition with debug output
  void set_state(TCPState new_state);
};

extern std::vector<TCP *> tcp_connections;

// convert tcp state to string
const char *tcp_state_to_string(TCPState state);

// generate initial seq
uint32_t generate_initial_seq();

// process received TCP
void process_tcp(const IPHeader *ip, const uint8_t *data, size_t size);

// calc TCP checksum
void update_tcp_checksum(const IPHeader *ip, TCPHeader *tcp);

// verify TCP checksum
bool verify_tcp_checksum(const IPHeader *ip, const TCPHeader *tcp);

// tcp sequence number comparisons
// rfc793 page 24
// https://www.rfc-editor.org/rfc/rfc793.html#page-24
// "The symbol "=<" means "less than or equal (modulo 2**32)."
bool tcp_seq_lt(uint32_t a, uint32_t b);
bool tcp_seq_le(uint32_t a, uint32_t b);
bool tcp_seq_gt(uint32_t a, uint32_t b);
bool tcp_seq_ge(uint32_t a, uint32_t b);

// functions for tcp user

// returns fd
int tcp_socket();

// TCP connect (OPEN call)
void tcp_connect(int fd, be32_t dst_addr, uint16_t dst_port);

// write data to TCP (SEND call)
// returns the bytes written
ssize_t tcp_write(int fd, const uint8_t *data, size_t size);

// read data from TCP (RECEIVE call)
// returns the bytes read
ssize_t tcp_read(int fd, uint8_t *data, size_t size);

// shutdown TCP connection
void tcp_shutdown(int fd);

// closes and free fd
void tcp_close(int fd);

// bind socket to TCP port
void tcp_bind(int fd, be32_t addr, uint16_t port);

// enter listen state
void tcp_listen(int fd);

// accept TCP connection if exists
// return new fd if a client is connecting, otherwise -1
int tcp_accept(int fd);

// get tcp state
TCPState tcp_state(int fd);

#endif