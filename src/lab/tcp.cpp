#include "tcp.h"
#include "common.h"
#include "timers.h"
#include <assert.h>
#include <map>
#include <stdio.h>

// mapping from fd to TCP connection
std::map<int, TCP *> tcp_fds;

// timer 计时器
struct Retransmission_timer {
  int fd;
  size_t operator()() {
    TCP *tcp = tcp_fds[fd];
    
    if (tcp->retransmission_queue.empty()) {
      return -1;
    } else {
      tcp->check_retransmission();
      return 2000;
    }
  }
};

struct Nagle_timer {
  int fd;
  size_t operator()() {
    TCP *tcp = tcp_fds[fd];

    if (tcp->nagle_buffer_size != 0) {
        if (2 * RTO < current_ts_msec() - tcp->nagle_time_last) {
          tcp->send_nagle_buffer();
          return -1;
        } else {
          return 1000;
        }
    }
  }
};

const char *tcp_state_to_string(TCPState state) {
  switch (state) {
  case TCPState::LISTEN:
    return "LISTEN";
  case TCPState::SYN_SENT:
    return "SYN_SENT";
  case TCPState::SYN_RCVD:
    return "SYN_RCVD";
  case TCPState::ESTABLISHED:
    return "ESTABLISHED";
  case TCPState::FIN_WAIT_1:
    return "FIN_WAIT_1";
  case TCPState::FIN_WAIT_2:
    return "FIN_WAIT_2";
  case TCPState::CLOSE_WAIT:
    return "CLOSE_WAIT";
  case TCPState::CLOSING:
    return "CLOSING";
  case TCPState::LAST_ACK:
    return "LAST_ACK";
  case TCPState::TIME_WAIT:
    return "TIME_WAIT";
  case TCPState::CLOSED:
    return "CLOSED";
  default:
    printf("Invalid TCPState\n");
    exit(1);
  }
}

void TCP::set_state(TCPState new_state) {
  // for unit tests
  printf("TCP state transitioned from %s to %s\n", tcp_state_to_string(state),
         tcp_state_to_string(new_state));
  fflush(stdout);
  state = new_state;
}

void TCP::set_reno_state(RenoState new_state) {
  fflush(stdout);
  reno_state = new_state;
}

void TCP::push_retransmission_queue(const uint8_t *buffer, const size_t header_length, const size_t body_length) {
  TCPHeader *tcp_hdr = (TCPHeader *)&buffer[20];
  uint32_t seq = ntohl(tcp_hdr->seq);
  uint8_t flag = 0;
  for (auto seg : retransmission_queue) {
    TCPHeader *seg_tcp_hdr = (TCPHeader *)&seg.buffer[20];
    uint32_t seg_seq = ntohl(seg_tcp_hdr->seq);
    if (seg_seq == seq) {
      flag = 1;
      break;
    }
  }
  if (flag == 0) {
    Segment new_seg = Segment(buffer, header_length, body_length, current_ts_msec());
    retransmission_queue.push_back(new_seg);
  }
}

void TCP::check_retransmission_queue(const uint32_t seg_ack) {
  ssize_t index = -1;
  for (ssize_t i = 0, iEnd = retransmission_queue.size(); i < iEnd; i++) {
    auto& seg = retransmission_queue[i];
    TCPHeader *tcp_hdr = (TCPHeader *)&seg.buffer[20];
    uint32_t seg_seq = ntohl(tcp_hdr->seq);
    // 重复的ACK，计算 repeat_ack
    if (seg_seq == seg_ack) {
      if (reno_state == RenoState::SLOW_START ||
          reno_state == RenoState::CONGESTION_AVOIDANCE) {
        // dupACKcount++
        seg.repeat_ack++;
        printf("seg_seq = %u seg_repeat_ack = %zu\n", seg_seq, seg.repeat_ack);
        // 连续收到3个重复的确认报文，进入快速恢复阶段
        if (seg.repeat_ack == 3) {
          set_reno_state(RenoState::FAST_RECOVERY);
          // ssthresh = cwnd / 2; cwnd = ssthresh + 3 * MSS
          ssthresh = cwnd >> 1;
          cwnd = ssthresh + 3 * DEFAULT_MSS;
          send_packet(seg.buffer, seg.header_length + seg.body_length);
        }
      } else {
        // 快速恢复阶段
        cwnd += DEFAULT_MSS;
      }
    }
    if (0 < seg.body_length) {
      if (seg_seq + seg.body_length == seg_ack) {
        index = i;
        break;
      }
    } else {
      if (seg_seq + 1 == seg_ack) {
        index = i;
        break;
      }
    }
  }
  // 收到新数据的确认
  if (index != -1) {
    retransmission_queue.erase(retransmission_queue.begin(), retransmission_queue.begin() + index + 1);
    // 慢启动 swnd += MSS
    if (reno_state == RenoState::SLOW_START) {
      cwnd += DEFAULT_MSS;
      // 状态转移
      if (cwnd == ssthresh) {
        set_reno_state(RenoState::CONGESTION_AVOIDANCE);
      }
    } 
    // 拥塞避免 cwnd += SMSS * SMSS / cwnd
    else if (reno_state == RenoState::CONGESTION_AVOIDANCE) {
      delta_cwnd += DEFAULT_MSS;
      if (delta_cwnd == cwnd) {
        cwnd += DEFAULT_MSS;
        delta_cwnd = 0;
      }
    } 
    // 快速重传+快速恢复
    else {
      if (seg_ack < recovery_ack) {
        // 收到部分应答，继续发包
        for (ssize_t i = 0, iEnd = retransmission_queue.size(); i < iEnd; i++) {
          auto& seg = retransmission_queue[i];
          TCPHeader *tcp_hdr = (TCPHeader *)&seg.buffer[20];
          uint32_t seg_seq = ntohl(tcp_hdr->seq);
          seg.start_time = current_ts_msec();
          if (seg_seq == seg_ack) {
            send_packet(seg.buffer, seg.header_length + seg.body_length);
            break;
          }
        }
      } else {
        // 收到恢复应答，退出快速恢复阶段
        cwnd = ssthresh;
        set_reno_state(RenoState::CONGESTION_AVOIDANCE);
      }
    }
    clear_repeat_ack();
  }
}

void TCP::check_retransmission() {
  uint64_t current_ms = current_ts_msec();
  for (auto seg : retransmission_queue) {
    if (RTO + seg.start_time < current_ms) {
      send_packet(seg.buffer, seg.header_length + seg.body_length);
    }
  }
}

void TCP::clear_repeat_ack() {
  for (auto seg : retransmission_queue) {
    seg.repeat_ack = 0;
  }
}

void TCP::update_recovery_ack() {
  if (recovery_ack < snd_nxt) {
    recovery_ack = snd_nxt;
  }
  printf("recovery_ack = %u\n", recovery_ack);
}

void TCP::push_order_list(const uint8_t *data, const size_t len, const uint32_t seg_seq) {
  OrderSegment ordersegment = OrderSegment(data, len, seg_seq);
  order_list.push_back(ordersegment);
}

void TCP::check_order(const uint32_t seg_seq) {
  ssize_t index = -1;
  for (ssize_t i = 0, iEnd = order_list.size(); i < iEnd; i++) {
    OrderSegment ordersegment = order_list[i];
    if (seg_seq == ordersegment.seg_seq) {
      size_t res = recv.write(ordersegment.data, ordersegment.len);
      rcv_nxt = rcv_nxt + res;
      rcv_wnd = recv.free_bytes();
      index = i;
      break;
    }
  }
  if (index != -1) {
    const uint32_t new_seg_seq = order_list[index].seg_seq + order_list[index].len;
    order_list.erase(order_list.begin() + index);
    if (!order_list.empty()) {
      check_order(new_seg_seq);
    }
  }
}

// construct ip header from tcp connection
void construct_ip_header(uint8_t *buffer, const TCP *tcp,
                         uint16_t total_length) {
  IPHeader *ip_hdr = (IPHeader *)buffer;
  memset(ip_hdr, 0, 20);
  ip_hdr->ip_v = 4;
  ip_hdr->ip_hl = 5;
  ip_hdr->ip_len = htons(total_length);
  ip_hdr->ip_ttl = 64;
  ip_hdr->ip_p = 6; // TCP
  ip_hdr->ip_src = tcp->local_ip;
  ip_hdr->ip_dst = tcp->remote_ip;
}

// update tcp & ip checksum
void update_tcp_ip_checksum(uint8_t *buffer) {
  IPHeader *ip_hdr = (IPHeader *)buffer;
  TCPHeader *tcp_hdr = (TCPHeader *)(buffer + ip_hdr->ip_hl * 4);
  update_tcp_checksum(ip_hdr, tcp_hdr);
  update_ip_checksum(ip_hdr);
}

void TCP::send_nagle_buffer() {
  size_t segment_len = nagle_buffer_size;
  if (segment_len > 0) {
    uint16_t total_length = 20 + 20 + segment_len;
    uint8_t buffer[MTU];
    construct_ip_header(buffer, this, total_length);
    // tcp
    TCPHeader *tcp_hdr = (TCPHeader *)&buffer[20];
    memset(tcp_hdr, 0, 20);
    tcp_hdr->source = htons(local_port);
    tcp_hdr->dest = htons(remote_port);
    tcp_hdr->seq = htonl(snd_nxt);
    snd_nxt += segment_len;
    // flags
    tcp_hdr->doff = 20 / 4; // 20 bytes

    tcp_hdr->ack = 1;
    tcp_hdr->ack_seq = htonl(rcv_nxt);

    tcp_hdr->window = htons(recv.free_bytes());

    memcpy(&buffer[40], nagle_buffer, segment_len);
    memset(nagle_buffer, 0, segment_len);
    nagle_buffer_size = 0;

    update_tcp_ip_checksum(buffer);
    send_packet(buffer, total_length);
  }
}

uint32_t generate_initial_seq() {
  // TODO(step 1: sequence number comparison and generation)
  // initial sequence number based on timestamp
  // rfc793 page 27 or rfc6528
  // https://www.rfc-editor.org/rfc/rfc793.html#page-27
  // "The generator is bound to a (possibly fictitious) 32
  // bit clock whose low order bit is incremented roughly every 4
  // microseconds."
  return ((uint32_t)current_ts_usec() >> 2) % 0xffffffff;
}

void process_tcp(const IPHeader *ip, const uint8_t *data, size_t size) {
  TCPHeader *tcp_header = (TCPHeader *)data;
  if (!verify_tcp_checksum(ip, tcp_header)) {
    printf("Bad TCP checksum\n");
    return;
  }

  // SEG.SEQ
  uint32_t seg_seq = ntohl(tcp_header->seq);
  // SEG.ACK
  uint32_t seg_ack = ntohl(tcp_header->ack_seq);
  // SEG.WND
  uint16_t seg_wnd = ntohs(tcp_header->window);
  // segment(ordersegment) length
  uint32_t seg_len = ntohs(ip->ip_len) - ip->ip_hl * 4 - tcp_header->doff * 4;
  const uint8_t *ordersegment = data + tcp_header->doff * 4;

  // iterate tcp connections in two pass
  // first pass: only exact matches
  // second pass: allow wildcard matches for listening socket
  // this gives priority to connected sockets
  for (int pass = 1; pass <= 2; pass++) {
    for (auto &pair : tcp_fds) {
      TCP *tcp = pair.second;
      if (tcp->state == TCPState::CLOSED) {
        // ignore closed sockets
        continue;
      }

      if (pass == 1) {
        // first pass: exact match
        if (tcp->local_ip != ip->ip_dst || tcp->remote_ip != ip->ip_src ||
            tcp->local_port != ntohs(tcp_header->dest) ||
            tcp->remote_port != ntohs(tcp_header->source)) {
          continue;
        }
      } else {
        // second pass: allow wildcard
        if (tcp->local_ip != 0 && tcp->local_ip != ip->ip_dst) {
          continue;
        }
        if (tcp->remote_ip != 0 && tcp->remote_ip != ip->ip_src) {
          continue;
        }
        if (tcp->local_port != 0 &&
            tcp->local_port != ntohs(tcp_header->dest)) {
          continue;
        }
        if (tcp->remote_port != 0 &&
            tcp->remote_port != ntohs(tcp_header->source)) {
          continue;
        }
      }

      // matched
      if (tcp_header->doff > 20 / 4) {
        // options exists
        // check TCP option header: MSS
        uint8_t *opt_ptr = (uint8_t *)data + 20;
        uint8_t *opt_end = (uint8_t *)data + tcp_header->doff * 4;
        while (opt_ptr < opt_end) {
          if (*opt_ptr == 0x00) {
            // End Of Option List
            break;
          } else if (*opt_ptr == 0x01) {
            // No-Operation
            opt_ptr++;
          } else if (*opt_ptr == 0x02) {
            // MSS
            uint8_t len = opt_ptr[1];
            if (len != 4) {
              printf("Bad TCP option len: %d\n", len);
              break;
            }

            uint16_t mss = ((uint16_t)opt_ptr[2] << 8) + opt_ptr[3];
            if (tcp_header->syn) {
              tcp->remote_mss = mss;
              printf("Remote MSS is %d\n", mss);
            } else {
              printf("Remote sent MSS option header in !SYN packet\n");
            }
            opt_ptr += len;
          } else {
            printf("Unrecognized TCP option: %d\n", *opt_ptr);
            break;
          }
        }
      }

      if (tcp->state == TCPState::LISTEN) {
        // rfc793 page 65
        // https://www.rfc-editor.org/rfc/rfc793.html#page-65
        // "If the state is LISTEN then"

        // "first check for an RST
        // An incoming RST should be ignored.  Return."
        if (tcp_header->rst) {
          return;
        }

        // "second check for an ACK"
        if (tcp_header->ack) {
          // "Any acknowledgment is bad if it arrives on a connection still in
          // the LISTEN state.  An acceptable reset segment should be formed
          // for any arriving ACK-bearing segment.  The RST should be
          // formatted as follows:
          // <SEQ=SEG.ACK><CTL=RST>
          // Return."
          UNIMPLEMENTED()
          return;
        }

        // "third check for a SYN"
        if (tcp_header->syn) {
          // create a new socket for the connection
          int new_fd = tcp_socket();
          TCP *new_tcp = tcp_fds[new_fd];
          tcp->accept_queue.push_back(new_fd);

          // initialize
          new_tcp->local_ip = tcp->local_ip;
          new_tcp->remote_ip = ip->ip_src;
          new_tcp->local_port = tcp->local_port;
          new_tcp->remote_port = ntohs(tcp_header->source);

          // "Set RCV.NXT to SEG.SEQ+1, IRS is set to SEG.SEQ and any other
          // control or text should be queued for processing later.  ISS
          // should be selected"
          new_tcp->rcv_nxt = seg_seq + 1;
          new_tcp->irs = seg_seq;

          uint32_t initial_seq = generate_initial_seq();
          new_tcp->iss = initial_seq;

          // initialize params
          // assume maximum mss for remote by default
          new_tcp->local_mss = new_tcp->remote_mss = DEFAULT_MSS;

          // TODO(step 2: 3-way handshake)
          // send SYN,ACK to remote
          // 44 = 20(IP) + 24(TCP)
          // with 4 bytes option(MSS)
          // "a SYN segment sent of the form:
          // <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>"
          uint8_t buffer[44];
          construct_ip_header(buffer, new_tcp, sizeof(buffer));
          // tcp
          TCPHeader *tcp_hdr = (TCPHeader *)&buffer[20];
          memset(tcp_hdr, 0, 20);
          tcp_hdr->source = htons(new_tcp->local_port);
          tcp_hdr->dest = htons(new_tcp->remote_port);
          tcp_hdr->seq = htonl(initial_seq);
          tcp_hdr->ack_seq = htonl(new_tcp->rcv_nxt);
          // flags
          tcp_hdr->doff = 24 / 4;
          tcp_hdr->syn = 1;
          tcp_hdr->ack = 1;
          // window size
          tcp_hdr->window = htons(tcp->recv.free_bytes());

          update_tcp_ip_checksum(buffer);
          send_packet(buffer, sizeof(buffer));
          
          // update full ack
          tcp->update_recovery_ack();
          // add to retransmission queue
          tcp->push_retransmission_queue(buffer, sizeof(buffer), 0);
          // start retransmission timer
          Retransmission_timer retransmission_fn;
          retransmission_fn.fd = new_fd;
          TIMERS.add_job(retransmission_fn, current_ts_msec());
          // UNIMPLEMENTED()

          // "SND.NXT is set to ISS+1 and SND.UNA to ISS.  The connection
          // state should be changed to SYN-RECEIVED."
          new_tcp->snd_nxt = initial_seq + 1;
          new_tcp->snd_una = initial_seq;
          new_tcp->snd_wnd = seg_wnd;
          new_tcp->rcv_wnd = new_tcp->recv.free_bytes();
          new_tcp->snd_wl2 = initial_seq - 1;
          new_tcp->set_state(TCPState::SYN_RCVD);
          return;
        }
      }

      if (tcp->state == TCPState::SYN_SENT) {
        // rfc793 page 66
        // https://www.rfc-editor.org/rfc/rfc793.html#page-66
        // "If the state is SYN-SENT then"
        // "If the ACK bit is set"
        if (tcp_header->ack) {
          // pop from retransmission queue
          tcp->check_retransmission_queue(seg_ack);

          // "If SEG.ACK =< ISS, or SEG.ACK > SND.NXT, send a reset (unless
          // the RST bit is set, if so drop the segment and return)
          //<SEQ=SEG.ACK><CTL=RST>
          // and discard the segment.  Return."
          if (tcp_seq_le(seg_ack, tcp->iss) ||
              tcp_seq_gt(seg_ack, tcp->snd_nxt)) {
            // send a reset when !RST
            UNIMPLEMENTED()
            return;
          }
        }

        // "second check the RST bit"
        // "If the RST bit is set"
        if (tcp_header->rst) {
          // "If the ACK was acceptable then signal the user "error:
          // connection reset", drop the segment, enter CLOSED state,
          // delete TCB, and return.  Otherwise (no ACK) drop the segment
          // and return."
          printf("Connection reset\n");
          tcp->set_state(TCPState::CLOSED);
          return;
        }

        // "fourth check the SYN bit"
        if (tcp_header->syn) {
          // TODO(step 2: 3-way handshake)
          // "RCV.NXT is set to SEG.SEQ+1, IRS is set to
          // SEG.SEQ.  SND.UNA should be advanced to equal SEG.ACK (if there
          // is an ACK), and any segments on the retransmission queue which
          // are thereby acknowledged should be removed."
          tcp->rcv_nxt = seg_seq + 1;
          tcp->irs = seg_seq;
          if (tcp_header->ack) {
              tcp->snd_una = seg_ack;
          }

          if (tcp_seq_gt(tcp->snd_una, tcp->iss)) {
            // "If SND.UNA > ISS (our SYN has been ACKed), change the connection
            // state to ESTABLISHED,"
            tcp->set_state(TCPState::ESTABLISHED);

            // TODO(step 2: 3-way handshake)
            // "form an ACK segment
            // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
            // and send it."
            uint8_t buffer[40];
            construct_ip_header(buffer, tcp, sizeof(buffer));
            // tcp
            TCPHeader *tcp_hdr = (TCPHeader *)&buffer[20];
            memset(tcp_hdr, 0, 20);
            tcp_hdr->source = htons(tcp->local_port);
            tcp_hdr->dest = htons(tcp->remote_port);
            tcp_hdr->seq = htonl(tcp->snd_nxt);
            tcp_hdr->ack_seq = htonl(tcp->rcv_nxt);
            // flags
            tcp_hdr->doff = 20 / 4;
            tcp_hdr->ack = 1;
            // window size
            tcp_hdr->window = htons(tcp->recv.free_bytes());

            update_tcp_ip_checksum(buffer);
            send_packet(buffer, sizeof(buffer));
            // UNIMPLEMENTED()

            // TODO(step 2: 3-way handshake)
            // https://www.rfc-editor.org/rfc/rfc1122#page-94
            // "When the connection enters ESTABLISHED state, the following
            // variables must be set:
            // SND.WND <- SEG.WND
            // SND.WL1 <- SEG.SEQ
            // SND.WL2 <- SEG.ACK"
            tcp->snd_wnd = seg_wnd;
            tcp->snd_wl1 = seg_seq;
            tcp->snd_wl2 = seg_ack;
            // UNIMPLEMENTED()
          } else {
            // "Otherwise enter SYN-RECEIVED"
            // "form a SYN,ACK segment
            //<SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
            // and send it."
            UNIMPLEMENTED()
          }
        }

        // "fifth, if neither of the SYN or RST bits is set then drop the
        // segment and return."
        if (!tcp_header->syn || !tcp_header->ack) {
          printf("Received unexpected !SYN || !ACK packet in SYN_SENT state\n");
          return;
        }
      }

      // rfc793 page 69
      // https://www.rfc-editor.org/rfc/rfc793.html#page-69
      // "Otherwise,"
      if (tcp->state == TCPState::SYN_RCVD ||
          tcp->state == TCPState::ESTABLISHED ||
          tcp->state == TCPState::FIN_WAIT_1 ||
          tcp->state == TCPState::FIN_WAIT_2 ||
          tcp->state == TCPState::CLOSE_WAIT ||
          tcp->state == TCPState::CLOSING || tcp->state == TCPState::LAST_ACK ||
          tcp->state == TCPState::TIME_WAIT) {

        // "first check sequence number"

        // "There are four cases for the acceptability test for an incoming
        // segment:"
        bool acceptable = false;
        if (seg_len == 0 && tcp->rcv_wnd == 0) {
          if (seg_seq == tcp->rcv_nxt) {
            acceptable = true;
          }
        } else if (seg_len == 0 && tcp->rcv_wnd > 0) {
          if (tcp_seq_le(tcp->rcv_nxt, seg_seq) && 
              tcp_seq_lt(seg_seq, tcp->rcv_nxt + tcp->rcv_wnd)) {
            acceptable = true;
          }
        } else if (seg_len > 0 && tcp->rcv_wnd > 0) {
          if ((tcp_seq_le(tcp->rcv_nxt, seg_seq) && tcp_seq_lt(seg_seq, tcp->rcv_nxt + tcp->rcv_wnd)) ||
              (tcp_seq_le(tcp->rcv_nxt, seg_seq + seg_len - 1) && tcp_seq_lt(seg_seq + seg_len - 1, tcp->rcv_nxt + tcp->rcv_wnd))) {
            acceptable = true;
          }
        } 
        // UNIMPLEMENTED_WARN();

        // "If an incoming segment is not acceptable, an acknowledgment
        // should be sent in reply (unless the RST bit is set, if so drop
        // the segment and return):"
        if (!acceptable) {
          if (!tcp_header->rst) {
            // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
            uint8_t buffer[40];
            construct_ip_header(buffer, tcp, sizeof(buffer));
            // tcp
            TCPHeader *tcp_hdr = (TCPHeader *)&buffer[20];
            memset(tcp_hdr, 0, 20);
            tcp_hdr->source = htons(tcp->local_port);
            tcp_hdr->dest = htons(tcp->remote_port);
            tcp_hdr->seq = htonl(tcp->snd_nxt);
            tcp_hdr->ack_seq = htonl(tcp->rcv_nxt);
            // flags
            tcp_hdr->doff = 20 / 4;
            tcp_hdr->ack = 1;
            // window size
            tcp_hdr->window = htons(tcp->recv.free_bytes());
            
            update_tcp_ip_checksum(buffer);
            send_packet(buffer, sizeof(buffer));
            return;
          }
          // UNIMPLEMENTED_WARN();
        }

        // "second check the RST bit,"
        if (tcp_header->rst) {
        }

        // "fourth, check the SYN bit,"
        if (tcp_header->syn) {
        }

        // "fifth check the ACK field,"
        if (tcp_header->ack) {
          // pop from retransmission queue
          tcp->check_retransmission_queue(seg_ack);
          
          // "if the ACK bit is on"
          // "SYN-RECEIVED STATE"
          if (tcp->state == SYN_RCVD) {
            // "If SND.UNA =< SEG.ACK =< SND.NXT then enter ESTABLISHED state
            // and continue processing."
            if (tcp_seq_le(tcp->snd_una, seg_ack) &&
                tcp_seq_le(seg_ack, tcp->snd_nxt)) {
              tcp->set_state(TCPState::ESTABLISHED);
            }
          }

          // "ESTABLISHED STATE"
          if (tcp->state == ESTABLISHED) {
            // TODO(step 3: send & receive)
            // "If SND.UNA < SEG.ACK =< SND.NXT then, set SND.UNA <- SEG.ACK."
            if (tcp_seq_lt(tcp->snd_una, seg_ack) && tcp_seq_le(seg_ack, tcp->snd_nxt)) {
                tcp->snd_una = seg_ack;
            }
            // UNIMPLEMENTED()

            // TODO(step 3: send & receive)
            // "If SND.UNA < SEG.ACK =< SND.NXT, the send window should be
            // updated.  If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and
            // SND.WL2 =< SEG.ACK)), set SND.WND <- SEG.WND, set
            // SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK."
            if (tcp_seq_lt(tcp->snd_wl1, seg_seq) || 
                ((tcp->snd_wl1 == seg_seq) && tcp_seq_le(tcp->snd_wl2, seg_ack))) {
                tcp->snd_wnd = seg_wnd;
                tcp->snd_wl1 = seg_seq;
                tcp->snd_wl2 = seg_ack;
            }
            // UNIMPLEMENTED()
          }

          // "FIN-WAIT-1 STATE"
          if (tcp->state == FIN_WAIT_1) {
            // "In addition to the processing for the ESTABLISHED state, if
            // our FIN is now acknowledged then enter FIN-WAIT-2 and continue
            // processing in that state."
            tcp->set_state(TCPState::FIN_WAIT_2);
          }

          // "FIN-WAIT-2 STATE"
          if (tcp->state == FIN_WAIT_2) {
            // "In addition to the processing for the ESTABLISHED state, if
            // the retransmission queue is empty, the user's CLOSE can be
            // acknowledged ("ok") but do not delete the TCB."
          }

          // LAST-ACK STATE
          if (tcp->state == LAST_ACK) {
            // "The only thing that can arrive in this state is an
            // acknowledgment of our FIN.  If our FIN is now acknowledged,
            // delete the TCB, enter the CLOSED state, and return."
            tcp->set_state(TCPState::CLOSED);
          }
        }

        // "seventh, process the segment text,"
        if (seg_len > 0) {
          if (tcp->state == ESTABLISHED) {
            // "Once in the ESTABLISHED state, it is possible to deliver
            // segment text to user RECEIVE buffers."
            printf("Received %d bytes from server\n", seg_len);

            // TODO(step 3: send & receive)
            // write to recv buffer
            // "Once the TCP takes responsibility for the data it advances
            // RCV.NXT over the data accepted, and adjusts RCV.WND as
            // appropriate to the current buffer availability.  The total of
            // RCV.NXT and RCV.WND should not be reduced."
            
            // assert(tcp->rcv_nxt <= seg_seq);
            if (tcp->rcv_nxt != seg_seq) {
              tcp->push_order_list(ordersegment, seg_len, seg_seq);
            } else {
              size_t res = tcp->recv.write(ordersegment, seg_len);
              tcp->rcv_nxt = tcp->rcv_nxt + res;
              tcp->rcv_wnd = tcp->recv.free_bytes();
              if (!tcp->order_list.empty()) {
                tcp->check_order(seg_seq + seg_len);
              }
            }
            // UNIMPLEMENTED()

            // "Send an acknowledgment of the form:
            // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>"
            uint8_t buffer[40];
            construct_ip_header(buffer, tcp, sizeof(buffer));
            // tcp
            TCPHeader *tcp_hdr = (TCPHeader *)&buffer[20];
            memset(tcp_hdr, 0, 20);
            tcp_hdr->source = htons(tcp->local_port);
            tcp_hdr->dest = htons(tcp->remote_port);
            tcp_hdr->seq = htonl(tcp->snd_nxt);
            tcp_hdr->ack_seq = htonl(tcp->rcv_nxt);
            // flags
            tcp_hdr->doff = 20 / 4; // 32 bytes
            tcp_hdr->ack = 1;
            // window size
            tcp_hdr->window = htons(tcp->recv.free_bytes());
            
            update_tcp_ip_checksum(buffer);
            send_packet(buffer, sizeof(buffer));
            // UNIMPLEMENTED()
          }
        }

        // "eighth, check the FIN bit,"
        if (tcp_header->fin) {
          // "Do not process the FIN if the state is CLOSED, LISTEN or SYN-SENT
          // since the SEG.SEQ cannot be validated; drop the segment and
          // return."
          if (tcp->state == CLOSED || tcp->state == LISTEN ||
              tcp->state == SYN_SENT) {
            return;
          }

          // TODO(step 4: connection termination)
          // "If the FIN bit is set, signal the user "connection closing" and
          // return any pending RECEIVEs with same message, advance RCV.NXT
          // over the FIN, and send an acknowledgment for the FIN.  Note that
          // FIN implies PUSH for any segment text not yet delivered to the
          // user."
          // 如果数据段标记了FIN，提示用户“connection closing”,对所有的RECEIVEs
          // 返回同样的信息。设置RCV.NXT为FIN的数据包的序列号+1，对FIN返回一个确认信息。
          // FIN和PUSH有相同的作用，把所有已经接收但是还没分发到用户进程的数据，分发到用户进程。

          // advance RCV.NXT over the FIN
          tcp->rcv_nxt = seg_seq + seg_len + 1;

          // send an acknowledgment for the FIN
          uint8_t buffer[40];
          construct_ip_header(buffer, tcp, sizeof(buffer));
          // tcp
          TCPHeader *tcp_hdr = (TCPHeader *)&buffer[20];
          memset(tcp_hdr, 0, 20);
          tcp_hdr->source = htons(tcp->local_port);
          tcp_hdr->dest = htons(tcp->remote_port);
          tcp_hdr->seq = htonl(tcp->snd_nxt);
          tcp_hdr->ack_seq = htonl(tcp->rcv_nxt);
          // flags
          tcp_hdr->doff = 20 / 4; // 32 bytes
          tcp_hdr->ack = 1;
          // window size
          tcp_hdr->window = htons(tcp->recv.free_bytes());

          update_tcp_ip_checksum(buffer);
          send_packet(buffer, sizeof(buffer));
          // UNIMPLEMENTED();

          if (tcp->state == SYN_RCVD || tcp->state == ESTABLISHED) {
            // Enter the CLOSE-WAIT state
            tcp->set_state(TCPState::CLOSE_WAIT);
          } else if (tcp->state == FIN_WAIT_1) {
            // FIN-WAIT-1 STATE
            // "If our FIN has been ACKed (perhaps in this segment), then
            // enter TIME-WAIT, start the time-wait timer, turn off the other
            // timers; otherwise enter the CLOSING state."

            tcp->set_state(TCPState::TIME_WAIT);
          } else if (tcp->state == FIN_WAIT_2) {
            // FIN-WAIT-2 STATE
            // "Enter the TIME-WAIT state.  Start the time-wait timer, turn
            // off the other timers."

            tcp->set_state(TCPState::TIME_WAIT);
          }
        }
      }
      return;
    }
  }

  printf("No matching TCP connection found\n");
  // send RST
  // rfc793 page 65 CLOSED state
  // https://www.rfc-editor.org/rfc/rfc793.html#page-65
  if (tcp_header->rst) {
    // "An incoming segment containing a RST is discarded."
    return;
  }

  // send RST segment
  // 40 = 20(IP) + 20(TCP)
  uint8_t buffer[40];
  IPHeader *ip_hdr = (IPHeader *)buffer;
  memset(ip_hdr, 0, 20);
  ip_hdr->ip_v = 4;
  ip_hdr->ip_hl = 5;
  ip_hdr->ip_len = htons(sizeof(buffer));
  ip_hdr->ip_ttl = 64;
  ip_hdr->ip_p = 6; // TCP
  ip_hdr->ip_src = ip->ip_dst;
  ip_hdr->ip_dst = ip->ip_src;

  // tcp
  TCPHeader *tcp_hdr = (TCPHeader *)&buffer[20];
  memset(tcp_hdr, 0, 20);
  tcp_hdr->source = tcp_header->dest;
  tcp_hdr->dest = tcp_header->source;
  if (!tcp_header->ack) {
    // "If the ACK bit is off, sequence number zero is used,"
    // "<SEQ=0>"
    tcp_hdr->seq = 0;
    // "<ACK=SEG.SEQ+SEG.LEN>"
    tcp_hdr->ack_seq = htonl(seg_seq + seg_len);
    // "<CTL=RST,ACK>"
    tcp_hdr->rst = 1;
    tcp_hdr->ack = 1;
  } else {
    // "If the ACK bit is on,"
    // "<SEQ=SEG.ACK>"
    tcp_hdr->seq = htonl(seg_ack);
    // "<CTL=RST>"
    tcp_hdr->rst = 1;
  }
  // flags
  tcp_hdr->doff = 20 / 4; // 20 bytes

  update_tcp_ip_checksum(buffer);
  send_packet(buffer, sizeof(buffer));
}

void update_tcp_checksum(const IPHeader *ip, TCPHeader *tcp) {
  uint32_t checksum = 0;

  // pseudo header
  // rfc793 page 17
  // https://www.rfc-editor.org/rfc/rfc793.html#page-17
  // "This pseudo header contains the Source
  // Address, the Destination Address, the Protocol, and TCP length."
  uint8_t pseudo_header[12];
  memcpy(&pseudo_header[0], &ip->ip_src, 4);
  memcpy(&pseudo_header[4], &ip->ip_dst, 4);
  // zero
  pseudo_header[8] = 0;
  // proto tcp
  pseudo_header[9] = 6;
  // TCP length (header + ordersegment)
  be16_t tcp_len = htons(ntohs(ip->ip_len) - ip->ip_hl * 4);
  memcpy(&pseudo_header[10], &tcp_len, 2);
  for (int i = 0; i < 6; i++) {
    checksum +=
        (((uint32_t)pseudo_header[i * 2]) << 8) + pseudo_header[i * 2 + 1];
  }

  // "The checksum field is the 16 bit one's complement of the one's
  // complement sum of all 16 bit words in the header and text."

  // TCP header
  uint8_t *tcp_data = (uint8_t *)tcp;
  tcp->checksum = 0;
  for (int i = 0; i < tcp->doff * 2; i++) {
    checksum += (((uint32_t)tcp_data[i * 2]) << 8) + tcp_data[i * 2 + 1];
  }

  // TCP ordersegment
  uint8_t *ordersegment = tcp_data + tcp->doff * 4;
  int ordersegment_len = ntohs(ip->ip_len) - ip->ip_hl * 4 - tcp->doff * 4;
  for (int i = 0; i < ordersegment_len; i++) {
    if ((i % 2) == 0) {
      checksum += (((uint32_t)ordersegment[i]) << 8);
    } else {
      checksum += ordersegment[i];
    }
  }

  while (checksum >= 0x10000) {
    checksum -= 0x10000;
    checksum += 1;
  }
  // update
  tcp->checksum = htons(~checksum);
}

bool verify_tcp_checksum(const IPHeader *ip, const TCPHeader *tcp) {
  uint32_t checksum = 0;

  // pseudo header
  // rfc793 page 17
  // https://www.rfc-editor.org/rfc/rfc793.html#page-17
  // "This pseudo header contains the Source
  // Address, the Destination Address, the Protocol, and TCP length."
  uint8_t pseudo_header[12];
  memcpy(&pseudo_header[0], &ip->ip_src, 4);
  memcpy(&pseudo_header[4], &ip->ip_dst, 4);
  // zero
  pseudo_header[8] = 0;
  // proto tcp
  pseudo_header[9] = 6;
  // TCP length (header + ordersegment)
  be16_t tcp_len = htons(ntohs(ip->ip_len) - ip->ip_hl * 4);
  memcpy(&pseudo_header[10], &tcp_len, 2);
  for (int i = 0; i < 6; i++) {
    checksum +=
        (((uint32_t)pseudo_header[i * 2]) << 8) + pseudo_header[i * 2 + 1];
  }

  // "The checksum field is the 16 bit one's complement of the one's
  // complement sum of all 16 bit words in the header and text."

  // TCP header
  uint8_t *tcp_data = (uint8_t *)tcp;
  for (int i = 0; i < tcp->doff * 2; i++) {
    checksum += (((uint32_t)tcp_data[i * 2]) << 8) + tcp_data[i * 2 + 1];
  }

  // TCP ordersegment
  uint8_t *ordersegment = tcp_data + tcp->doff * 4;
  int ordersegment_len = ntohs(ip->ip_len) - ip->ip_hl * 4 - tcp->doff * 4;
  for (int i = 0; i < ordersegment_len; i++) {
    if ((i % 2) == 0) {
      checksum += (((uint32_t)ordersegment[i]) << 8);
    } else {
      checksum += ordersegment[i];
    }
  }

  while (checksum >= 0x10000) {
    checksum -= 0x10000;
    checksum += 1;
  }
  return checksum == 0xffff;
}

// TODO(step 1: sequence number comparison and generation)
bool tcp_seq_lt(uint32_t a, uint32_t b) {
  return (b - a) < 0x80000000 && (a != b);
}

bool tcp_seq_le(uint32_t a, uint32_t b) {
  return (b - a) < 0x80000000;
}

bool tcp_seq_gt(uint32_t a, uint32_t b) {
  return (a - b) < 0x80000000 && (a != b);
}

bool tcp_seq_ge(uint32_t a, uint32_t b) {
  return (a - b) < 0x80000000;
}

// returns fd
int tcp_socket() {
  for (int i = 0;; i++) {
    if (tcp_fds.find(i) == tcp_fds.end()) {
      // found free fd, create one
      TCP *tcp = new TCP;
      tcp_fds[i] = tcp;

      // add necessary initialization here
      return i;
    }
  }
}

void tcp_connect(int fd, uint32_t dst_addr, uint16_t dst_port) {
  TCP *tcp = tcp_fds[fd];

  tcp->local_ip = client_ip;
  // random local port
  tcp->local_port = 40000 + (rand() % 10000);
  tcp->remote_ip = dst_addr;
  tcp->remote_port = dst_port;

  // initialize params
  // assume maximum mss for remote by default
  tcp->local_mss = tcp->remote_mss = DEFAULT_MSS;

  uint32_t initial_seq = generate_initial_seq();
  // rfc793 page 54 OPEN Call CLOSED STATE
  // https://www.rfc-editor.org/rfc/rfc793.html#page-54
  tcp->iss = initial_seq;
  // only one unacknowledged number: initial_seq
  // "Set SND.UNA to ISS, SND.NXT to ISS+1, enter SYN-SENT
  // state, and return."
  tcp->snd_una = initial_seq;
  tcp->snd_nxt = initial_seq + 1;
  tcp->snd_wnd = 0;
  tcp->rcv_wnd = tcp->recv.free_bytes();
  tcp->snd_wl2 = initial_seq - 1;
  tcp->set_state(TCPState::SYN_SENT);

  // send SYN to remote
  // 44 = 20(IP) + 24(TCP)
  // with 4 bytes option(MSS)
  uint8_t buffer[44];
  construct_ip_header(buffer, tcp, sizeof(buffer));

  // tcp
  TCPHeader *tcp_hdr = (TCPHeader *)&buffer[20];
  memset(tcp_hdr, 0, 20);
  tcp_hdr->source = htons(tcp->local_port);
  tcp_hdr->dest = htons(tcp->remote_port);
  tcp_hdr->seq = htonl(initial_seq);
  // flags
  tcp_hdr->doff = 24 / 4; // 24 bytes
  tcp_hdr->syn = 1;

  // TODO(step 3: send & receive)
  // window size: size of empty bytes in recv buffer
  tcp_hdr->window = htons(tcp->recv.free_bytes());
  // UNIMPLEMENTED_WARN();

  // mss option, rfc793 page 18
  // https://www.rfc-editor.org/rfc/rfc793.html#page-18
  buffer[40] = 0x02; // kind
  buffer[41] = 0x04; // length
  buffer[42] = tcp->local_mss >> 8;
  buffer[43] = tcp->local_mss;

  update_tcp_ip_checksum(buffer);
  send_packet(buffer, sizeof(buffer));
  
  // update full ack
  tcp->update_recovery_ack();
  // push to retransmission queue
  tcp->push_retransmission_queue(buffer, sizeof(buffer), 0);
  // start retransmission timer
  Retransmission_timer retransmission_fn;
  retransmission_fn.fd = fd;
  TIMERS.add_job(retransmission_fn, current_ts_msec());
  return;
}

ssize_t tcp_write(int fd, const uint8_t *data, size_t size) {
  TCP *tcp = tcp_fds[fd];
  assert(tcp);

  // rfc793 page 56 SEND Call
  // https://www.rfc-editor.org/rfc/rfc793.html#page-56
  if (tcp->state == TCPState::SYN_SENT || tcp->state == TCPState::SYN_RCVD) {
    // queue data for transmission
    return tcp->send.write(data, size);
  } else if (tcp->state == TCPState::ESTABLISHED ||
             tcp->state == TCPState::CLOSE_WAIT) {
    // queue data for transmission
    size_t res = tcp->send.write(data, size);

    // send data to remote
    size_t bytes_to_send = tcp->send.size;

    // nagle 算法
    if (bytes_to_send < NAGLE_MIN_SIZE) {
      printf("bytes_to_send: %zu\n", bytes_to_send);
      tcp->nagle_time_last = current_ts_msec();
      size_t bytes_read = tcp->send.read(&tcp->nagle_buffer[tcp->nagle_buffer_size], bytes_to_send);
      tcp->nagle_buffer_size += bytes_read;
      
      Nagle_timer nagle_fn;
      nagle_fn.fd = fd;
      TIMERS.add_job(nagle_fn, current_ts_msec());

      // 足够大或超时
      if (tcp->nagle_buffer_size > NAGLE_MIN_SIZE) {
          tcp->send_nagle_buffer();
      }
    } 
    else {
      // TODO(step 3: send & receive)
      // consider mss and send sequence space
      // send sequence space: https://www.rfc-editor.org/rfc/rfc793.html#page-20 figure 4
      // compute the segment length to send

      while (bytes_to_send){
        size_t segment_len = min(bytes_to_send, tcp->remote_mss);
        bytes_to_send -= segment_len;
        // UNIMPLEMENTED()

        if (segment_len > 0) {
          printf("Sending segment of len %zu to remote\n", segment_len);
          // send data now

          // 20 IP header & 20 TCP header
          uint16_t total_length = 20 + 20 + segment_len;
          uint8_t buffer[MTU];
          construct_ip_header(buffer, tcp, total_length);

          // tcp
          TCPHeader *tcp_hdr = (TCPHeader *)&buffer[20];
          memset(tcp_hdr, 0, 20);
          tcp_hdr->source = htons(tcp->local_port);
          tcp_hdr->dest = htons(tcp->remote_port);
          // this segment occupies range:
          // [snd_nxt, snd_nxt+seg_len)
          tcp_hdr->seq = htonl(tcp->snd_nxt);
          tcp->snd_nxt += segment_len;
          // flags
          tcp_hdr->doff = 20 / 4; // 20 bytes

          // TODO(step 3: send & receive)
          // set ack bit and ack_seq
          tcp_hdr->ack = 1;
          tcp_hdr->ack_seq = htonl(tcp->rcv_nxt);

          // TODO(step 3: send & receive)
          // window size: size of empty bytes in recv buffer
          tcp_hdr->window = htons(tcp->recv.free_bytes());
          // UNIMPLEMENTED();

          // ordersegment
          size_t bytes_read = tcp->send.read(&buffer[40], segment_len);
          // should never fail
          assert(bytes_read == segment_len);

          update_tcp_ip_checksum(buffer);
          send_packet(buffer, total_length);

          // update full ack
          tcp->update_recovery_ack();
          // push to retransmission queue
          tcp->push_retransmission_queue(buffer, 52, segment_len);
          // start retransmission timer
          Retransmission_timer retransmission_fn;
          retransmission_fn.fd = fd;
          TIMERS.add_job(retransmission_fn, current_ts_msec());
        }
      }
    }
    return res;
  }
  return -1;
}

ssize_t tcp_read(int fd, uint8_t *data, size_t size) {
  TCP *tcp = tcp_fds[fd];
  assert(tcp);

  // TODO(step 3: send & receive)
  // copy from recv_buffer to user data
  return tcp->recv.read(data, size);
  // UNIMPLEMENTED();
}

void tcp_shutdown(int fd) {
  TCP *tcp = tcp_fds[fd];
  assert(tcp);

  // CLOSE Call
  // ESTABLISHED STATE
  if (tcp->state == TCPState::ESTABLISHED) {
    // TODO(step 4: connection termination)
    // "Queue this until all preceding SENDs have been segmentized, then
    // form a FIN segment and send it. In any case, enter FIN-WAIT-1 state."
    // 缓存这个请求，直到所有以前的发送请求都完成，
    // 然后生成一个FIN数据段发送出去。然后进入FIN-WAIT-1状态。

    uint8_t buffer[40];
    construct_ip_header(buffer, tcp, sizeof(buffer));
    // tcp
    TCPHeader *tcp_hdr = (TCPHeader *)&buffer[20];
    memset(tcp_hdr, 0, 20);
    tcp_hdr->source = htons(tcp->local_port);
    tcp_hdr->dest = htons(tcp->remote_port);
    tcp_hdr->seq = htonl(tcp->snd_nxt);
    // flags
    tcp_hdr->doff = 20 / 4; // 20 bytes
    tcp_hdr->fin = 1;
    // window size
    tcp_hdr->window = htons(tcp->recv.free_bytes());

    // FIN is a segment
    tcp->snd_nxt += 1;

    update_tcp_ip_checksum(buffer);
    send_packet(buffer, sizeof(buffer));

    // update full ack
    tcp->update_recovery_ack();
    // push to retransmission queue
    tcp->push_retransmission_queue(buffer, sizeof(buffer), 0);
    // start retransmission timer
    Retransmission_timer retransmission_fn;
    retransmission_fn.fd = fd;
    TIMERS.add_job(retransmission_fn, current_ts_msec());

    // UNIMPLEMENTED();
    tcp->set_state(TCPState::FIN_WAIT_1);
  } else if (tcp->state == TCPState::CLOSE_WAIT) {
    // TODO(step 4: connection termination)
    // CLOSE_WAIT STATE
    // "Queue this request until all preceding SENDs have been
    // segmentized; then send a FIN segment, enter LAST-ACK state."
    // 缓存这个请求，直到所有的send指令都完成，
    // 然后发送一个FIN标志出去，之后进入CLOSING状态。
    
    uint8_t buffer[40];
    construct_ip_header(buffer, tcp, sizeof(buffer));
    // tcp
    TCPHeader *tcp_hdr = (TCPHeader *)&buffer[20];
    memset(tcp_hdr, 0, 20);
    tcp_hdr->source = htons(tcp->local_port);
    tcp_hdr->dest = htons(tcp->remote_port);
    tcp_hdr->seq = htonl(tcp->snd_nxt);
    // flags
    tcp_hdr->doff = 20 / 4; // 20 bytes
    tcp_hdr->fin = 1;
    // window size
    tcp_hdr->window = htons(tcp->recv.free_bytes());
    
    // FIN is a segment
    tcp->snd_nxt += 1;

    update_tcp_ip_checksum(buffer);
    send_packet(buffer, sizeof(buffer));

    // update full ack
    tcp->update_recovery_ack();
    // push to retransmission queue
    tcp->push_retransmission_queue(buffer, sizeof(buffer), 0);
    // start retransmission timer
    Retransmission_timer retransmission_fn;
    retransmission_fn.fd = fd;
    TIMERS.add_job(retransmission_fn, current_ts_msec());

    // UNIMPLEMENTED();
    tcp->set_state(TCPState::LAST_ACK);
  }
}

void tcp_close(int fd) {
  // shutdown first
  tcp_shutdown(fd);

  TCP *tcp = tcp_fds[fd];
  assert(tcp);

  // remove connection if closed
  if (tcp->state == TCPState::CLOSED) {
    printf("Removing TCP connection fd=%d\n", fd);
    tcp_fds.erase(fd);
    delete tcp;
  }
}

void tcp_bind(int fd, be32_t addr, uint16_t port) {
  TCP *tcp = tcp_fds[fd];
  assert(tcp);

  tcp->local_ip = addr;
  tcp->local_port = port;
  // wildcard
  tcp->remote_ip = 0;
  tcp->remote_port = 0;
}

void tcp_listen(int fd) {
  TCP *tcp = tcp_fds[fd];
  assert(tcp);

  // enter listen state
  tcp->set_state(TCPState::LISTEN);
}

int tcp_accept(int fd) {
  TCP *tcp = tcp_fds[fd];
  assert(tcp);

  // pop fd from accept queue
  if (tcp->accept_queue.empty()) {
    return -1;
  } else {
    int fd = tcp->accept_queue.front();
    tcp->accept_queue.pop_front();
    return fd;
  }
}

TCPState tcp_state(int fd) {
  TCP *tcp = tcp_fds[fd];
  assert(tcp);
  return tcp->state;
}
