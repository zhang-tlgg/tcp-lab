#include <assert.h>
#include <set>

#include "tcp.h"

int main(int argc, char *argv[]) {
  // test sequence comparison functions
  assert(tcp_seq_lt(0x00000000, 0x00000001));
  assert(tcp_seq_lt(0xFFFFFFFF, 0x00000000));
  assert(tcp_seq_lt(0x00001000, 0x00002000));
  assert(tcp_seq_lt(0xFFFFF000, 0xFFFFFFFF));

  assert(tcp_seq_le(0x00000000, 0x00000001));
  assert(tcp_seq_le(0x00000000, 0x00000000));
  assert(tcp_seq_le(0xFFFFF000, 0xFFFFFFFF));
  assert(tcp_seq_le(0xFFFFFFFF, 0x00000000));
  assert(tcp_seq_le(0xFFFFF000, 0x00000000));

  assert(tcp_seq_gt(0x00000001, 0x00000000));
  assert(tcp_seq_gt(0x00000000, 0xFFFFFFFF));

  assert(tcp_seq_ge(0x00001234, 0x0000));
  assert(tcp_seq_ge(0xFFFFFFFF, 0xFFFFF000));

  return 0;
}