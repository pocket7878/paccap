#ifndef __TCP_H__
#define __TCP_H__

typedef struct {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seq_num;
  uint32_t ack_num;
  uint32_t hdr_len: 4;
  uint32_t reserved: 6;
  struct flags_t {
    uint32_t urg: 1;
    uint32_t ack: 1;
    uint32_t psh: 1;
    uint32_t rst: 1;
    uint32_t syn: 1;
    uint32_t fin: 1;
  } flags;
  uint16_t window_size;
  uint16_t checksum;
  uint16_t urgent_ptr;
} tcp_hdr;

#endif