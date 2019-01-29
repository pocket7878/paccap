#ifndef __UDP_H__
#define __UDP_H__

typedef struct {
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t data_len;
  uint16_t checksum;
} udp_hdr;

#endif