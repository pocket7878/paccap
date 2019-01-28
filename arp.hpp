#ifndef __ARP_H__
#define __ARP_H__

#include <cstdint>
#include "ethernet.hpp"
#include "ip.hpp"

#define ARP_OP_REQ 1
#define ARP_OP_RES 2
#define ARP_OP_RREQ 3
#define ARP_OP_RRES 4

typedef struct {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hsize;
  uint8_t psize;
  uint16_t op;
  ethernet_addr_t src_hw;
  ip_addr_t src_ip;
  ethernet_addr_t target_hw;
  ip_addr_t target_ip;
} arp_data;

#endif
