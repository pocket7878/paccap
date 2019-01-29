#ifndef __ETHERNET_H__
#define __ETHERNET_H__

#include <cstdint>

#define ETHERNET_ADDR_SIZE 6
#define ETHERNET_HDR_SIZE 14
#define ETHERNET_TRL_SIZE 4
#define ETHERNET_FRAME_SIZE_MIN 64
#define ETHERNET_FRAME_SIZE_MAX 1518
#define ETHERNET_PAYLOAD_SIZE_MIN (ETHERNET_FRAME_SIZE_MIN - (ETHERNET_HDR_SIZE + ETHERNET_TRL_SIZE))
#define ETHERNET_PAYLOAD_SIZE_MAX (ETHERNET_FRAME_SIZE_MAX - (ETHERNET_HDR_SIZE + ETHERNET_TRL_SIZE))

#define TYPE_IPV4 0x0800
#define TYPE_ARP 0x0806

typedef struct {
  uint8_t addr[ETHERNET_ADDR_SIZE];
} ethernet_addr_t;

typedef struct {
  ethernet_addr_t dst;
  ethernet_addr_t src;
  uint16_t typ;
} eth_hdr;

extern const ethernet_addr_t ETHERNET_ADDR_BCAST;

#endif
