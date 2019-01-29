#ifndef __DHCP_H_
#define __DHCP_H_

#include <cstdint>
#include "ethernet.hpp"

#define DHCP_MESSAGE_MIN_LEN (sizeof(struct dhcp) + 64)
#define DHCP_MESSAGE_BUF_LEN (sizeof(struct dhcp) + 312)
#define DHCP_MAGIC_CODE "\x63\x82\x53\x63"
#define DHCP_FLAG_BROADCAST (0x8000)
#define DHCP_VENDOR_BYTE_SIZE 64
#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67

typedef struct {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint8_t options[0];
} dhcp_t;

void dhcp_discover(dhcp_t *msg, ethernet_addr_t eth, uint32_t xid);

#endif
