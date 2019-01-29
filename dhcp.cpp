#include "dhcp.hpp"
#include "net_util.hpp"

void dhcp_discover(dhcp_t *msg, ethernet_addr_t addr, uint32_t xid) {
    uint8_t *opt;
    msg->op = 0x01;
    msg->htype = 0x01;
    msg->hlen = 0x06;
    msg->xid = hton32(xid);
    msg->flags = hton16(DHCP_FLAG_BROADCAST);
    memcpy(msg->chaddr, addr.addr, 6);

    opt = msg->options;
    memcpy(opt, DHCP_MAGIC_CODE, 4);
    opt += 4;
    // Discover
    *opt++ = 0x35;
    *opt++ = 0x01;
    *opt++ = 0x01;
    // CLient ID
    *opt++ = 0x3d;
    *opt++ = 0x07;
    *opt++ = 0x01;
    // Mac Addr
    memcpy(opt, msg->chaddr, 6);
    opt += 6;
    // Stoppper
    *opt++ = 0xff;
}
