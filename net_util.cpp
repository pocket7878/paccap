#include <iostream>
#include <cstdlib>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/bpf.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <ifaddrs.h>
#include <boost/format.hpp>

#include "ethernet.hpp"
#include "ip.hpp"
#include "udp.hpp"
#include "tcp.hpp"
#include "arp.hpp"
#include "json.hpp"
#include "net_util.hpp"
#include "packet.hpp"

int get_ip_addr(char *ifname, ip_addr_t *ip_addr) {
    struct ifaddrs *ifa_list, *ifa;
    if (getifaddrs(&ifa_list) < 0) {
        return -1;
    }
    for(ifa = ifa_list; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) {
            continue;
        }
        if (strcmp(ifa->ifa_name, ifname) != 0) {
            continue;
        }
        if (ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        uint32_t addr = ((struct sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr;
        memcpy(ip_addr->addr, &addr, sizeof(uint8_t) * 4);
        return 0;
    }

    return -1;
}

int get_mac_addr(char *ifname, ethernet_addr_t *mac_addr) {
    struct ifaddrs *ifa_list, *ifa;
    struct sockaddr_dl *dl;
    char name[12];
    unsigned char *addr;
    if (getifaddrs(&ifa_list) < 0) {
        return -1;
    }
    for(ifa = ifa_list; ifa != NULL; ifa = ifa->ifa_next) {
        if (strcmp(ifname, ifa->ifa_name) == 0) {
        dl = (struct sockaddr_dl*)ifa->ifa_addr;
        if (dl->sdl_family == AF_LINK && dl->sdl_type == IFT_ETHER) {
                memcpy(name, dl->sdl_data, dl->sdl_nlen);
                name[dl->sdl_nlen] = '\0';
                memcpy(mac_addr->addr, LLADDR(dl), ETHERNET_ADDR_SIZE);
                return 0;
            }
        }
    }

    return -1;
}

pk_ethernet_frame_t parse_eth_frame(long eth_frame) {
    pk_ethernet_frame_t frame;

    eth_hdr *ehdr = (eth_hdr*)eth_frame;
    long payload_ptr = (long)ehdr + sizeof(eth_hdr);
    frame.src_hw = ehdr->src;
    frame.dst_hw = ehdr->dst;
    frame.raw_type = ntoh16(ehdr->typ);
    switch(frame.raw_type) {
        case TYPE_IPV4:
            frame.type = PACKET_TYPE_IPV4;
            frame.payload.ipv4_payload = parse_ipv4_frame(payload_ptr);
            break;
        case TYPE_ARP:
            frame.type = PACKET_TYPE_ARP;
            frame.payload.arp_payload = parse_arp_frame(payload_ptr);
            break;
        default:
            frame.type = PACKET_TYPE_UNKNOWN;
    }
    return frame;
}

pk_ipv4_payload_t parse_ipv4_frame(long ptr) {
    pk_ipv4_payload_t payload;

    ip_hdr *iphdr = (ip_hdr*)ptr;
    long data_ptr = (long)iphdr + (iphdr->ihl * 4);

    payload.ttl = iphdr->ttl;
    payload.src_ip = iphdr->src;
    payload.dst_ip = iphdr->dst;

    switch(iphdr->protocol) {
        case IP_PROT_TCP:
            payload.protocol = PACKET_PROTOCOL_TCP;
            break;
        case IP_PROT_UDP:
            payload.protocol = PACKET_PROTOCOL_UDP;
            break;
    }

    return payload;
}

pk_tcp_data_t parse_tcp_frame(long ptr) {
    pk_tcp_data_t data;
    tcp_hdr *tcp = (tcp_hdr*)ptr;
    data.src_port = tcp->src_port;
    data.dst_port = tcp->dst_port;

    return data;
}

pk_udp_data_t parse_udp_frame(long ptr) {
    pk_udp_data_t data;

    udp_hdr *udp = (udp_hdr*)ptr;
    data.src_port = udp->src_port;
    data.dst_port = udp->dst_port;

    return data;
}

pk_arp_payload_t parse_arp_frame(long ptr) {
    pk_arp_payload_t payload;
    arp_data *adata = (arp_data*)ptr;

    payload.htype = ntoh16(adata->htype);
    payload.ptype = ntoh16(adata->ptype);

    payload.op = ntoh16(adata->op);
    payload.src_hw = adata->src_hw;
    payload.src_ip = adata->src_ip;
    payload.dst_hw = adata->target_hw;
    payload.dst_ip = adata->target_ip;

    return payload;
}

uint16_t ntoh16(uint16_t n) {
  return ntohs(n);
}

uint16_t hton16(uint16_t h) {
  return htons(h);
}

uint32_t ntoh32(uint32_t n) {
    return ntohl(n);
}

uint32_t hton32(uint32_t h) {
    return htonl(h);
}

std::string mac_addr_string(uint8_t *addr) {
    return (boost::format("%x:%x:%x:%x:%x:%x") % (unsigned int)addr[0] % (unsigned int)addr[1] % (unsigned int)addr[2] % (unsigned int)addr[3] % (unsigned int)addr[4] % (unsigned int)addr[5]).str();
}

std::string ip_addr_string(uint8_t *addr) {
    return (boost::format("%d.%d.%d.%d") % (unsigned int)addr[0] % (unsigned int)addr[1] % (unsigned int)addr[2]  % (unsigned int)addr[3]).str();
}

void log_ethernet_frame(const uint8_t *frame) {
  pk_ethernet_frame_t pkt = parse_eth_frame((long)frame);
}
