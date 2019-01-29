#ifndef __NET_UTIL_H__
#define __NET_UTIL_H__

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

#include "ethernet.hpp"
#include "ip.hpp"
#include "json.hpp"
#include "packet.hpp"

int get_mac_addr(char *ifname, ethernet_addr_t *mac_addr);
int get_ip_addr(char *ifname, ip_addr_t *ip_addr);
pk_ethernet_frame_t parse_eth_frame(long eth_frame);
pk_ipv4_payload_t parse_ipv4_frame(long ptr);
pk_tcp_data_t parse_tcp_frame(long ptr);
pk_udp_data_t parse_udp_frame(long ptr);
pk_arp_payload_t parse_arp_frame(long ptr);

uint16_t ntoh16(uint16_t n);
uint16_t hton16(uint16_t h);
uint32_t ntoh32(uint32_t n);
uint32_t hton32(uint32_t h);

std::string mac_addr_string(uint8_t *addr);
std::string ip_addr_string(uint8_t *addr);
void log_ethernet_frame(const uint8_t *frame);

#endif
