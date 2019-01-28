#ifndef __PACKET_H__
#define __PACKET_H__

#include <cstdint>
#include "ethernet.hpp"
#include "ip.hpp"

#define PACKET_TYPE_IPV4 0
#define PACKET_TYPE_ARP 1
#define PACKET_TYPE_UNKNOWN 2

#define PACKET_PROTOCOL_TCP 0
#define PACKET_PROTOCOL_UDP 1

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
} pk_tcp_data_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
} pk_udp_data_t;

typedef struct {
    unsigned char protocol;
    uint8_t ttl;
    ip_addr_t src_ip;
    ip_addr_t dst_ip;
    union {
        pk_tcp_data_t tcp_data;
        pk_udp_data_t udp_data;
    } data;
} pk_ipv4_payload_t;

typedef struct {
    uint16_t htype;
    uint16_t ptype;
    uint16_t op;
    ethernet_addr_t src_hw;
    ip_addr_t src_ip;
    ethernet_addr_t dst_hw;
    ip_addr_t dst_ip;
} pk_arp_payload_t;

typedef struct {
    unsigned char type;
    uint16_t raw_type;
    ethernet_addr_t src_hw;
    ethernet_addr_t dst_hw;
    union {
        pk_ipv4_payload_t ipv4_payload;
        pk_arp_payload_t arp_payload;
    } payload;
} pk_ethernet_frame_t;

#endif
