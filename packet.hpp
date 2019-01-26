#include <cstdint>

#define TYPE_IPV4 0x0008
#define IP_PROT_TCP 6
#define IP_PROT_UDP 17

typedef struct {
  uint8_t dst_mac[6];
  uint8_t src_mac[6];
  unsigned short typ;
} eth_hdr;

typedef struct {
  unsigned char ihl: 4;
  unsigned char version: 4;
  unsigned char typ;
  unsigned short total_len;
  unsigned short id;
  unsigned short offset: 13;
  unsigned char flg: 3;
  unsigned char ttl;
  unsigned char protocol;
  unsigned short checksum;
  unsigned char src_addr[4];
  unsigned char dst_addr[4];
  unsigned int options;
} ip_hdr;

typedef struct {
  unsigned short src_port;
  unsigned short dst_port;
  unsigned int seq_num;
  unsigned int ack_num;
  unsigned int hdr_len: 4;
  unsigned int reserved: 6;
  struct flags_t {
    unsigned int urg: 1;
    unsigned int ack: 1;
    unsigned int psh: 1;
    unsigned int rst: 1;
    unsigned int syn: 1;
    unsigned int fin: 1;
  } flags;
  unsigned short window_size;
  unsigned short checksum;
  unsigned short urgent_ptr;
} tcp_hdr;

typedef struct {
  unsigned short src_port;
  unsigned short dst_port;
  unsigned short data_len;
  unsigned short checksum;
} udp_hdr;
