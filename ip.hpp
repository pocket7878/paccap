#ifndef __IP_H__
#define __IP_H__

#include <cstdint>
#include <cstring>

#define IP_PROT_TCP 6
#define IP_PROT_UDP 17

typedef struct ip_addr {
  uint8_t addr[4];

  bool operator==(const ip_addr& other) const;
  bool operator!=(const ip_addr& other) const;
} ip_addr_t;

inline bool ip_addr::operator==(const ip_addr& other) const {
  return addr[0] == other.addr[0] && addr[1] == other.addr[1] && addr[2] == other.addr[2] && addr[3] == other.addr[3];
}

inline bool ip_addr::operator!=(const ip_addr& other) const {
  return !(this->operator==(other));
}

namespace std{
  template<>
  class hash<ip_addr_t> {
    public:
    size_t operator () ( const ip_addr_t &a) const {
      uint32_t buf;
      memcpy(&buf, &a.addr, sizeof(uint8_t) * 4);
      return buf;
    }
  };
}

typedef struct {
  uint8_t ihl: 4;
  uint8_t version: 4;
  uint8_t typ;
  uint16_t total_len;
  uint16_t id;
  uint16_t offset: 13;
  uint8_t flg: 3;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;
  ip_addr_t src;
  ip_addr_t dst;
  uint32_t options;
} ip_hdr;

#endif
