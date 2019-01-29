#include <iostream>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <net/if.h>
#include <net/bpf.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <boost/format.hpp>
#include "json.hpp"
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <unordered_map>
#include <algorithm>
#include "device.hpp"
#include "ip.hpp"
#include "arp.hpp"
#include "packet.hpp"
#include "net_util.hpp"
#include "json.hpp"

using namespace std;

int main(int argc, char **argv) {
  BpfDevice dev = BpfDevice("en17");
  if (dev.init() < 0) {
    return 1;
  };
  if (argc < 5) {
    cerr << "Usage: " << argv[0] << " 192 168 100 30" << endl;
    exit(1);
  }
  unordered_map<ip_addr_t, ethernet_addr_t> arp_table;
  ip_addr_t search_addr = {(uint8_t)atoi(argv[1]), (uint8_t)atoi(argv[2]), (uint8_t)atoi(argv[3]), (uint8_t)atoi(argv[4])};
  while (1) {
    dev.send_arp_request(&search_addr);
    std::vector<pk_ethernet_frame_t> packets = dev.read_packets();
    for(auto p : packets) {
      cerr << p.to_json().dump() << endl;
      if (p.type == PACKET_TYPE_ARP && p.payload.arp_payload.op == ARP_OP_RES) {
        ip_addr_t raddr = p.payload.arp_payload.src_ip;
        if (raddr == search_addr) {
          cout << ip_addr_string(search_addr.addr) << " IS " << mac_addr_string(p.payload.arp_payload.src_hw.addr) << endl;
          return 0;
        }
      }
    }
  }

  return 0;
}
