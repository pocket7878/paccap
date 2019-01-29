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
#include <sstream>
#include <bitset>

#include "device.hpp"
#include "arp.hpp"
#include "net_util.hpp"
#include "json.hpp"
#include "packet.hpp"

TapDevice::TapDevice() {
}

int TapDevice::init() {
    if (this->open_device() < 0) {
        return -1;
    }
    if (this->up_device() < 0) {
        return -1;
    }

    if (this->load_mac_addr() < 0) {
        return -1;
    }

    return 0;
}

int TapDevice::open_device() {
    char path_buf[11] = {0};
    for (int i = 0; i < 99; i++) {
        sprintf(this->ifname, "tap%d", i);
        sprintf(path_buf, "/dev/%s", this->ifname);
        this->fd = open(path_buf, O_RDWR | O_NONBLOCK);
        if(this->fd != -1) break;
    }

    if (this->fd == -1) {
        return -1;
    }

    return 0;
}

int TapDevice::up_device() {
    char cmd_buf[512];
    sprintf(cmd_buf, "sudo ifconfig %s", this->ifname);
    std::system(cmd_buf);

    return 0;
}

int TapDevice::set_ip(ip_addr_t addr) {
    std::stringstream cmd;
    cmd << "sudo ifconfig " << this->ifname << " " << ip_addr_string(addr.addr) << " up";
    std::cout << cmd.str() << std::endl;
    std::system(cmd.str().c_str());
    this->ip_addr = addr;

    return 0;
}

int TapDevice::load_mac_addr() {
    if (get_mac_addr(this->ifname, &this->mac_addr) < 0) {
        return -1;
    }

    return 0;
}

std::vector<pk_ethernet_frame_t> TapDevice::read_packets() {
    std::vector<pk_ethernet_frame_t> result;
    int read_byte = 0;
    char packet_buf[1500];

    memset(packet_buf, 0, 1500);

    if ((read_byte = read(this->fd, packet_buf, 1500)) < 0) {
        if (errno != EAGAIN) {
            perror("read");
        }
        return result;
    }

    if (read_byte <= 0) {
        return result;
    }

    pk_ethernet_frame_t pkt = parse_eth_frame((long)packet_buf);
    result.push_back(pkt);

    return result;
}

int TapDevice::send_arp_request(const ip_addr_t *addr) {
  arp_data request;
  request.htype = hton16(1);
  request.ptype = hton16(TYPE_IPV4);
  request.hsize = 6;
  request.psize = 4;
  request.op = hton16(1);
  request.src_hw = this->mac_addr;
  request.src_ip = this->ip_addr;
  memset(&request.target_hw, 0, ETHERNET_ADDR_SIZE);
  request.target_ip = *addr;
  if (this->ethernet_output(TYPE_ARP, (uint8_t*)&request, sizeof(request), &ETHERNET_ADDR_BCAST) < 0) {
    return -1;
  }
  return 0;
}

int TapDevice::ethernet_output(uint16_t type, uint8_t *payload, size_t payload_length, const ethernet_addr_t *target_addr) {
  uint8_t frame[ETHERNET_FRAME_SIZE_MAX] = {0};
  eth_hdr *ehdr;
  size_t flen;

  ehdr = (eth_hdr*)frame;
  memcpy(ehdr->dst.addr, target_addr->addr, ETHERNET_ADDR_SIZE);
  memcpy(ehdr->src.addr, this->mac_addr.addr, ETHERNET_ADDR_SIZE);
  ehdr->typ = hton16(type);
  memcpy(ehdr + 1, payload, payload_length);
  flen = sizeof(eth_hdr) + (payload_length < ETHERNET_PAYLOAD_SIZE_MIN ? ETHERNET_PAYLOAD_SIZE_MIN : payload_length);
  return this->output(frame, flen) == (ssize_t)flen ? (ssize_t)payload_length : -1;
}



ssize_t TapDevice::output(const uint8_t *frame, size_t flen) {
  log_ethernet_frame(frame);
  return write(this->fd, frame, flen);
}
