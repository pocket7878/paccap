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
#include <net/bpf.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#include <boost/format.hpp>

#include "device.hpp"
#include "net_util.hpp"
#include "arp.hpp"

BpfDevice::BpfDevice(char *ifname): ifname(ifname) {
}

int BpfDevice::open_device() {
    char buf[11] = {0};
    for (int i = 0; i < 99; i++) {
        sprintf(buf, "/dev/bpf%d", i);
        this->fd = open(buf, O_RDWR);
        if(this->fd != -1) break;
    }

    if (this->fd == -1) {
        return -1;
    }

    return 0;
}

int BpfDevice::bind_device() {
    struct ifreq interface;
    strcpy(interface.ifr_name, this->ifname);
    if(ioctl(this->fd, BIOCSETIF, &interface) > 0) {
        perror("ioctl BIOCSETIF");
        return -1;
    }

    unsigned int one = 1;
    // BIOCIMMEDIATE : 受信したら即時readする
    if (ioctl(this->fd, BIOCIMMEDIATE, &one) == -1) {
        perror("ioctl BIOCIMMEDIATE");
        return -1;
    }

    // BIOCGBLEN : 受信バッファの必要サイズ
    if (ioctl(this->fd, BIOCGBLEN, &this->buf_len) == -1) {
        perror("ioctl BIOCGBLEN");
        return -1;
    }

    // 強制的にプロミスキャスモードにする
    if (ioctl(this->fd, BIOCPROMISC, NULL) == -1) {
        perror("ioctl BIOCPROMISC");
        return -1;
    }

    return 0;
}

int BpfDevice::load_mac_addr() {
    if (get_mac_addr(this->ifname, &this->mac_addr) < 0) {
        return -1;
    }

    return 0;
}

int BpfDevice::load_ip_addr() {
    if (get_ip_addr(this->ifname, &this->ip_addr) < 0) {
        return -1;
    }
    return 0;
}

int BpfDevice::init() {
    if (this->open_device() < 0) {
        return -1;
    }
    if (this->bind_device() < 0) {
        return -1;
    }

    if (this->load_mac_addr() < 0) {
        return -1;
    }

    if (this->load_ip_addr() < 0) {
        return -1;
    }

    return 0;
}

std::vector<pk_ethernet_frame_t> BpfDevice::read_packets() {
    std::vector<pk_ethernet_frame_t> result;
    int read_byte = 0;
    char *bpf_buf = (char*)malloc(sizeof(char) * this->buf_len);

    memset(bpf_buf, 0, this->buf_len);

    if ((read_byte = read(this->fd, bpf_buf, this->buf_len)) == -1) {
        perror("read");
        return result;
    }

    if (read_byte <= 0) {
        return result;
    }

    char *ptr = 0;
    struct bpf_hdr* bpfPacket;

    while(((int)(size_t)ptr + sizeof(bpf_buf)) < read_byte) {
        bpfPacket = (struct bpf_hdr*)((long)bpf_buf + (long)ptr);
        pk_ethernet_frame_t obj = parse_eth_frame(((long)bpf_buf + (long)ptr + bpfPacket->bh_hdrlen));
        result.push_back(obj);
        ptr += BPF_WORDALIGN(bpfPacket->bh_hdrlen + bpfPacket->bh_caplen);
    }

    return result;
}

int BpfDevice::send_arp_request(const ip_addr_t *addr) {
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

int BpfDevice::ethernet_output(uint16_t type, uint8_t *payload, size_t payload_length, const ethernet_addr_t *target_addr) {
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



ssize_t BpfDevice::output(const uint8_t *frame, size_t flen) {
  log_ethernet_frame(frame);
  return write(this->fd, frame, flen);
}
