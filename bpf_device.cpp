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
}

int BpfDevice::load_mac_addr() {
    if (get_mac_addr(this->ifname, &this->mac_addr) < 0) {
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
}

std::vector<nlohmann::json> BpfDevice::read_packets() {
    std::vector<nlohmann::json> result;
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
        nlohmann::json obj = parse_eth_frame(((long)bpf_buf + (long)ptr + bpfPacket->bh_hdrlen));
        result.push_back(obj);
        ptr += BPF_WORDALIGN(bpfPacket->bh_hdrlen + bpfPacket->bh_caplen);
    }

    return result;
}
