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

#include "device.hpp"
#include "net_util.hpp"

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
    char name_buf[5] = {0};
    char path_buf[11] = {0};
    for (int i = 0; i < 99; i++) {
        sprintf(name_buf, "/dev/tap%d", i);
        sprintf(path_buf, "/dev/%s", name_buf);
        this->fd = open(path_buf, O_RDWR);
        if(this->fd != -1) break;
    }

    if (this->fd == -1) {
        return -1;
    }

    return 0;
}

int TapDevice::up_device() {
    char cmd_buf[512];
    sprintf(cmd_buf, "sudo ifconfig %s up", this->ifname, 512);
    std::system(cmd_buf);

    return 0;
}

int TapDevice::load_mac_addr() {
    if (get_mac_addr(this->ifname, &this->mac_addr) < 0) {
        return -1;
    }

    return 0;
}

std::vector<nlohmann::json> TapDevice::read_packets() {
    std::vector<nlohmann::json> result;
    int read_byte = 0;
    char packet_buf[1500];

    memset(packet_buf, 0, 1500);

    if ((read_byte = read(this->fd, packet_buf, 1500)) < 0) {
        perror("read");
        return result;
    }

    if (read_byte <= 0) {
        return result;
    }

    nlohmann::json obj = parse_eth_frame((long)packet_buf);
    result.push_back(obj);

    return result;
}
