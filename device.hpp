#include "json.hpp"
#include "ethernet.hpp"
#include "ip.hpp"
#include "packet.hpp"
#include <vector>

class Device {
    public:
    virtual ~Device() {}
    virtual int init() = 0;
    virtual std::vector<pk_ethernet_frame_t> read_packets() = 0;
};

class BpfDevice: Device {
    private:
        int fd;
        char *ifname;
        int buf_len;
        ethernet_addr_t mac_addr;
        ip_addr_t ip_addr;
        int open_device();
        int bind_device();
        int load_mac_addr();
        int load_ip_addr();
        ssize_t output(const uint8_t *frame, size_t flen);
    public:
        BpfDevice(char *ifname);
        virtual int init();
        virtual std::vector<pk_ethernet_frame_t> read_packets();
        int send_arp_request(const ip_addr_t *addr);
        int ethernet_output(uint16_t type, uint8_t *payload, size_t payload_length, const ethernet_addr_t *target_addr);
};

class TapDevice: Device {
    private:
        int fd;
        char ifname[5];
        ethernet_addr_t mac_addr;
        ip_addr_t ip_addr;
        int open_device();
        int up_device();
        int load_mac_addr();
        ssize_t output(const uint8_t *frame, size_t flen);
    public:
        TapDevice();
        virtual int init();
        virtual std::vector<pk_ethernet_frame_t> read_packets();
        int set_ip(ip_addr_t addr);
        int send_arp_request(const ip_addr_t *addr);
        int ethernet_output(uint16_t type, uint8_t *payload, size_t payload_length, const ethernet_addr_t *target_addr);
};
