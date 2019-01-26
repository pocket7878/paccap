#include "json.hpp"
#include "packet.hpp"
#include <vector>

class Device {
    public:
    virtual ~Device() {}
    virtual int init() = 0;
    virtual std::vector<nlohmann::json> read_packets() = 0;
};

class BpfDevice: Device {
    private:
        int fd;
        char *ifname;
        int buf_len;
        caddr_t mac_addr;
        int open_device();
        int bind_device();
        int load_mac_addr();
    public:
        BpfDevice(char *ifname);
        virtual int init();
        virtual std::vector<nlohmann::json> read_packets();
};

class TapDevice: Device {
    private:
        int fd;
        char *ifname;
        caddr_t mac_addr;
        int open_device();
        int up_device();
        int load_mac_addr();
    public:
        TapDevice();
        virtual int init();
        virtual std::vector<nlohmann::json> read_packets();
};
