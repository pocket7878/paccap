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

#include "packet.hpp"
#include "json.hpp"
#include "net_util.hpp"

int get_mac_addr(char *ifname, caddr_t *mac_addr) {
    struct ifaddrs *ifa_list, *ifa;
    struct sockaddr_dl *dl;
    char name[12];
    unsigned char *addr;
    if (getifaddrs(&ifa_list) < 0) {
        return -1;
    }
    for(ifa = ifa_list; ifa != NULL; ifa = ifa->ifa_next) {
        if (strcmp(ifname, ifa->ifa_name) == 0) {
        dl = (struct sockaddr_dl*)ifa->ifa_addr;
        if (dl->sdl_family == AF_LINK && dl->sdl_type == IFT_ETHER) {
                memcpy(name, dl->sdl_data, dl->sdl_nlen);
                name[dl->sdl_nlen] = '\0';
                *mac_addr = LLADDR(dl);
                return 0;
            }
        }
    }

    return -1;
}

nlohmann::json parse_eth_frame(long eth_frame) {
    nlohmann::json obj;

    eth_hdr *ehdr = (eth_hdr*)eth_frame;
    obj["src_mac"] = (boost::format("%x:%x:%x:%x:%x:%x") % (unsigned int)ehdr->src_mac[0] % (unsigned int)ehdr->src_mac[1] % (unsigned int)ehdr->src_mac[2] % (unsigned int)ehdr->src_mac[3] % (unsigned int)ehdr->src_mac[4] % (unsigned int)ehdr->src_mac[5]).str();
    obj["dst_mac"] = (boost::format("%x:%x:%x:%x:%x:%x") % (unsigned int)ehdr->dst_mac[0] % (unsigned int)ehdr->dst_mac[1] % (unsigned int)ehdr->dst_mac[2] % (unsigned int)ehdr->dst_mac[3] % (unsigned int)ehdr->dst_mac[4] % (unsigned int)ehdr->dst_mac[5]).str();
    obj["raw_eth_type"] = ehdr->typ;
    if (ehdr->typ == TYPE_IPV4) {
        obj["eth_type"] = "ipv4";

        nlohmann::json ip_obj;

        ip_hdr *iphdr = (ip_hdr*)((long)ehdr + sizeof(eth_hdr));
        ip_obj["header_length"] = iphdr->ihl * 4;
        ip_obj["ttl"] = iphdr->ttl;
        ip_obj["dst_addr"] = (boost::format("%d.%d.%d.%d") % (unsigned int)iphdr->dst_addr[0] % (unsigned int)iphdr->dst_addr[1] % (unsigned int)iphdr->dst_addr[2]  % (unsigned int)iphdr->dst_addr[3]).str();
        ip_obj["src_addr"] = (boost::format("%d.%d.%d.%d") % (unsigned int)iphdr->src_addr[0] % (unsigned int)iphdr->src_addr[1] % (unsigned int)iphdr->src_addr[2]  % (unsigned int)iphdr->src_addr[3]).str();
        if (iphdr->protocol == IP_PROT_TCP) {
            nlohmann::json tcp_obj;
            tcp_hdr *tcp = (tcp_hdr*)((long)iphdr + (iphdr->ihl * 4));
            tcp_obj["dst_port"] = tcp->dst_port;
            tcp_obj["src_port"] = tcp->src_port;
            ip_obj["tcp"] = tcp_obj;
        } else if (iphdr->protocol == IP_PROT_UDP) {
            nlohmann::json udp_obj;
            udp_hdr *udp = (udp_hdr*)((long)iphdr + (iphdr->ihl * 4));
            udp_obj["dst_port"] = udp->dst_port;
            udp_obj["src_port"] = udp->src_port;
            ip_obj["udp"] = udp_obj;
        }
        obj["ip"] = ip_obj;
    } else {
        obj["eth_type"] = "unknown";
    }

    return obj;
}
