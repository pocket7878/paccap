#include "packet.hpp"
#include "net_util.hpp"
#include "json.hpp"

nlohmann::json pk_tcp_data_t::to_json() {
    nlohmann::json obj;

    obj["src_port"] = src_port;
    obj["dst_port"] = dst_port;

    return obj;
}

nlohmann::json pk_udp_data_t::to_json() {
    nlohmann::json obj;

    obj["src_port"] = src_port;
    obj["dst_port"] = dst_port;

    return obj;
}

nlohmann::json pk_ipv4_payload_t::to_json() {
    nlohmann::json obj;

    obj["ttl"] = ttl;
    obj["src_ip"] = ip_addr_string(src_ip.addr);
    obj["dst_ip"] = ip_addr_string(dst_ip.addr);

    switch(protocol) {
        case PACKET_PROTOCOL_TCP:
            obj["tcp"] = data.tcp_data.to_json();
            break;
        case PACKET_PROTOCOL_UDP:
            obj["udp"] = data.udp_data.to_json();
            break;
    }

    return obj;
}

nlohmann::json pk_arp_payload_t::to_json() {
    nlohmann::json obj;

    obj["htype"] = htype;
    obj["ptype"] = ptype;
    switch(op) {
        case ARP_OP_REQ:
            obj["op"] = "request";
            break;
        case ARP_OP_RES:
            obj["op"] = "response";
            break;
        case ARP_OP_RREQ:
            obj["op"] = "reverse_request";
            break;
        case ARP_OP_RRES:
            obj["op"] = "reverse_response";
            break;
    }

    obj["src_hw"] = mac_addr_string(src_hw.addr);
    obj["src_ip"] = ip_addr_string(src_ip.addr);
    obj["dst_hw"] = mac_addr_string(dst_hw.addr);
    obj["dst_ip"] = ip_addr_string(dst_ip.addr);

    return obj;
}


nlohmann::json pk_ethernet_frame_t::to_json() {
    nlohmann::json obj;

    switch(type) {
        case PACKET_TYPE_ARP:
            obj["type"] = "arp";
            obj["arp"] = payload.arp_payload.to_json();
            break;
        case PACKET_TYPE_IPV4:
            obj["type"] = "ipv4";
            obj["ipv4"] = payload.ipv4_payload.to_json();
            break;
    }

    obj["raw_type"] = raw_type;
    obj["src_hw"] = mac_addr_string(src_hw.addr);
    obj["dst_hw"] = mac_addr_string(dst_hw.addr);

    return obj;
}
