//
// Created by biscuit on 16. 10. 13.
//

#ifndef KENSV3_PROTOCOL_HPP
#define KENSV3_PROTOCOL_HPP


#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>

#define IP_P_TCP 6

namespace PROTOCOL
{

    struct kens_hdr {
        struct ethhdr eth;
        struct ip ip;
        struct tcphdr tcp;
    } __attribute__((packed));

    struct pseudo_tcp_hdr
    {
        struct in_addr source, dest;
        u_int8_t reserved;
        u_int8_t protocol;
        u_int16_t tcp_size;
    } __attribute__((packed));

    uint16_t checksum (const char *buf, size_t size);
    uint16_t tcp_checksum (struct kens_hdr *hdr);
}




#endif //KENSV3_PROTOCOL_HPP