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

}

#endif //KENSV3_PROTOCOL_HPP