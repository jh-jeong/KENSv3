//
// Created by biscuit on 16. 10. 27.
//

#include <cstring>
#include <iostream>
#include "protocol.hpp"

namespace PROTOCOL
{
    /* Calculate the checksum of the buffer with given size. */
    uint16_t checksum (const char *buf, size_t size) {
        uint64_t sum = 0;
        const uint64_t *b = (uint64_t *) buf;

        uint32_t t1, t2;
        uint16_t t3, t4;

        /* Main loop - 8 bytes at a time */
        while (size >= 8) {
            uint64_t s = *b++;
            sum += s;
            if (sum < s) sum++;
            size -= 8;
        }

        /* Handle tail less than 8-bytes long */
        buf = (const char *) b;
        if (size & 4) {
            uint32_t s = *(uint32_t *) buf;
            sum += s;
            if (sum < s) sum++;
            buf += 4;
            size -= 4;
        }

        if (size & 2) {
            uint16_t s = *(uint16_t *) buf;
            sum += s;
            if (sum < s) sum++;
            buf += 2;
            size -= 2;
        }

        if (size) {
            unsigned char s = *(unsigned char *) buf;
            sum += s;
            if (sum < s) sum++;
        }

        /* Fold down to 16 bits */
        t1 = sum;
        t2 = sum >> 32;
        t1 += t2;
        if (t1 < t2) t1++;
        t3 = t1;
        t4 = t1 >> 16;
        t3 += t4;
        if (t3 < t4) t3++;

        return ~t3;
    }

    uint16_t tcp_checksum (struct kens_hdr *hdr) {
        struct tcphdr *thdr = &(hdr->tcp);
        struct pseudo_tcp_hdr pth;
        size_t size = sizeof(struct pseudo_tcp_hdr) + sizeof(struct tcphdr);
        char buf[size] = {0};

        pth.source.s_addr = hdr->ip.ip_src.s_addr;
        pth.dest.s_addr = hdr->ip.ip_dst.s_addr;
        pth.protocol = hdr->ip.ip_p;

        // TODO size with buffer
        pth.tcp_size = htons(sizeof(struct tcphdr));

        memcpy(buf, &pth, sizeof(struct pseudo_tcp_hdr));
        memcpy(buf+sizeof(struct pseudo_tcp_hdr), thdr, sizeof(struct tcphdr));

        std::cout<< std::hex << int(hdr->ip.ip_p) <<std::endl;
        std::cout<< std::hex << pth.dest.s_addr <<std::endl;

        return checksum(buf, size);

    }

}