//
// Created by biscuit on 16. 9. 28.
//

#include "socket.hpp"

namespace APP_SOCKET
{

    Address::Address(sockaddr_in *addr_in)
    {
        uint16_t port = ntohs(addr_in->sin_port);
        uint32_t s_addr = ntohl(addr_in->sin_addr.s_addr);
        this->addr = s_addr;
        this->port = port;
    }

    Address::Address(in_addr_t addr, uint16_t port)
    {
        this->addr = addr;
        this->port = port;
    }

    bool Address::operator== (const Address other) {
        bool matchPort = (this->port == other.port);
        bool matchAddr = (this->addr == other.addr);
        bool hasAny = (this->addr == INADDR_ANY || other.addr == INADDR_ANY);

        return matchPort && (matchAddr || hasAny);
    }

    Socket::Socket(int domain, int type)
    {
        // TODO type validation
        this->state = CLOSED;
        this->domain = domain;
        this->type = type;
        this->addr_src = NULL;
        this->addr_dest = NULL;
        this->parent = NULL;
        this->send_seq = (uint32_t) rand();
        this->ack_seq = 0;
    }

    Socket::~Socket() {
        if (this->addr_src != NULL)
            delete this->addr_src;
        if (this->addr_dest != NULL)
            delete this->addr_dest;
    }

    bool Socket::isBound() {
        // TODO Another way
        return (this->addr_src != NULL);
    };

    bool Socket::make_hdr(struct PROTOCOL::kens_hdr *hdr, uint8_t flag) {

        if (addr_src == NULL || addr_dest == NULL)
            return false;

        memset(hdr, 0, sizeof(struct PROTOCOL::kens_hdr));

        hdr->ip.ip_src.s_addr = htonl(addr_src->addr);
        hdr->ip.ip_dst.s_addr = htonl(addr_dest->addr);
        hdr->ip.ip_p = IP_P_TCP;

        hdr->tcp.th_sport = htons(addr_src->port);
        hdr->tcp.th_dport = htons(addr_dest->port);

        hdr->tcp.fin = (flag & TH_FIN) ? 1 : 0;
        hdr->tcp.syn = (flag & TH_SYN) ? 1 : 0;
        hdr->tcp.rst = (flag & TH_RST) ? 1 : 0;
        hdr->tcp.psh = (flag & TH_PUSH) ? 1 : 0;
        hdr->tcp.ack = (flag & TH_ACK) ? 1 : 0;
        hdr->tcp.urg = (flag & TH_URG) ? 1 : 0;

        hdr->tcp.doff = 5;
        hdr->tcp.window = htons(51200);

        hdr->tcp.seq = htonl(send_seq);
        hdr->tcp.ack_seq = (flag & TH_ACK) ? htonl(ack_seq) : 0;

        return true;
    }

    int Socket::bindAddr(sockaddr_in *addr_in) {
        if (this->state != CLOSED)
            return -1;

        this->addr_src = new APP_SOCKET::Address(addr_in);
        return 0;
    }

}