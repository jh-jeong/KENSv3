//
// Created by biscuit on 16. 9. 28.
//

#include <E/Networking/E_NetworkUtil.hpp>
#include "socket.hpp"
#include <cerrno>

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
        this->send_base = (uint32_t) rand();
        this->send_seq = send_base;
        this->ack_seq = 0;

        this->syn_seq = 0;
        this->fin_seq = 0;
        this->synack = false;
        this->peer_fin = false;
        this->fin_rcvd = 0;

        this->buf_recv = new IndexedCacheBuffer(RECV_BUFFER);
        this->buf_send = new CircularBuffer(SEND_BUFFER);

        this->rwnd = 0;

        this->cong_state = SLOW_START;
        this->cwnd = MSS;
        this->sstresh = SSTHRESH_INIT;
        this->dupACKcount = 0;
    }

    Socket::~Socket() {
        if (this->addr_src != NULL)
            delete this->addr_src;
        if (this->addr_dest != NULL)
            delete this->addr_dest;

        delete this->buf_recv;
        delete this->buf_send;
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

        hdr->tcp.seq = htonl(send_base);
        hdr->tcp.ack_seq = (flag & TH_ACK) ? htonl(ack_seq) : 0;

        return true;
    }

    bool Socket::getPacket(char *buf, uint8_t flag, size_t offset, size_t c_size) {

        struct PROTOCOL::kens_hdr *hdr = (struct PROTOCOL::kens_hdr *) buf;
        if (!make_hdr(hdr, flag))
            return false;

        if (c_size != 0) {
            buf_send->read(buf + sizeof(struct PROTOCOL::kens_hdr), c_size, offset);
        }
        hdr->tcp.seq = htonl(send_base + (uint32_t) offset);
        hdr->tcp.check = htons(~E::NetworkUtil::tcp_sum(hdr->ip.ip_src.s_addr,
                                                        hdr->ip.ip_dst.s_addr,
                                                        (uint8_t *) &(hdr->tcp),
                                                        (sizeof(struct tcphdr)) + c_size));
        return true;
    }

    bool Socket::listen(int backlog) {
        if (backlog <= 0) {
            errno = EINVAL;
            return false;
        }
        if (state != CLOSED) {
            errno = EADDRINUSE;
            return false;
        }
        if (!isBound()) {
            errno = EADDRINUSE;
            return false;
        }

        this->backlog = (unsigned int) backlog;
        this->state = APP_SOCKET::LISTEN;

        return true;
    }

    Socket* Socket::getChild(Address *src, Address *dst, uint32_t ack_init) {
        Socket *d_sock = new Socket(*this);

        d_sock->addr_src = src;
        d_sock->addr_dest = dst;
        d_sock->state = SYN_RCVD;
        d_sock->send_base = (uint32_t) rand();
        d_sock->send_seq = d_sock->send_base;
        d_sock->ack_seq = ack_init;
        d_sock->parent = this;
        d_sock->buf_recv = new IndexedCacheBuffer(RECV_BUFFER);
        d_sock->buf_send = new CircularBuffer(SEND_BUFFER);

        return d_sock;
    }

    int Socket::bindAddr(sockaddr_in *addr_in) {
        if (this->state != CLOSED)
            return -1;

        this->addr_src = new APP_SOCKET::Address(addr_in);
        return 0;
    }

}