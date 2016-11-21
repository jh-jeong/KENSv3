//
// Created by biscuit on 16. 9. 28.
//

#ifndef KENSV3_SOCKET_HPP
#define KENSV3_SOCKET_HPP


#include <utility>

#include <E/E_Common.hpp>
#include <E/Networking/E_Packet.hpp>
#include <netinet/in.h>
#include "protocol.hpp"
#include "buffer.hpp"

#define MSS 512
#define RECV_BUFFER MSS*100
#define SEND_BUFFER MSS*50

#define SSTHRESH_INIT MSS*128
#define DEFAULT_RTT 100
#define DEFAULT_RTO 3000
#define ALPHA 0.125
#define BETA 0.25
#define K 4

namespace APP_SOCKET
{
    class Address
    {
    public:
        Address(sockaddr_in *addr_in);
        Address(in_addr_t addr, uint16_t port);

        in_addr_t addr;
        uint16_t port;

        bool operator == (const Address other);
    };

    enum CongStatus{
        SLOW_START,
        CONGESTION_AVOIDANCE,
        FAST_RECOVERY
    };

    enum Status {
        CLOSED,
        LISTEN,
        SYN_RCVD,
        SYN_SENT,
        ESTABLISHED,
        CLOSE_WAIT,
        LAST_ACK,
        FIN_WAIT_1,
        FIN_WAIT_2,
        CLOSING,
        TIME_WAIT
    };

    class Socket
    {
    public:
        Address *addr_src;
        Address *addr_dest;

        Socket* parent;

        Status state;

        uint32_t syn_seq;
        uint32_t fin_seq;
        bool synack;
        bool peer_fin;
        uint32_t fin_rcvd;

        uint32_t send_base;
        uint32_t send_seq;
        uint32_t ack_seq;

        int type;
        int domain;
        uint backlog;

        IndexedCacheBuffer *buf_recv;
        CircularBuffer *buf_send;
        u_int16_t rwnd;

        CongStatus cong_state;
        uint32_t cwnd;
        uint32_t sstresh;
        int dupACKcount;

        int64_t send_time;
        double rto;
        double rtt;
        double rttvar;

        uint64_t timer_slot;
        uint64_t time_wait;

        Socket(int domain, int type);
        ~Socket();

        Socket* getChild(Address *src, Address *dst, uint32_t ack_init);

        bool getPacket(char *packet, uint8_t flag, size_t offset, size_t c_size);

        bool listen(int backlog);

        bool isBound();
        bool make_hdr(struct PROTOCOL::kens_hdr *hdr, uint8_t flag);
        int bindAddr(sockaddr_in *addr_in);

        std::set<APP_SOCKET::Socket *> wait_sock;
        std::queue<APP_SOCKET::Socket *> est_queue;
    };
}

#endif //KENSV3_SOCKET_HPP