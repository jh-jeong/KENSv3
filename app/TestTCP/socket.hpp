//
// Created by biscuit on 16. 9. 28.
//

#ifndef KENSV3_SOCKET_HPP
#define KENSV3_SOCKET_HPP


#include <utility>

#include <E/E_Common.hpp>
#include <netinet/in.h>
#include "protocol.hpp"


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

        Status state;
        uint32_t send_seq;
        uint32_t ack_seq;

        int type;
        int domain;
        int backlog;

        Socket(int domain, int type);
        ~Socket();

        bool isBound();
        bool make_hdr(struct PROTOCOL::kens_hdr *hdr, uint8_t flag);
        int bindAddr(sockaddr_in *addr_in);

        std::queue<APP_SOCKET::Socket *> wait_queue;
    };

}

#endif //KENSV3_SOCKET_HPP