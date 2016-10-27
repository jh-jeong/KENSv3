/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: 근홍
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"
#include "protocol.hpp"
#include <gtest/gtest.h>

using APP_SOCKET::Socket;
using APP_SOCKET::Address;

namespace E {

    TCPAssignment::TCPAssignment(Host *host) : HostModule("TCP", host),
                                               NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
                                               SystemCallInterface(AF_INET, IPPROTO_TCP, host),
                                               NetworkLog(host->getNetworkSystem()),
                                               TimerModule(host->getSystem()) {

    }

    TCPAssignment::~TCPAssignment() {

    }

    void TCPAssignment::initialize() {

    }

    void TCPAssignment::finalize() {

    }

    Socket *TCPAssignment::getAppSocket(int pid, int fd) {
        std::unordered_map<s_id, APP_SOCKET::Socket *, std::hash<s_id>>::iterator entry;
        s_id sock_id = {pid, fd};
        entry = app_sockets.find(sock_id);

        if (entry == app_sockets.end())
            return NULL;
        return entry->second;
    }

    long TCPAssignment::removeAppSocket(int pid, int fd) {
        s_id sock_id = {pid, fd};
        return app_sockets.erase(sock_id);
    }

    bool TCPAssignment::checkOverlap (sockaddr_in* other) {
        for(auto it = sockets.begin(); it != sockets.end() ; ++it )
        {
            Socket *sock = *it;
            if (!sock->isBound())
                continue;
            if ((*sock->addr_src) == Address(other))
                return true; //overlap
        }
        return false;
    }

    bool TCPAssignment::sendFlagPacket(APP_SOCKET::Socket *sock, uint8_t flag) {
        Packet *packet = allocatePacket(sizeof(struct PROTOCOL::kens_hdr));
        struct PROTOCOL::kens_hdr hdr;
        if (!sock->make_hdr(&hdr, flag)) {
            freePacket(packet);
            return false;
        }

        hdr.tcp.check = htons(~NetworkUtil::tcp_sum(hdr.ip.ip_src.s_addr,
                                                    hdr.ip.ip_dst.s_addr,
                                                    (uint8_t *) &(hdr.tcp),
                                                    sizeof (struct tcphdr)));

        packet->writeData(0, &hdr, sizeof(struct PROTOCOL::kens_hdr));
        this->sendPacket("IPv4", packet);

        return true;
    }

    void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter &param) {
        switch (param.syscallNumber) {
            case SOCKET:
                this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
                break;
            case CLOSE:
                this->syscall_close(syscallUUID, pid, param.param1_int);
                break;
            case READ:
                //this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
                break;
            case WRITE:
                //this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
                break;
            case CONNECT:
                this->syscall_connect(syscallUUID, pid, param.param1_int,
                                      static_cast<struct sockaddr*>(param.param2_ptr),
                                      (socklen_t)param.param3_int);
                break;
            case LISTEN:
                this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
                break;
            case ACCEPT:
                this->syscall_accept(syscallUUID, pid, param.param1_int,
                                     static_cast<struct sockaddr*>(param.param2_ptr),
                                     static_cast<socklen_t*>(param.param3_ptr));
                break;
            case BIND:
                this->syscall_bind(syscallUUID, pid, param.param1_int,
                                   static_cast<struct sockaddr *>(param.param2_ptr),
                                   (socklen_t) param.param3_int);
                break;
            case GETSOCKNAME:
                this->syscall_getsockname(syscallUUID, pid, param.param1_int,
                                          static_cast<struct sockaddr *>(param.param2_ptr),
                                          static_cast<socklen_t*>(param.param3_ptr));
                break;
            case GETPEERNAME:
                //this->syscall_getpeername(syscallUUID, pid, param.param1_int,
                //		static_cast<struct sockaddr *>(param.param2_ptr),
                //		static_cast<socklen_t*>(param.param3_ptr));
                break;
            default:
                assert(0);
        }
    }

    void TCPAssignment::packetArrived(std::string fromModule, Packet *packet) {
        if (fromModule.compare("IPv4")) {
            freePacket(packet);
            return;
        }

        if (packet->getSize() < sizeof (struct PROTOCOL::kens_hdr)) {
            freePacket(packet);
            return;
        }

        struct PROTOCOL::kens_hdr hdr;
        packet->readData(0, &hdr, sizeof (struct PROTOCOL::kens_hdr));

        Address *src = new Address(ntohl(hdr.ip.ip_src.s_addr),
                                   ntohs(hdr.tcp.th_sport));
        Address *dst = new Address(ntohl(hdr.ip.ip_dst.s_addr),
                                   ntohs(hdr.tcp.th_dport));
        Socket *sock = NULL;

        for(auto it = sockets.begin(); it != sockets.end() ; ++it )
        {
            Socket *s = *it;
            if (s->addr_src == NULL || s->addr_dest == NULL)
                continue;
            if (!((*s->addr_src) == *dst))
                continue;
            if (!((*s->addr_dest) == *src))
                continue;
            sock = s;
            break;
        }

        if (sock == NULL) {
            for(auto it = listen_sockets.begin(); it != listen_sockets.end() ; ++it )
            {
                Socket *s = *it;
                if (!((*s->addr_src) == *dst))
                    continue;
                sock = s;
                break;
            }
        }

        if (sock == NULL) {
            freePacket(packet);
            return;
        }

        freePacket(packet);

        switch (sock->state) {
            case APP_SOCKET::LISTEN:
                //recv syn packet 
                //send syn ack
                if(hdr.tcp.syn) {
                    Socket *d_sock = new Socket(*sock);
                    sockets.insert(d_sock);

                    d_sock->addr_dest = src;
                    d_sock->addr_src = dst;
                    d_sock->state = APP_SOCKET::SYN_RCVD;
                    d_sock->send_seq = (uint32_t) rand();
                    d_sock->ack_seq = ntohl(hdr.tcp.seq) + 1;

                    sendFlagPacket(d_sock, TH_SYN | TH_ACK);
                }
                break;
            case APP_SOCKET::SYN_RCVD:
                if(hdr.tcp.ack) {
                    sock->state = APP_SOCKET::ESTABLISHED;

                    APP_SOCKET::Socket *l_sock = NULL;

                    for(auto it = listen_sockets.begin(); it != listen_sockets.end() ; ++it )
                    {
                        Socket *s = *it;
                        if (!((*s->addr_src) == *dst))
                            continue;
                        l_sock = s;
                        break;
                    }

                    if (l_sock != NULL) {
                        l_sock->wait_queue.push(sock);
                    }
                }
                break;

            case APP_SOCKET::SYN_SENT:
                //recv syn_ack from server
                //send ack
                // go established
                if(hdr.tcp.syn && hdr.tcp.ack) {
                    sendFlagPacket(sock, TH_ACK);
                    sock->state = APP_SOCKET::ESTABLISHED;

                    std::unordered_map<APP_SOCKET::Socket *, UUID>::iterator entry;
                    entry = syscall_blocks.find(sock);

                    if (entry == syscall_blocks.end()) {
                        freePacket(packet);
                        return;
                    }

                    UUID syscallUUID = entry->second;
                    returnSystemCall(syscallUUID, 0);
                }
                break;
            case APP_SOCKET::ESTABLISHED:
                break;
            case APP_SOCKET::CLOSE_WAIT:
                break;
            case APP_SOCKET::LAST_ACK:
                break;
            case APP_SOCKET::FIN_WAIT_1:
                break;
            case APP_SOCKET::FIN_WAIT_2:
                break;
            case APP_SOCKET::CLOSING:
                break;
            case APP_SOCKET::TIME_WAIT:
                break;
            default:
                break;
        }
    }

    void TCPAssignment::timerCallback(void *payload) {

    }

    void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type) {
        int fd = createFileDescriptor(pid);
        if (fd < 0) {
            returnSystemCall(syscallUUID, fd);
            return;
        }
        s_id sock_id = {pid, fd};

        Socket *sock = new Socket(domain, type);
        // TODO socket valid check

        sockets.insert(sock);
        app_sockets[sock_id] = sock;
        returnSystemCall(syscallUUID, fd);
    }

    void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd) {
        Socket *sock = getAppSocket(pid, fd);

        removeAppSocket(pid, fd);

        if (sock != NULL) {
            sockets.erase(sock);
            if (sock->state == APP_SOCKET::LISTEN) {
                listen_sockets.erase(sock);
            }
            delete sock;
        }

        removeFileDescriptor(pid, fd);
        returnSystemCall(syscallUUID, 0);
    }

    void TCPAssignment::syscall_bind(UUID syscallUUID, int pid,
                                     int sockfd, const struct sockaddr *addr, socklen_t addrlen) {

        // convert sockaddr -> sockaddr_in
        if (addr->sa_family != AF_INET) {
            errno = -EAFNOSUPPORT;
            returnSystemCall(syscallUUID, -1);
            return;
        }

        struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;
        Socket *sock = getAppSocket(pid, sockfd);

        if (sock == NULL) {
            errno = EBADF;
            returnSystemCall(syscallUUID, -1);
            return;
        }
        if (sock->isBound()) {
            returnSystemCall(syscallUUID, -1);
            return;
        }

        if(checkOverlap(addr_in)) {
            returnSystemCall(syscallUUID, -1);
            return;
        }

        returnSystemCall(syscallUUID, sock->bindAddr(addr_in));
    }

    void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid,
                                            int sockfd , struct sockaddr *addr , socklen_t *addrlen) {
        Socket *sock = getAppSocket(pid, sockfd);
        if (sock == NULL) {
            errno = EBADF;
            returnSystemCall(syscallUUID, -1);
            return;
        }

        struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;
        addr_in->sin_port = htons(sock->addr_src->port);
        addr_in->sin_addr.s_addr = htonl(sock->addr_src->addr);
        addr_in->sin_family = AF_INET;

        returnSystemCall(syscallUUID, 0);
    }

    void TCPAssignment::syscall_listen(UUID syscallUUID, int pid,
                                       int sockfd, int backlog) {
        if (backlog <= 0) {
            errno = EINVAL;
            returnSystemCall(syscallUUID, -1);
            return;
        }

        Socket *sock = getAppSocket(pid, sockfd);
        if (sock == NULL) {
            errno = EBADF;
            returnSystemCall(syscallUUID, -1);
            return;
        }

        if (sock->state != APP_SOCKET::CLOSED) {
            errno = EADDRINUSE;
            returnSystemCall(syscallUUID, -1);
            return;
        }
        if (!sock->isBound()) {
            errno = EADDRINUSE;
            returnSystemCall(syscallUUID, -1);
            return;
        }
        sock->backlog = backlog;
        sock->state = APP_SOCKET::LISTEN;
        listen_sockets.insert(sock);
        returnSystemCall(syscallUUID, 0);
    }

    void TCPAssignment::syscall_accept(UUID syscallUUID, int pid,
                                       int sockfd, struct sockaddr *addr,
                                       socklen_t *addrlen) {

        Socket *sock = getAppSocket(pid, sockfd);
        if (sock == NULL) {
            errno = EBADF;
            returnSystemCall(syscallUUID, -1);
            return;
        }
        if (addrlen <= 0) {
            errno = EINVAL;
            returnSystemCall(syscallUUID, -1);
            return;
        }
        if (sock->state != APP_SOCKET::LISTEN) {
            errno = EINVAL;
            returnSystemCall(syscallUUID, -1);
            return;
        }

        struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;


        if (!sock->wait_queue.empty()) {
            Socket *d_sock = sock->wait_queue.front();
            sock->wait_queue.pop();

            memset(addr_in, 0, sizeof(struct sockaddr_in));
            addr_in->sin_port = htons(d_sock->addr_dest->port);
            addr_in->sin_addr.s_addr = htonl(d_sock->addr_dest->addr);
            addr_in->sin_family = AF_INET;
            *addrlen = sizeof(struct sockaddr_in);

            int fd = createFileDescriptor(pid);
            d_sock->state = APP_SOCKET::ESTABLISHED;

            sockets.insert(d_sock);
            s_id sock_id = {pid, fd};
            app_sockets[sock_id] = d_sock;

            returnSystemCall(syscallUUID, fd);
        }

    }

    void TCPAssignment::syscall_connect(UUID syscallUUID, int pid,
                                        int sockfd, const struct sockaddr *addr,
                                        socklen_t addrlen) {

        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        Socket *sock = getAppSocket(pid, sockfd);

        uint32_t c_addr;
        uint16_t c_port;
        Host *c_host = getHost();

        if (sock == NULL) {
            errno = EBADF;
            returnSystemCall(syscallUUID, -1);
            return;
        }
        if (sock->state == APP_SOCKET::CLOSED) {
            errno = EISCONN;
            returnSystemCall(syscallUUID, -1);
            return;
        }

        if (addrlen != sizeof (struct sockaddr_in)) {
            errno = EFAULT;
            returnSystemCall(syscallUUID, -1);
            return;
        }
        if(!sock->isBound())
        {
            uint32_t local = LOCALHOST;

            struct sockaddr_in c_addr_in;
            memset(&c_addr_in, 0, sizeof (struct sockaddr_in));
            c_addr_in.sin_family = addr_in->sin_family;

            if (!c_host->getIPAddr((uint8_t *)&c_addr,
                                   c_host->getRoutingTable((uint8_t *) &local))) {
                returnSystemCall(syscallUUID, -1);
                return;
            }
            c_addr = ntohl(c_addr); // c_addr is in network order

            int p_iter = 0;
            for (p_iter = 0; p_iter < PORT_ITER_MAX; p_iter++) {
                c_port = (uint16_t) ((rand() % (LOCAL_PORT_MAX + 1 - LOCAL_PORT_MIN)) + LOCAL_PORT_MIN);
                c_addr_in.sin_addr.s_addr = c_addr;
                c_addr_in.sin_port = c_port;

                // TODO checkOverlap must be tested before calling bindAddr -> capsulate
                if (!checkOverlap(&c_addr_in))
                {
                    sock->bindAddr(&c_addr_in); // TODO sock is guaranteed to be CLOSED.
                    break;
                }
            }
            if (p_iter == PORT_ITER_MAX) {
                errno = EADDRNOTAVAIL;
                returnSystemCall(syscallUUID, -1);
                return;
            }
        }

        sock->addr_dest->addr = addr_in->sin_addr.s_addr;
        sock->addr_dest->port = addr_in->sin_port;

        sendFlagPacket(sock, TH_SYN);
        syscall_blocks[sock] = syscallUUID;

        sock->state = APP_SOCKET::SYN_SENT;
    }
}