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
        size_t p_size = sock->packetSize();
        size_t d_size = p_size - sizeof(struct PROTOCOL::kens_hdr);

        Packet *packet = allocatePacket(p_size);
        if (!sock->getPacket(packet, flag, p_size)) {
            freePacket(packet);
            return false;
        }
        this->sendPacket("IPv4", packet);
        sock->send_seq += d_size;

        if (flag & (TH_SYN | TH_FIN)) {
            sock->send_seq++;
        }

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
                this->syscall_getpeername(syscallUUID, pid, param.param1_int,
                		static_cast<struct sockaddr *>(param.param2_ptr),
                		static_cast<socklen_t*>(param.param3_ptr));
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

        uint32_t ack_num = ntohl(hdr.tcp.ack_seq);
        if (ack_num > sock->send_base) {
            sock->send_base = ack_num;
            if (sock->send_base > sock->send_seq)
                sock->send_seq = sock->send_base;
        }

        switch (sock->state) {
            case APP_SOCKET::LISTEN:
                //recv syn packet
                //send syn ack

                if(hdr.tcp.syn) {
                    Socket *d_sock = sock->getChild(dst, src, ntohl(hdr.tcp.seq)+1);
                    sockets.insert(d_sock);

                    if (sock->wait_sock.size() < sock->backlog) {
                        sock->wait_sock.insert(d_sock);
                        sendFlagPacket(d_sock, TH_SYN | TH_ACK);
                    }
                    else {
                        sendFlagPacket(d_sock, TH_RST);
                        delete d_sock;
                    }
                }
                break;

            case APP_SOCKET::SYN_RCVD:
                if(hdr.tcp.ack) {
                    sock->ack_seq = ntohl(hdr.tcp.seq) + 1;
                    sock->state = APP_SOCKET::ESTABLISHED;

                    Socket *parent = sock->parent;

                    if (parent == NULL) {
                        std::cout << "Empty parent socket while SYN_RCVD" << std::endl;
                        break;
                    }
                    if (!parent->wait_sock.erase(sock)) {
                        std::cout << "The parents has no such child" << std::endl;
                        break;
                    }

                    std::unordered_map<APP_SOCKET::Socket *, syscall_cont>::iterator entry;
                    entry = syscall_blocks.find(parent);

                    if (entry != syscall_blocks.end()) {

                        UUID syscallUUID = entry->second.second;
                        int pid = entry->second.first;
                        int fd = createFileDescriptor(pid);

                        std::unordered_map<UUID, addr_ptr>::iterator accept_entry;
                        accept_entry = accept_cont.find(syscallUUID);

                        if (accept_entry == accept_cont.end()) {
                            std::cout << "No accept context." << std::endl;
                            break;
                        }

                        struct sockaddr_in *addr_in = accept_entry->second.first;
                        socklen_t *addrlen = accept_entry->second.second;

                        memset(addr_in, 0, sizeof(struct sockaddr_in));
                        addr_in->sin_port = htons(sock->addr_dest->port);
                        addr_in->sin_addr.s_addr = htonl(sock->addr_dest->addr);
                        addr_in->sin_family = AF_INET;  // Don't network ordering
                        *addrlen = sizeof(struct sockaddr_in);

                        s_id sock_id = {pid, fd};
                        app_sockets[sock_id] = sock;

                        syscall_blocks.erase(parent);
                        returnSystemCall(syscallUUID, fd);
                        break;
                    }

                    parent->est_queue.push(sock);
                }
                break;

            case APP_SOCKET::SYN_SENT:
                //recv syn_ack from server
                //send ack
                // go established

                if(hdr.tcp.syn && hdr.tcp.ack) {
                    sock->ack_seq = ntohl(hdr.tcp.seq) + 1;
                    sock->state = APP_SOCKET::ESTABLISHED;

                    std::unordered_map<APP_SOCKET::Socket *, syscall_cont>::iterator entry;
                    entry = syscall_blocks.find(sock);

                    if (entry == syscall_blocks.end()) {
                        std::cout << "SYN_SENT socket must save its context" << std::endl;
                        break;
                    }

                    sendFlagPacket(sock, TH_ACK);

                    UUID syscallUUID = entry->second.second;
                    syscall_blocks.erase(sock);

                    returnSystemCall(syscallUUID, 0);
                }
                break;
            case APP_SOCKET::ESTABLISHED:
                if(hdr.tcp.fin) {
                    sock->ack_seq = ntohl(hdr.tcp.seq) + 1;
                    sock->state = APP_SOCKET::CLOSE_WAIT;

                    sendFlagPacket(sock,TH_ACK);
                }
                break;
            case APP_SOCKET::LAST_ACK:
                if(hdr.tcp.ack){
                    sock->ack_seq = ntohl(hdr.tcp.seq)+1;
                    sock->state = APP_SOCKET::CLOSED;

                    sockets.erase(sock);
                    delete sock;
                }
                break;
            case APP_SOCKET::FIN_WAIT_1:
                if(hdr.tcp.fin){
                    sock->ack_seq = ntohl(hdr.tcp.seq)+1;
                    sock->state = APP_SOCKET::CLOSING;
                    sendFlagPacket(sock,TH_ACK);
                }
                else if(hdr.tcp.ack){
                    sock->ack_seq = ntohl(hdr.tcp.seq)+1;
                    sock->state = APP_SOCKET::FIN_WAIT_2;
                }
                break;
            case APP_SOCKET::FIN_WAIT_2:
                if(hdr.tcp.fin){
                    sock->ack_seq = ntohl(hdr.tcp.seq)+1;
                    sendFlagPacket(sock,TH_ACK);
                    sock->state = APP_SOCKET::TIME_WAIT;

                    UUID timer = addTimer(sock, 2 * MAX_SEG_LIFETIME);
                    timers[sock] = timer;
                }
                break;
            case APP_SOCKET::CLOSE_WAIT:
                if(hdr.tcp.fin) {
                    sendFlagPacket(sock,TH_ACK);
                }
                break;
            case APP_SOCKET::TIME_WAIT:
                if(hdr.tcp.fin) {
                    sendFlagPacket(sock,TH_ACK);
                }
                break;
            case APP_SOCKET::CLOSING:
                if(hdr.tcp.ack){
                    sock->ack_seq = ntohl(hdr.tcp.seq)+1;
                    sock->state = APP_SOCKET::TIME_WAIT;

                    UUID timer = addTimer(sock, 2 * MAX_SEG_LIFETIME);
                    timers[sock] = timer;
                }
                break;
            default:
                break;
        }

        freePacket(packet);
    }

    void TCPAssignment::timerCallback(void *payload) {
        std::unordered_map<APP_SOCKET::Socket *, UUID>::iterator entry;
        entry = timers.find((APP_SOCKET::Socket *) payload);

        if (entry != timers.end()) {
            cancelTimer(entry->second);
            sockets.erase((APP_SOCKET::Socket *) payload);
        }
    }

    void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type) {
        int fd = createFileDescriptor(pid);
        if (fd < 0) {
            returnSystemCall(syscallUUID, fd);
            return;
        }
        s_id sock_id = {pid, fd};

        Socket *sock = new Socket(domain, type, fd);
        // TODO socket valid check

        sockets.insert(sock);
        app_sockets[sock_id] = sock;
        returnSystemCall(syscallUUID, fd);
    }

    void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd) {

        Socket *sock = getAppSocket(pid, fd);

        if (sock == NULL) {
            errno = EBADF;
            returnSystemCall(syscallUUID, -1);
            return;
        }

        app_sockets.erase({pid, fd});
        removeFileDescriptor(pid, fd);

        switch (sock->state) {
            case APP_SOCKET::LISTEN:
                listen_sockets.erase(sock);
            case APP_SOCKET::CLOSED:
            case APP_SOCKET::SYN_RCVD:
            case APP_SOCKET::SYN_SENT:
                sockets.erase(sock);
                break;
            case APP_SOCKET::ESTABLISHED:
                sendFlagPacket(sock, TH_FIN);
                sock->state = APP_SOCKET::FIN_WAIT_1;
                break;
            case APP_SOCKET::CLOSE_WAIT:
                sendFlagPacket(sock, TH_FIN);
                sock->state = APP_SOCKET::LAST_ACK;
                break;
            default:
                break;
        }

        returnSystemCall(syscallUUID, 0);

        //if (sock != NULL) {
        //    sockets.erase(sock);
        //    if (sock->state == APP_SOCKET::LISTEN) {
        //        listen_sockets.erase(sock);
        //    }
        //}
        //delete sock;
        //returnSystemCall(syscallUUID, 0);
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
        Socket *sock = getAppSocket(pid, sockfd);
        if (sock == NULL) {
            errno = EBADF;
            returnSystemCall(syscallUUID, -1);
            return;
        }

        if (!sock->listen((unsigned int) backlog)) {
            returnSystemCall(syscallUUID, -1);
            return;
        }

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

        if (!sock->est_queue.empty()) {
            Socket *d_sock = sock->est_queue.front();
            sock->est_queue.pop();

            if (d_sock->state != APP_SOCKET::ESTABLISHED &&
                    d_sock->state != APP_SOCKET::CLOSE_WAIT) {
                std::cout << "Un-established connection is in est_queue" << std::endl;
                std::cout << d_sock->state << std::endl;
                returnSystemCall(syscallUUID, -1);
                return;
            }

            memset(addr_in, 0, sizeof(struct sockaddr_in));
            addr_in->sin_port = htons(d_sock->addr_dest->port);
            addr_in->sin_addr.s_addr = htonl(d_sock->addr_dest->addr);
            addr_in->sin_family = AF_INET;
            *addrlen = sizeof(struct sockaddr_in);

            int fd = createFileDescriptor(pid);

            s_id sock_id = {pid, fd};
            app_sockets[sock_id] = d_sock;

            returnSystemCall(syscallUUID, fd);
            return;
        }
        else {
            syscall_blocks[sock] = {pid, syscallUUID};
            accept_cont[syscallUUID] = {addr_in, addrlen};
        }

    }

    void TCPAssignment::syscall_connect(UUID syscallUUID, int pid,
                                        int sockfd, const struct sockaddr *addr,
                                        socklen_t addrlen) {

        // TODO Success, but -1 cases
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

        if (sock->state != APP_SOCKET::CLOSED) {
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

            int p_iter = 0;
            for (p_iter = 0; p_iter < PORT_ITER_MAX; p_iter++) {
                c_port = (uint16_t) ((rand() % (LOCAL_PORT_MAX + 1 - LOCAL_PORT_MIN)) + LOCAL_PORT_MIN);
                c_addr_in.sin_addr.s_addr = c_addr;
                c_addr_in.sin_port = htons(c_port);

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

        syscall_blocks[sock] = {pid, syscallUUID};

        sock->addr_dest = new Address(addr_in);
        sock->state = APP_SOCKET::SYN_SENT;

        sendFlagPacket(sock, TH_SYN);
    }

    void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr,
                                     socklen_t *addrlen)
    {
        Socket *sock = getAppSocket(pid, sockfd);

        if (sock == NULL) {
            errno = EBADF;
            returnSystemCall(syscallUUID, -1);
            return;
        }

        if(sock->addr_dest == NULL)
        {
            errno = EFAULT;
            returnSystemCall(syscallUUID , -1);
            return ;
        }

        struct sockaddr_in addr_in;
        addr_in.sin_port = htons(sock->addr_dest->port);
        addr_in.sin_addr.s_addr = htonl(sock->addr_dest->addr);
        addr_in.sin_family = AF_INET;

        memcpy(addr, &addr_in, sizeof(struct sockaddr_in));

        returnSystemCall(syscallUUID, 0);
    }
}