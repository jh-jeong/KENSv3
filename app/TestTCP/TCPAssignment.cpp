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

    bool TCPAssignment::sendFlagPacket(APP_SOCKET::Socket *sock, uint8_t flag, bool retransmit = false)
    {
        size_t data_len = sock->buf_send->size();

        char payload[MSS + sizeof(struct PROTOCOL::kens_hdr)] = {0};

        if ((flag & (TH_SYN | TH_FIN)) || data_len == 0) {
            size_t p_size = sock->packetSize();
            if (!sock->getPacket(payload, flag, 0))
                return false;
            Packet *packet = allocatePacket(p_size);
            packet->writeData(0, payload, p_size);
            if (flag & (TH_SYN | TH_FIN)) {
                sock->send_seq++;
            }
            this->sendPacket("IPv4", packet);
        }
        else {
            size_t not_acked = sock->send_seq - sock->send_base;
            size_t not_sent = data_len - not_acked;

            size_t offset = retransmit ? 0 : not_acked;
            while (not_sent > 0) {
                size_t c_size = std::min(not_sent, (size_t) MSS);
                size_t p_size = c_size + sizeof(struct PROTOCOL::kens_hdr);

                if (not_acked + c_size > std::max((uint32_t) MSS,
                                                  std::min(sock->cwnd,
                                                           (uint32_t) sock->rwnd)))
                    break;

                if (!sock->getPacket(payload, flag, offset))
                    return false;
                Packet *packet = allocatePacket(p_size);
                packet->writeData(0, payload, p_size);
                this->sendPacket("IPv4", packet);

                sock->send_seq += c_size;
                not_acked = sock->send_seq - sock->send_base;
                offset += c_size;
                not_sent -= c_size;
            };

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
                this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
                break;
            case WRITE:
                this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
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

        uint32_t bytes_ack = 0;
        bool is_dupACK = false;
        if (hdr.tcp.ack) {
            uint32_t ack_num = ntohl(hdr.tcp.ack_seq);
            if (ack_num > sock->send_base) {
                bytes_ack = ack_num - sock->send_base;
                sock->send_base = ack_num;

                u_int16_t rwnd = ntohs(hdr.tcp.th_win);
                sock->rwnd = rwnd;
            }
            else if (ack_num == sock->send_base)
                is_dupACK = true;
        }

        char data[MSS] = {0};
        size_t len_data = 0;
        len_data = packet->readData(sizeof (struct PROTOCOL::kens_hdr),
                                    data, MSS);

        switch (sock->state) {
            case APP_SOCKET::LISTEN:
                //recv syn packet
                //send syn ack

                if (hdr.tcp.syn) {
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
                if (hdr.tcp.ack) {
                    sock->state = APP_SOCKET::ESTABLISHED;

                    // TODO initial data?

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

                if (hdr.tcp.syn && hdr.tcp.ack) {
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
                if (hdr.tcp.fin) {
                    sock->ack_seq = ntohl(hdr.tcp.seq) + 1;
                    sock->state = APP_SOCKET::CLOSE_WAIT;

                    sendFlagPacket(sock, TH_ACK);
                    break;
                }

                if (hdr.tcp.ack) {
                    sock->buf_send->pop(bytes_ack);
                    std::unordered_map<APP_SOCKET::Socket *, syscall_cont>::iterator entry;
                    entry = syscall_blocks.find(sock);

                    if (entry != syscall_blocks.end()) {
                        UUID syscallUUID = entry->second.second;
                        std::unordered_map<UUID, buf_write>::iterator entry_w;
                        entry_w = write_cont.find(syscallUUID);
                        if (entry_w != write_cont.end()) {
                            char *payload = (char *) std::get<0>(entry_w->second);
                            size_t len = std::get<1>(entry_w->second);
                            size_t bytes_prev = std::get<2>(entry_w->second);

                            size_t bytes_write = sock->buf_send->write(payload, len);

                            payload += bytes_write;
                            len -= bytes_write;

                            write_cont.erase(syscallUUID);

                            size_t bytes_total = bytes_prev + bytes_write;
                            if (len > 0)
                                write_cont[syscallUUID] = buf_write(payload, len, bytes_write);
                            else {
                                syscall_blocks.erase(sock);
                                returnSystemCall(syscallUUID, bytes_total);
                            }
                        }
                    }

                    uint32_t seq = ntohl(hdr.tcp.seq);
                    if (sock->ack_seq > seq)
                        break;
                    if (sock->ack_seq < seq) {
                        if (!sock->buf_recv->regCache(seq, data, len_data))
                            break;
                    }

                    if (!sock->buf_recv->write(data, len_data))
                        break;
                    sock->ack_seq += len_data;

                    while (1) {
                        uint32_t ack_next = sock->buf_recv->moveCache(sock->ack_seq);
                        if (sock->ack_seq == ack_next)
                            break;
                        else sock->ack_seq = ack_next;
                    }

                    if (entry != syscall_blocks.end()) {
                        UUID syscallUUID = entry->second.second;
                        std::unordered_map<UUID, buf_read>::iterator entry_r;
                        entry_r = read_cont.find(syscallUUID);
                        if (entry_r != read_cont.end()) {
                            char *payload = (char *) entry_r->second.first;
                            size_t len = entry_r->second.second;

                            size_t bytes_read = sock->buf_recv->read(payload, len);
                            read_cont.erase(syscallUUID);
                            syscall_blocks.erase(sock);
                            returnSystemCall(syscallUUID, bytes_read);
                        }
                    }

                    // Congestion control
                    switch (sock->cong_state) {
                        case APP_SOCKET::SLOW_START:
                            if (is_dupACK)
                                sock->dupACKcount++;
                            if (sock->dupACKcount == 3) {
                                sock->sstresh = sock->cwnd / 2;
                                sock->cwnd = sock->sstresh + 3;
                                sock->cong_state = APP_SOCKET::FAST_RECOVERY;
                                break;
                            }
                            if (bytes_ack > 0) {
                                sock->cwnd += MSS;
                                sock->dupACKcount = 0;
                            }
                            if (sock->cwnd >= sock->sstresh)
                                sock->cong_state = APP_SOCKET::CONGESTION_AVOIDANCE;
                            break;
                        case APP_SOCKET::CONGESTION_AVOIDANCE:
                            if (is_dupACK)
                                sock->dupACKcount++;
                            if (sock->dupACKcount == 3) {
                                sock->sstresh = sock->cwnd / 2;
                                sock->cwnd = sock->sstresh + 3;
                                sock->cong_state = APP_SOCKET::FAST_RECOVERY;
                                break;
                            }
                            if (bytes_ack > 0) {
                                sock->cwnd += MSS * (MSS / (1.0 * sock->cwnd));
                                sock->dupACKcount = 0;
                            }
                            break;
                        case APP_SOCKET::FAST_RECOVERY:
                            if (is_dupACK)
                                sock->cwnd += MSS;
                            if (bytes_ack > 0) {
                                sock->cwnd = sock->sstresh;
                                sock->dupACKcount = 0;
                                sock->cong_state = APP_SOCKET::CONGESTION_AVOIDANCE;
                                break;
                            }
                            break;
                        default:
                            break;
                    }

                    sendFlagPacket(sock, TH_ACK);
                }
                break;
            case APP_SOCKET::LAST_ACK:
                if (hdr.tcp.ack) {
                    sock->ack_seq = ntohl(hdr.tcp.seq)+1;
                    sock->state = APP_SOCKET::CLOSED;

                    sockets.erase(sock);
                    delete sock;
                }
                break;
            case APP_SOCKET::FIN_WAIT_1:
                if (hdr.tcp.fin) {
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
                if (hdr.tcp.fin) {
                    sock->ack_seq = ntohl(hdr.tcp.seq)+1;
                    sendFlagPacket(sock,TH_ACK);
                    sock->state = APP_SOCKET::TIME_WAIT;

                    UUID timer = addTimer(sock, 2 * MAX_SEG_LIFETIME);
                    timers[sock] = timer;
                }
                break;
            case APP_SOCKET::CLOSE_WAIT:
                if (hdr.tcp.fin) {
                    sendFlagPacket(sock,TH_ACK);
                }
                break;
            case APP_SOCKET::TIME_WAIT:
                if (hdr.tcp.fin) {
                    sendFlagPacket(sock,TH_ACK);
                }
                break;
            case APP_SOCKET::CLOSING:
                if (hdr.tcp.ack) {
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


    void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int sockfd, void *payload,
                                     size_t len)
    {
        Socket *sock = getAppSocket(pid, sockfd);

        if (sock == NULL) {
            errno = EBADF;
            returnSystemCall(syscallUUID, -1);
            return;
        }

        if (len == 0) {
            returnSystemCall(syscallUUID, 0);
            return;
        }

        if(sock->buf_recv->size()) {
            size_t bytes_read = sock->buf_recv->read((char *) payload, len);
            returnSystemCall(syscallUUID, bytes_read);
        }
        else {
            syscall_blocks[sock] = {pid, syscallUUID};
            read_cont[syscallUUID] = {payload, len};
        }
    }

    void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int sockfd, void *payload,
                                      size_t len)
    {
        Socket *sock = getAppSocket(pid, sockfd);
        char *buf = (char *) payload;

        if (sock == NULL) {
            errno = EBADF;
            returnSystemCall(syscallUUID, -1);
            return;
        }

        if (sock->state == APP_SOCKET::CLOSED) {
            errno = EPIPE;
            returnSystemCall(syscallUUID, -1);
            return;
        }

        if(sock->addr_dest == NULL)
        {
            errno = EDESTADDRREQ;
            returnSystemCall(syscallUUID , -1);
            return;
        }

        if (len == 0) {
            returnSystemCall(syscallUUID, 0);
            return;
        }

        size_t bytes_write = sock->buf_send->write(buf, len);

        buf += bytes_write;
        len -= bytes_write;

        // TODO Always ACK?
        if (bytes_write > 0)
            sendFlagPacket(sock, TH_ACK);

        if (len > 0) {
            syscall_blocks[sock] = {pid, syscallUUID};
            write_cont[syscallUUID] = buf_write(buf, len, bytes_write);
        }
        else {
            returnSystemCall(syscallUUID, bytes_write);
        }
        return;
    }
}
