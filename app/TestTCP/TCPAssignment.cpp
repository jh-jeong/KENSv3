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

#include <iostream>

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
                //this->syscall_connect(syscallUUID, pid, param.param1_int,
                //		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
                break;
            case LISTEN:
                //this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
                break;
            case ACCEPT:
                //this->syscall_accept(syscallUUID, pid, param.param1_int,
                //		static_cast<struct sockaddr*>(param.param2_ptr),
                //		static_cast<socklen_t*>(param.param3_ptr));
                break;
            case BIND:
                this->syscall_bind(syscallUUID, pid, param.param1_int,
                                   static_cast<struct sockaddr *>(param.param2_ptr),
                                   (socklen_t) param.param3_int);
                break;
            case GETSOCKNAME:
                //this->syscall_getsockname(syscallUUID, pid, param.param1_int,
                //		static_cast<struct sockaddr *>(param.param2_ptr),
                //		static_cast<socklen_t*>(param.param3_ptr));
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

    }

    void TCPAssignment::timerCallback(void *payload) {

    }

    void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type) {
        int fd = createFileDescriptor(pid);
        if (fd < 0)
            returnSystemCall(syscallUUID, fd);

        APP_SOCKET::s_id sock_id = {pid, fd};

        APP_SOCKET::Socket *sock = new APP_SOCKET::Socket(domain, type);
        // TODO socket valid check

        TCPAssignment::sock_map[sock_id] = sock;
        // std::cout << sock_map[sock_id] << std::endl;
        returnSystemCall(syscallUUID, fd);
    }

    void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd) {
        APP_SOCKET::Socket *sock = APP_SOCKET::getSocketEntry(&sock_map, pid, fd);
        // TODO sock valid check

        APP_SOCKET::removeSocketEntry(&sock_map, pid, fd);
        delete sock;

        removeFileDescriptor(pid, fd);
        returnSystemCall(syscallUUID, 0);
    }

    void TCPAssignment::syscall_bind(UUID syscallUUID, int pid,
                                     int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
        returnSystemCall(syscallUUID, 0);
    }

}
