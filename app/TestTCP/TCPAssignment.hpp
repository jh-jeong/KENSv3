/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: 근홍
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <unordered_map>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include "socket.hpp"

#include <E/E_TimerModule.hpp>

#define LOCALHOST 2130706433
#define LOCAL_PORT_MIN 32768
#define LOCAL_PORT_MAX 60999
#define PORT_ITER_MAX (LOCAL_PORT_MAX - LOCAL_PORT_MIN) * 2
#define MAX_SEG_LIFETIME 60

namespace E
{

    typedef std::pair<int, int> s_id;
    typedef std::pair<struct sockaddr_in *, socklen_t *> addr_ptr;
    typedef std::pair<void *, size_t> buf_read;
    typedef std::tuple<void *, size_t, size_t> buf_write;
    typedef std::pair<int, UUID> syscall_cont;


    class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
    {
    private:
        virtual void timerCallback(void* payload) final;
        std::unordered_map<s_id, APP_SOCKET::Socket *, std::hash<s_id>> app_sockets;
        std::set<APP_SOCKET::Socket *> sockets;
        std::set<APP_SOCKET::Socket *> listen_sockets;
        std::unordered_map<UUID, addr_ptr> accept_cont;
        std::unordered_map<UUID, buf_write> write_cont;
        std::unordered_map<UUID, buf_read> read_cont;

        std::unordered_map<APP_SOCKET::Socket *, UUID> timers;
        std::unordered_map<APP_SOCKET::Socket *, syscall_cont> syscall_blocks;


    public:
        TCPAssignment(Host* host);
        virtual void initialize();
        virtual void finalize();
        virtual ~TCPAssignment();

        APP_SOCKET::Socket *getAppSocket(int pid, int fd);
        bool checkOverlap (sockaddr_in* other);

        bool sendFlagPacket(APP_SOCKET::Socket *sock, uint8_t flag);

    protected:
        virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
        virtual void packetArrived(std::string fromModule, Packet* packet) final;

        virtual void syscall_socket(UUID syscallUUID, int pid, int domain, int type);
        virtual void syscall_close(UUID syscallUUID, int pid, int fd);
        virtual void syscall_bind(UUID syscallUUID, int pid,
                                  int sockfd, const struct sockaddr *addr, socklen_t addrlen);
        virtual void syscall_getsockname(UUID syscallUUID , int pid ,
                                         int sockfd, struct sockaddr *addr, socklen_t * addrlen);
        virtual void syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog);
        virtual void syscall_accept(UUID syscallUUID, int pid,
                                    int sockfd, struct sockaddr *addr, socklen_t *addrlen);
        virtual void syscall_connect(UUID syscallUUID, int pid,
                                     int sockfd, const struct sockaddr *addr,
                                     socklen_t addrlen);
        virtual void syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr,
                                         socklen_t *addrlen);
        virtual void syscall_read(UUID syscallUUID, int pid, int sockfd, void * payload,
                                         size_t len);
        virtual void syscall_write(UUID syscallUUID, int pid, int sockfd, void * payload,
                                         size_t len);
    };

    class TCPAssignmentProvider
    {
    private:
        TCPAssignmentProvider() {}
        ~TCPAssignmentProvider() {}
    public:
        static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
    };

}


#endif /* E_TCPASSIGNMENT_HPP_ */