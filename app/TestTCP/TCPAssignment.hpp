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

namespace E
{

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	virtual void timerCallback(void* payload) final;
    APP_SOCKET::socket_map sockets;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;

    virtual void syscall_socket(UUID syscallUUID, int pid, int domain, int type);
    virtual void syscall_close(UUID syscallUUID, int pid, int fd);
    virtual void syscall_bind(UUID syscallUUID, int pid,
                              int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    virtual void syscall_getsockname(UUID syscallUUID , int pid ,
                                int sockfd, struct sockaddr *addr, socklen_t * addrlen);
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
