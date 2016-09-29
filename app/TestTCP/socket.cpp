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

    Socket *getSocketEntry (APP_SOCKET::socket_map *sock_map,
                                        int pid, int fd) {
        APP_SOCKET::Socket *sock;
        APP_SOCKET::s_id sock_id = {pid, fd};
        sock = sock_map->find(sock_id)->second;
        return sock;
    }

    int Socket::bindAddr(sockaddr_in *addr_in) {
        if (this->state != CLOSED)
            return -1;
        this->addr_src = new APP_SOCKET::Address(addr_in);
        return 0;
    }

    long removeSocketEntry (APP_SOCKET::socket_map *sock_map,
                                        int pid, int fd) {
        s_id sock_id = {pid, fd};
        return sock_map->erase(sock_id);
    }

    bool checkOverlap(APP_SOCKET::socket_map *sock_map,
                      sockaddr_in *other) {

        for(auto it = sock_map->begin(); it != sock_map->end() ; ++it )
        {
            Socket *sock = it->second;
            if (!sock->isBound())
                continue;
            if ((*sock->addr_src) == APP_SOCKET::Address(other))
                return true; //overlap
        }
        return false;
    }
}
