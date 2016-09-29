//
// Created by biscuit on 16. 9. 28.
//

#ifndef KENSV3_SOCKET_HPP
#define KENSV3_SOCKET_HPP


#include <utility>

#include <E/E_Common.hpp>
#include <netinet/in.h>


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

    class Socket
    {
    private:
        enum Status {
            CLOSED
        };

    public:
        Address *addr_src;
        Address *addr_dest;

        Status state;

        int type;
        int domain;

        Socket(int domain, int type);
        ~Socket();

        bool isBound();
        int bindAddr(sockaddr_in *addr_in);
        int fd;
    };

    typedef std::pair<int, int> s_id;
    typedef std::unordered_map<s_id, APP_SOCKET::Socket *, std::hash<s_id>> socket_map;

    APP_SOCKET::Socket *getSocketEntry (socket_map* sock_map, int pid, int fd);
    long removeSocketEntry (socket_map* sock_map, int pid, int fd);
    bool checkOverlap (socket_map* sock_map, sockaddr_in* other);

}

#endif //KENSV3_SOCKET_HPP
