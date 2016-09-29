//
// Created by biscuit on 16. 9. 28.
//

#ifndef KENSV3_SOCKET_HPP
#define KENSV3_SOCKET_HPP


#include <utility>

#include <E/E_Common.hpp>


namespace APP_SOCKET
{
    class Socket
    {
    private:
        int type;
        int domain;
    public:
        Socket(int domain, int type);
        ~Socket();

        int fd;
    };

    typedef std::pair<int, int> s_id;
    typedef std::unordered_map<s_id, APP_SOCKET::Socket *, std::hash<s_id>> socket_map;

    APP_SOCKET::Socket *getSocketEntry (socket_map* sock_map, int pid, int fd);
    long removeSocketEntry (socket_map* sock_map, int pid, int fd);
}

#endif //KENSV3_SOCKET_HPP
