//
// Created by biscuit on 16. 9. 28.
//

#include "socket.hpp"

namespace APP_SOCKET
{
    Socket::Socket(int domain, int type)
    {
        // TODO type validation
        this->domain = domain;
        this->type = type;
    }

    Socket::~Socket() {

    }

    Socket *getSocketEntry (APP_SOCKET::socket_map *sock_map,
                                        int pid, int fd) {
        APP_SOCKET::Socket *sock;
        APP_SOCKET::s_id sock_id = {pid, fd};
        sock = sock_map->find(sock_id)->second;
        return sock;
    }

    long removeSocketEntry (APP_SOCKET::socket_map *sock_map,
                                        int pid, int fd) {
        s_id sock_id = {pid, fd};
        return sock_map->erase(sock_id);
    }
}
