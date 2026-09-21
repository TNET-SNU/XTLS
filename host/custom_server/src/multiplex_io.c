#include "multiplex_io.h"

/*---------------------------------------------------------------------------*/
int 
set_nonblock(int fd) 
{
    int flags = fcntl(fd, F_GETFL, 0);

    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int 
register_epoll_in_meta_sock(int meta_sock) 
{
    int epfd = epoll_create1(0);
    
    conn_state_t* conn = NULL;
    MEASURE("calloc of conn_state",
        conn = calloc(1, sizeof(conn_state_t));
        if (!conn) { perror("calloc"); exit(EXIT_FAILURE); }
    );

    conn->sock_fd = meta_sock;
    conn->sock_state = INIT;

    if (epfd < 0) {
        perror("epoll_create1");
        exit(EXIT_FAILURE);
    }

    struct epoll_event ev = {
        .events = EPOLLIN,
        .data.ptr = conn
    };

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, meta_sock, &ev) < 0) {
        perror("epoll_ctl: meta_sock");
        exit(EXIT_FAILURE);
    }

    return epfd;
}

int 
register_epoll_in_mig_sock(conn_state_t* conn, int epfd) 
{
    if (epfd < 0) {
        perror("invalid epfd");
        exit(EXIT_FAILURE);
    }

    struct epoll_event ev = {
        .events = EPOLLIN,
        .data.ptr = conn
    };

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, conn->sock_fd, &ev) < 0) {
        perror("epoll_ctl: mig_sock (reg epoll in)");
        exit(EXIT_FAILURE);
    }

    return epfd;
}

int 
register_epoll_out_mig_sock(conn_state_t* conn, int epfd) 
{
    if (epfd < 0) {
        perror("invalid epfd");
        exit(EXIT_FAILURE);
    }

    struct epoll_event ev = {
        .events = EPOLLOUT,
        .data.ptr = conn
    };

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, conn->sock_fd, &ev) < 0) {
        perror("epoll_ctl: mig_sock (reg epoll out)");
        exit(EXIT_FAILURE);
    }

    return epfd;
}

int 
mod_epoll_inout_mig_sock(conn_state_t* conn, int epfd) 
{
    if (epfd < 0) {
        perror("invalid epfd");
        exit(EXIT_FAILURE);
    }

    struct epoll_event ev = {
        .events = EPOLLIN | EPOLLOUT,
        .data.ptr = conn
    };

    if (epoll_ctl(epfd, EPOLL_CTL_MOD, conn->sock_fd, &ev) < 0) {
        perror("epoll_ctl: mig_sock (mod epoll out)");
        exit(EXIT_FAILURE);
    }

    return epfd;
}

int 
mod_epoll_in_mig_sock(conn_state_t* conn, int epfd) 
{
    if (epfd < 0) {
        perror("invalid epfd");
        exit(EXIT_FAILURE);
    }

    struct epoll_event ev = {
        .events = EPOLLIN,
        .data.ptr = conn
    };

    if (epoll_ctl(epfd, EPOLL_CTL_MOD, conn->sock_fd, &ev) < 0) {
        perror("epoll_ctl: mig_sock (del epoll out & mod epoll in)");
        exit(EXIT_FAILURE);
    }

    return epfd;
}

int 
mod_epoll_out_mig_sock(conn_state_t* conn, int epfd) 
{
    if (epfd < 0) {
        perror("invalid epfd");
        exit(EXIT_FAILURE);
    }

    struct epoll_event ev = {
        .events = EPOLLOUT,
        .data.ptr = conn
    };

    if (epoll_ctl(epfd, EPOLL_CTL_MOD, conn->sock_fd, &ev) < 0) {
        perror("epoll_ctl: mig_sock (del epoll out & mod epoll in)");
        exit(EXIT_FAILURE);
    }

    return epfd;
}

int 
remove_epoll_mig_sock(conn_state_t* conn, int epfd) 
{
    if (epfd < 0) {
        perror("invalid epfd");
        exit(EXIT_FAILURE);
    }

    if (epoll_ctl(epfd, EPOLL_CTL_DEL, conn->sock_fd, NULL) < 0) {
        perror("epoll_ctl: mig_sock (rm epoll out)");
        exit(EXIT_FAILURE);
    }

    return epfd;
}
/*---------------------------------------------------------------------------*/
