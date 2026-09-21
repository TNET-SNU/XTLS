#pragma once

#include <stdlib.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <stdio.h>

#include "option.h"
#include "common.h"
/*---------------------------------------------------------------------------*/
typedef struct conn_state conn_state_t;

int 
set_nonblock(int fd);

int
register_epoll_in_meta_sock(int meta_sock);

int 
register_epoll_in_mig_sock(conn_state_t* conn, int epfd);

int 
register_epoll_out_mig_sock(conn_state_t* conn, int epfd);

int 
mod_epoll_inout_mig_sock(conn_state_t* conn, int epfd);

int 
mod_epoll_in_mig_sock(conn_state_t* conn, int epfd);

int 
mod_epoll_out_mig_sock(conn_state_t* conn, int epfd);

int 
remove_epoll_mig_sock(conn_state_t* conn, int epfd);
