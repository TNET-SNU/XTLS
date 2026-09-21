#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/version.h>
#include <errno.h>

#include "option.h"
#include "common.h"
#include "helpers.h"
#include "multiplex_io.h"
#include "fhash.h"
/*---------------------------------------------------------------------------*/
int
setup_meta_sock(thread_ctx_t* ctx);

int 
set_mig_sock(meta_info_t* meta_info);

int 
mig_tcp_conn(conn_state_t* conn, int epfd);

int 
mig_tls_conn(conn_state_t* conn);

void 
close_tcp_conn(thread_ctx_t* ctx, struct conn_state *conn);
