#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <netinet/tcp.h>

#include "option.h"
#include "common.h"
#include "mempool.h"
#include "set_sock.h"
#include "fhash.h"
/*---------------------------------------------------------------------------*/
/* Recv */
int
validate_meta_type(uint8_t* meta_buf, 
                   ssize_t buf_len);

int 
handle_meta_packet(thread_ctx_t* ctx,
                   uint8_t* meta_buf, 
                   ssize_t buf_len);

int
handle_key_packet(thread_ctx_t* ctx, 
                  uint8_t* meta_buf, 
                  ssize_t buf_len);

int
handle_rst_conn_packet(thread_ctx_t* ctx, 
                       uint8_t* meta_buf, 
                       ssize_t buf_len);

int
handle_unterminated_conn(thread_ctx_t* ctx, 
                         uint8_t* meta_buf, 
                         ssize_t buf_len);
/*---------------------------------------------------------------------------*/
/* Send */
int 
send_mig_fin_to_arm(int meta_sock, conn_state_t* conn);

int 
send_close_to_arm(int meta_sock, conn_state_t* conn);
