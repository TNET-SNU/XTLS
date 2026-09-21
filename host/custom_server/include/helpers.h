#pragma once

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif /* _LARGEFILE64_SOURCE */

#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
/*---------------------------------------------------------------------------*/
typedef struct file_cache {
  char name[NAME_LIMIT];
  char fullname[FULL_PATH_LIMIT];
  uint64_t size;
  char *file;
  int fd;
} file_cache_t;
/*---------------------------------------------------------------------------*/
char *scode_2_str(int scode);

int find_http_header(char *data, int len);

void http_get_url(char *data, int data_len, char *value, int value_len);

void hexdump(const void *ptr, size_t size);

void print_hex_array(const char *label, const uint8_t *data, size_t size);

void load_file_cache(DIR *dir, const char *dir_path, file_cache_t *fcache,
                     int *nfiles);

struct sock_fprog bpf_filter_for_meta(thread_ctx_t *ctx);

void reset_conn_for_next_req(conn_state_t *conn);
