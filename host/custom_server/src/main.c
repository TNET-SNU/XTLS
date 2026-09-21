#define _GNU_SOURCE

#include <errno.h>
#include <linux/version.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sendfile.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "option.h"

#include "fhash.h"
#include "helpers.h"
#include "mempool.h"
#include "meta_pkt.h"
#include "multiplex_io.h"
#include "set_sock.h"
/*---------------------------------------------------------------------------*/
/* Global Variables */
int tls13 = 0;
int thread_num = 1;
thread_ctx_t *ctx_array[MAX_THREAD_NUM] = {NULL};

#if EVALUATION
struct timespec start_ts;
struct timespec cur_ts, prev_ts;
uint64_t duration = 0;
uint64_t key_metas[MAX_THREAD_NUM] = {0};
uint64_t new_conns[MAX_THREAD_NUM] = {0};
uint64_t unterminated_conns[MAX_THREAD_NUM] = {0};
uint64_t closed_conns[MAX_THREAD_NUM] = {0};
uint64_t total_conns = 0;
uint64_t total_conns_after_warmup = 0;
uint64_t total_cps = 0;
uint64_t total_unterminated_conns = 0;
struct timespec total_conn_time = {0, 0};
#endif /* EVALUATION */

#if DEBUG
int nic_unterminated_conn = 0;
int sent_close_meta = 0;
#endif /* DEBUG */
/*---------------------------------------------------------------------------*/
/////////////////////////////// for control flow //////////////////////////////
int handle_received_pkt(int sock, struct conn_state *conn,
                        struct file_cache *fcache, int nfiles,
                        const char *www_main) {
  char data_buf[HTTP_HEADER_LEN];
  char ctrl_buf[128];

  struct iovec iov = {.iov_base = data_buf, .iov_len = sizeof(data_buf)};

  struct msghdr msg = {.msg_name = NULL,
                       .msg_namelen = 0,
                       .msg_iov = &iov,
                       .msg_iovlen = 1,
                       .msg_control = ctrl_buf,
                       .msg_controllen = sizeof(ctrl_buf),
                       .msg_flags = 0};

  ssize_t received = recvmsg(sock, &msg, 0);

  conn->recv_bytes += received;

  if (received < 0) {
    // perror("recvmsg http req");
    // fprintf(stderr, "client port: %u\n", htons(conn->meta_info.client_port));
    if (errno == EAGAIN || errno == EWOULDBLOCK)
      return RECV_CONTINUE;
    if (errno == EPIPE || errno == ECONNRESET)
      return RECV_ERR;

    return RECV_ERR;
  }

  if (received == 0)
    return RECV_FIN;

  struct cmsghdr *cmsg;

  for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
       cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level == SOL_TLS && cmsg->cmsg_type == TLS_GET_RECORD_TYPE) {
      uint8_t record_type = *CMSG_DATA(cmsg);
      if (unlikely(record_type == 0x15)) { /* 0x15: TLS Record Type - Alert */
        if (received == 2 && data_buf[0] == 0x01 &&
            data_buf[1] == 0x00) { /* level=1, desc=0: close_notify */
          PRINT_CUR_TIME("TLS close_notify received");

          return RECV_CLOSE_NOTIFY;
        }
        fprintf(stderr, "Received TLS Alert from client (UB)\n");
      }
      if (unlikely(record_type == 0x16 ||
                   record_type ==
                       0x14)) { /* 0x16: Handshake, 0x14: Change Cipher Spec */
        return RECV_TLS;
      }
    }
  }

  ssize_t space_left = sizeof(conn->req_buf) - conn->req_len - 1;
  if (received > space_left) {
    conn->scode = 414;
    return RECV_OK;
  }

  memcpy(conn->req_buf + conn->req_len, data_buf, received);
  conn->req_len += received;
  conn->req_buf[conn->req_len] = '\0'; /* for using strstr() */

  /* Find \n\n or \r\n\r\n: end of the HTTP header */
  int hdr_len = find_http_header(conn->req_buf, conn->req_len);

  /* We need to receive rest of the HTTP header */
  if (hdr_len <= 0)
    return RECV_CONTINUE;

  conn->keep_alive = 1;
  if (strstr(conn->req_buf, "connection: close"))
    conn->keep_alive = 0;

#if VERBOSE_HTTPS
  printf("\n[Received HTTPS Request]\n");

  printf("HTTPS request received successfully.\n");
#endif /* VERBOSE_HTTPS */

#if VERBOSE_SSL
  hexdump(recv_buf, received);
#endif /* VERBOSE_SSL */

  /* Receive HTTPS request from client. Let's parse HTTP request */
  char url[URL_LEN];
  char req_fname[NAME_LIMIT];

  http_get_url(conn->req_buf, hdr_len, url, URL_LEN);
  int path_len = snprintf(req_fname, NAME_LIMIT, "%s%s", www_main, url);

  /* Find file in cache */
  int scode = 404;
  if (path_len >= NAME_LIMIT) {
    scode = 414;
  } else {
    for (int i = 0; i < nfiles; i++) {
      if (strcmp(req_fname, fcache[i].fullname) == 0) {
        scode = 200;
        conn->file_idx = i;
        conn->file_size = fcache[i].size;
        break;
      }
    }
  }

  conn->scode = scode;

  return RECV_OK;
}

void init_send_state(conn_state_t *conn) {
  conn->hdr_sent = 0;
  conn->hdr_offset = 0;
  conn->hdr_remain = conn->hdr_len;

  conn->resp_fd = -1;
  conn->resp_offset = 0;
  conn->resp_remain = 0;
}

int send_server_records(struct conn_state *conn) {
  ssize_t sent = send(conn->sock_fd, conn->sccs_sf_buf, conn->record_len, 0);

  if (sent < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
      return 0;

    perror("send: sending server records");
    return -1;
  }

  return 1;
}

int send_https_header(int sock, struct conn_state *conn) {
  if (!(conn->hdr_sent)) {
    if (conn->hdr_len == 0) {
      struct timespec t_now;
      char t_str[128];

      /* HTTP/1.1 Response header */
      clock_gettime(CLOCK_REALTIME, &t_now);
      strftime(t_str, 128, "%a, %d %b %Y %X GMT", gmtime(&t_now.tv_sec));

      int hdr_len = snprintf(conn->hdr_buf, sizeof(conn->hdr_buf),
                             "HTTP/1.1 %d %s\r\n"
                             "Date: %s\r\n"
                             "Server: Webserver of seongjong\r\n"
                             "Content-Length: %zu\r\n"
                             "connection: %s\r\n"
                             "\r\n",
                             conn->scode, scode_2_str(conn->scode), t_str,
                             conn->file_size,
                             (conn->keep_alive) ? "keep-alive" : "close");

      if (hdr_len < 0 || hdr_len >= (int)sizeof(conn->hdr_buf)) {
        fprintf(stderr, "truncated HTTP header or strange hdr len (-)\n");

        return -1;
      }

      conn->hdr_len = (size_t)hdr_len;
      conn->hdr_offset = 0;
      conn->hdr_remain = conn->hdr_len;
    }

    ssize_t sent = send(sock, conn->hdr_buf + conn->hdr_offset,
                        conn->hdr_remain, MSG_MORE);

    if (sent < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return 0;

      perror("send");
      return -1;
    }

    conn->hdr_remain -= (size_t)sent;
    conn->hdr_offset += (size_t)sent;

    if (conn->hdr_remain <= 0)
      conn->hdr_sent = 1;
    else
      return 0;

#if VERBOSE_HTTPS
    printf("Sent HTTP response successfully (%zd bytes).\n", sent);
    hexdump(conn->hdr_buf + (conn->hdr_offset - sent), sent);
#endif /* VERBOSE_HTTPS */
  }

  return 1;
}

int send_file_content(int sock, struct conn_state *conn,
                      struct file_cache *fcache) {
  PRINT_CUR_TIME("Send file content");
  if (conn->scode == 200) {
    if (conn->resp_remain == 0) {
      conn->resp_offset = 0;
      conn->resp_remain = fcache[conn->file_idx].size;
    }

    if (conn->resp_remain > 0) {
      ssize_t fsize = fcache[conn->file_idx].size;
      if (fsize > FILE_SIZE_THRESHOLD) {
        // UNUSED(fsize);
        // if (0) {
        if (conn->resp_fd < 0) {
          conn->resp_fd = fcache[conn->file_idx].fd;
          if (conn->resp_fd < 0) {
            perror("cached fd missing");
            return -1;
          }
        }

        while (conn->resp_remain > 0) {
          ssize_t sent = sendfile(sock, conn->resp_fd, &conn->resp_offset,
                                  conn->resp_remain);

          if (sent > 0) {
            conn->resp_remain -= sent;
          } else if (sent == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
              return 0;
            perror("sendfile: sending large file");
            return -1;
          }
        }
      } else {
        // const char *base = fcache[conn->file_idx].file;
        // const char *p = base + conn->resp_offset;
        // size_t to_send = conn->resp_remain;

        ssize_t sent =
            send(sock, fcache[conn->file_idx].file + conn->resp_offset,
                 conn->resp_remain, 0);

        if (sent > 0) {
          conn->resp_remain -= sent;
          conn->resp_offset += sent;
        } else if (sent == -1) {
          if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return 0;
          if (errno == ECONNRESET || errno == EPIPE)
            return -1;
          else {
            fprintf(stderr, "NEW errno %d: %s (symbol name: %s)\n", errno,
                    strerror(errno), strerrorname_np(errno));
            perror("sendfile: sending small file");
            return -1;
          }
        }
      }
    }
  }

  // init_send_state(conn);

  return 1;
}

int handle_persist_conn_after_resp_sent(int sock, struct conn_state *conn) {
  int cork = 0;
  setsockopt(conn->sock_fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));

  cork = 1;
  setsockopt(conn->sock_fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));

  reset_conn_for_next_req(conn);

  return 1;
}

int handle_ephe_conn_after_resp_sent(int sock, struct conn_state *conn) {
  uint8_t alert[2] = {
      0x01, // Alert Level: warning
      0x00  // Alert Description: close_notify
  };

  struct msghdr msg = {0};
  struct cmsghdr *cmsg;
  char ctrl[CMSG_SPACE(sizeof(uint8_t))] = {0};

  struct iovec iov = {.iov_base = alert, .iov_len = sizeof(alert)};

  msg.msg_control = ctrl;
  msg.msg_controllen = sizeof(ctrl);
  cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_TLS;
  cmsg->cmsg_type = TLS_SET_RECORD_TYPE;
  cmsg->cmsg_len = CMSG_LEN(sizeof(uint8_t));
  *CMSG_DATA(cmsg) = 0x15; // TODO: kernel version > 5.19, net/tls_prot.h
                           // defines TLS_RECORD_TYPE_ALERT
  msg.msg_controllen = sizeof(ctrl);

  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  int ret = sendmsg(sock, &msg, 0);
  if (ret < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
      return 0;
    if (errno == EPIPE || errno == ECONNRESET)
      return -1;
    else {
      fprintf(stderr, "NEW errno %d: %s (symbol name: %s)\n", errno,
              strerror(errno), strerrorname_np(errno));

      return -1;
    }

    perror("sendmsg (close_notify)");
  }

  // Unset TCP_CORK to flush the data (for sync w/ host close packet)
  int cork = 0;
  setsockopt(sock, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));

  return 1;
}

int send_https_resp(int sock, struct conn_state *conn,
                    struct file_cache *fcache, int nfiles, int epfd,
                    int meta_sock) {
  int ret = send_https_header(sock, conn);
  if (ret != 1)
    return ret;

  /* Send file content */
  if (conn->hdr_sent) {
    ret = send_file_content(sock, conn, fcache);

    if (ret != 1)
      return ret;

    if (conn->resp_remain <= 0) {
      PRINT_CUR_TIME("Send file content done");

      // close(conn->resp_fd);
      conn->resp_fd = -1;

      if (!(conn->keep_alive)) {
        ret = handle_ephe_conn_after_resp_sent(sock, conn);

        if (ret != 1)
          return ret;
      } else
        ret = handle_persist_conn_after_resp_sent(sock, conn);

      if (ret != 1)
        return ret;
    }
  }

  return 0;
}
/*----------------------------------------------------------------------------*/
void thread_local_init(thread_args_t *thread_args) {
  int thread_id = thread_args->core_id;

  thread_ctx_t *ctx = calloc(1, sizeof(thread_ctx_t));
  if (!ctx) {
    fprintf(stderr, "Failed to allocate thread context for thread %d\n",
            thread_id);
    exit(EXIT_FAILURE);
  }

  ctx->core_id = thread_id;

  ctx->dir = opendir(thread_args->www_main);
  if (!ctx->dir) {
    TRACE_CONFIG("Failed to open %s.\n", thread_args->www_main);
    perror("opendir");
    exit(EXIT_FAILURE);
  }

  ctx_array[thread_id] = ctx;
}

void print_stat(thread_ctx_t *ctx) {
  if (ctx->core_id != 0)
    return;

#if EVALUATION
  clock_gettime(CLOCK_MONOTONIC, &cur_ts);

  if (unlikely(cur_ts.tv_sec > prev_ts.tv_sec)) {
    long elapsed = cur_ts.tv_sec - start_ts.tv_sec;

    total_cps = 0;
    total_unterminated_conns = 0;

    for (int i = 0; i < thread_num; i++) {
      unterminated_conns[i] += new_conns[i];
      unterminated_conns[i] -= closed_conns[i];

      total_conns += new_conns[i];
      total_cps += new_conns[i];
      total_unterminated_conns += unterminated_conns[i];
    }

    if (likely(elapsed >= WARM_UP_SEC)) {
      duration++;

      for (int i = 0; i < thread_num; i++) {
        total_conns_after_warmup += new_conns[i];
      }

      fprintf(stderr, "==================================\n");
      for (int i = 0; i < thread_num; i++) {
        fprintf(stderr, "[Thread %d]: ", i);
        fprintf(stderr, "%ld\n", new_conns[i]);
      }

      fprintf(stderr, "[TOTAL CPS]:  ");
      fprintf(stderr, "%ld conn/sec\n", total_cps);
      double avg_conn_sec = (double)total_conns_after_warmup / (double)duration;
      fprintf(stderr, "[AVG TOTAL CPS]: %.2f conn/sec\n", avg_conn_sec);
      fprintf(stderr, "----------------------------------\n");
      fprintf(stderr, "[ACTIVE CONNS]: %ld\n", total_unterminated_conns);
      fprintf(stderr, "[TOTAL CONNS]: %ld\n", total_conns);
    } else {
      fprintf(stderr, "Warm-up… (%lds left)\n", WARM_UP_SEC - elapsed);
    }

    for (int i = 0; i < thread_num; i++) {
      new_conns[i] = 0;
      closed_conns[i] = 0;
    }

    prev_ts = cur_ts;

#if DEBUG
    if (total_conns > 0) {
      fprintf(stderr, "Avg connection time: %.2f msec\n",
              ((double)total_conn_time.tv_sec / total_conns * 1e9 +
               (double)total_conn_time.tv_nsec / total_conns) /
                  1e6);
    }

    fprintf(stderr, "Total NIC-side unterminated conns: %d\n",
            nic_unterminated_conn);
    fprintf(stderr, "Total sent close meta packets: %d\n", sent_close_meta);
#endif /* DEBUG */
#endif /* EVALUATION */
  }
}

void *worker_thread(void *arg) {
  thread_args_t *thread_args = (thread_args_t *)arg;
  const char *www_main = thread_args->www_main;
  thread_local_init(thread_args);

  int nfiles = 0;
  struct file_cache fcache[MAX_FILES];
  thread_ctx_t *ctx = ctx_array[thread_args->core_id];

  load_file_cache(ctx->dir, www_main, fcache, &nfiles);

  conn_pool_init(ctx->core_id);

  ctx->ht_conn = create_ht(NUM_BINS);

  /* main loop */
  ctx->meta_sock = setup_meta_sock(ctx);

  if (ctx->meta_sock < 0) {
    fprintf(stderr, "Failed to set up meta socket\n");
    exit(EXIT_FAILURE);
  }

  if (set_nonblock(ctx->meta_sock) < 0) {
    perror("set_nonblock");
    close(ctx->meta_sock);
    exit(EXIT_FAILURE);
  }

  ctx->epfd = register_epoll_in_meta_sock(ctx->meta_sock);
  uint8_t meta_buf[RECV_META_BUF_SIZE];
  struct epoll_event events[MAX_CONN + 1]; // meta_sock + mig_socks

  clock_gettime(CLOCK_MONOTONIC, &start_ts);

  while (1) {
    int nfds = epoll_wait(ctx->epfd, events, MAX_CONN + 1, 1000);
    if (nfds < 0) {
      perror("epoll_wait");
      continue;
    }

    for (int i = 0; i < nfds; ++i) {
      // TODO: remove fd & meta & etc. (access via conn) &
      int fd = ((conn_state_t *)events[i].data.ptr)->sock_fd;
      conn_state_t *conn = (conn_state_t *)events[i].data.ptr;

      /* Processing meta packet */
      if (fd == ctx->meta_sock) {
        PRINT_CUR_TIME("ARM Meta Packet Received");

        if (handle_meta_packet(ctx, meta_buf, sizeof(meta_buf)) < 0)
          continue;
      }

      /* TLS migration after TCP migration */
      else if ((events[i].events & EPOLLOUT) && conn->sock_state == INIT) {
        PRINT_CUR_TIME("Mig TLS Start");
        if (mig_tls_conn(conn) < 0) {
          fprintf(stderr, "Failed to migrate TLS connection\n");
          continue;
        }
        PRINT_CUR_TIME("Mig TLS End");

#if VERBOSE_TCP
        printf(
            "Connected with client %u.%u.%u.%u:%u\n",
            (((struct conn_state *)events[i].data.ptr)->meta_info.client_ip >>
             24) &
                0xFF,
            (((struct conn_state *)events[i].data.ptr)->meta_info.client_ip >>
             16) &
                0xFF,
            (((struct conn_state *)events[i].data.ptr)->meta_info.client_ip >>
             8) &
                0xFF,
            (((struct conn_state *)events[i].data.ptr)->meta_info.client_ip) &
                0xFF,
            (((struct conn_state *)events[i].data.ptr)->meta_info.client_port));
#endif /* VERBOSE_TCP */

        conn->sock_state = CONNECTED;

#if EVALUATION
        new_conns[ctx->core_id]++;
#endif /* EVALUATION */
      }

      /* Send mig FIN pkt to ARM */
      else if ((events[i].events & EPOLLOUT) && conn->sock_state == CONNECTED) {
        if (send_mig_fin_to_arm(ctx->meta_sock, conn) < 0) {
          fprintf(stderr, "Failed to send ACK to ARM\n");
          continue;
        }
        mod_epoll_in_mig_sock(conn, ctx->epfd);

        conn->sock_state = READY_TO_RECV;
      }

      /* Recv HTTPS req */
      else if ((events[i].events & EPOLLIN) &&
               conn->sock_state == READY_TO_RECV) {
        int ret = handle_received_pkt(fd, conn, fcache, nfiles, www_main);

        switch (ret) {
        case RECV_OK:
          mod_epoll_inout_mig_sock(conn, ctx->epfd);
          conn->sock_state = HTTP_REQ_RECVED;
          break;
        case RECV_CLOSE_NOTIFY:
          mod_epoll_inout_mig_sock(conn, ctx->epfd);
          conn->sock_state = WAIT_TCP_FIN;
          break;
        case RECV_TLS:
          mod_epoll_out_mig_sock(conn, ctx->epfd);
          conn->sock_state = TLS_HS_RECVED;
          break;
        case RECV_FIN:
          fprintf(stderr, "Receive Client FIN\n");
          mod_epoll_out_mig_sock(conn, ctx->epfd);
          conn->sock_state = ERRORED;
          break;
        case RECV_ERR:
          mod_epoll_out_mig_sock(conn, ctx->epfd);
          conn->sock_state = ERRORED;
          break;
        case RECV_CONTINUE:
          // Do nothing, wait for more data
          break;
        default:
          // Should not reach here
          fprintf(stderr, "Unknown return value from handle_received_pkt: %d\n",
                  ret);
          break;
        }
      }

      /* Send HTTPS resp */
      else if ((events[i].events & EPOLLOUT) &&
               conn->sock_state == HTTP_REQ_RECVED) {
        if (send_https_resp(fd, conn, fcache, nfiles, ctx->epfd,
                            ctx->meta_sock) < 0) {
          fprintf(stderr, "Failed to send HTTPS response\n");
          conn->sock_state = ERRORED;
          continue;
        }

        if (conn->resp_remain <= 0) {
          switch (conn->keep_alive) {
          case 0:
            mod_epoll_in_mig_sock(conn, ctx->epfd);
            conn->sock_state = READY_TO_RECV;
            break;
          case 1:
            mod_epoll_in_mig_sock(conn, ctx->epfd);
            conn->sock_state = READY_TO_RECV;
            break;
          }
        }
      }

      /* Handle retransmitted CKE, CCCS, CHD */
      else if ((events[i].events & EPOLLOUT) &&
               (conn->sock_state == TLS_HS_RECVED)) {
        send_server_records(conn);
        mod_epoll_in_mig_sock(conn, ctx->epfd);
        conn->sock_state = READY_TO_RECV;
      }

      /* Close migrated socket */
      else if ((events[i].events & EPOLLIN) &&
               (conn->sock_state == HTTP_RESP_SENT ||
                conn->sock_state == WAIT_TCP_FIN)) {
        close_tcp_conn(ctx, conn);
      }

      /* Close errored socket */
      else if ((events[i].events & EPOLLOUT) &&
               (conn->sock_state == HTTP_RESP_SENT ||
                conn->sock_state == ERRORED)) {
        close_tcp_conn(ctx, conn);
      }
    }

    print_stat(ctx);
  }

  close(ctx->meta_sock);

  return NULL;
}
/*----------------------------------------------------------------------------*/
int main(int argc, char **argv) {
  /* argument parsing */
  int o;
  const char *www_main = NULL;
  int cpu_size;
  thread_args_t thread_args[MAX_THREAD_NUM];

  if (argc < 2) {
    TRACE_CONFIG("$%s directory_to_service\n", argv[0]);
    return 0;
  }

  while (-1 != (o = getopt(argc, argv, "p:v:t:"))) {
    switch (o) {
    case 'p':
      /* open the directory to serve */
      www_main = optarg;
      // dir = opendir(www_main);
      // if (!dir) {
      // 	TRACE_CONFIG("Failed to open %s.\n", www_main);
      // 	perror("opendir");
      // 	return 0;
      // }
      break;
    case 'v':
      if (strcmp(optarg, "tls12") == 0) {
        fprintf(stderr, "Custom server SSL version: TLS 1.2\n");
        tls13 = 0;
      } else if (strcmp(optarg, "tls13") == 0) {
        fprintf(stderr, "Custom server SSL version: TLS 1.3\n");
        tls13 = 1;
      } else {
        fprintf(stderr, "Only TLS version 1.2 and 1.3 are supported.\n");
        return -1;
      }
      break;
    case 't':
      thread_num = atoi(optarg);
      if (thread_num < 1 || thread_num > MAX_THREAD_NUM) {
        fprintf(stderr, "Thread number should be between 1 and %d.\n",
                MAX_THREAD_NUM);
        return -1;
      }
      break;
    }
  }

  pthread_t p_thread[MAX_THREAD_NUM];
  pthread_attr_t attr[MAX_THREAD_NUM];
  cpu_set_t *cpusetp[MAX_THREAD_NUM];

  long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
  if (ncpu < 1)
    ncpu = 1;

  for (int i = 0; i < thread_num; i++) {
    /* set core */
    if ((cpusetp[i] = CPU_ALLOC(thread_num)) == NULL) {
      fprintf(stderr, "Error: cpu_set initialize failed\n");
      exit(0);
    }
    cpu_size = CPU_ALLOC_SIZE(thread_num);
    CPU_ZERO_S(cpu_size, cpusetp[i]);
    CPU_SET_S(i % ncpu, cpu_size, cpusetp[i]);

    thread_args[i] = (thread_args_t){.www_main = www_main, .core_id = i};

    /* set thread attribute (core pinning) */
    if (pthread_attr_init(&attr[i]) != 0) {
      fprintf(stderr, "Error: thread attribute initialize failed\n");
      exit(0);
    }
    pthread_attr_setaffinity_np(&attr[i], cpu_size, cpusetp[i]);

    /* create thread */
    int rc =
        pthread_create(&p_thread[i], &attr[i], worker_thread, &thread_args[i]);
    if (rc != 0) {
      fprintf(stderr, "Error: pthread_create failed: %s (rc = %d)\n",
              strerror(rc), rc);
      exit(0);
    }
  }

  /* wait threads */
  for (int i = 0; i < thread_num; i++) {
    pthread_join(p_thread[i], NULL);
    CPU_FREE(cpusetp[i]);
  }

  return 0;
}