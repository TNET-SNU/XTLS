#include "set_sock.h"
#include "mempool.h"
#include "meta_pkt.h"

// #include <time.h>
// #include <net/if.h>
// #include <netinet/tcp.h>
// #include <linux/filter.h>

extern uint64_t closed_conns[MAX_THREAD_NUM];
extern struct timespec total_conn_time;

/*----------------------------------------------------------------------------*/
int setup_meta_sock(thread_ctx_t *ctx) {
  int sock;
  struct ifreq ifr;
  struct sockaddr_ll saddr;
  const char *iface = "ens17f0np0";

  static const uint16_t key_eth_types[] = {
      KEY_META_ETH_TYPE_0,  KEY_META_ETH_TYPE_1,  KEY_META_ETH_TYPE_2,
      KEY_META_ETH_TYPE_3,  KEY_META_ETH_TYPE_4,  KEY_META_ETH_TYPE_5,
      KEY_META_ETH_TYPE_6,  KEY_META_ETH_TYPE_7,  KEY_META_ETH_TYPE_8,
      KEY_META_ETH_TYPE_9,  KEY_META_ETH_TYPE_10, KEY_META_ETH_TYPE_11,
      KEY_META_ETH_TYPE_12, KEY_META_ETH_TYPE_13, KEY_META_ETH_TYPE_14,
      KEY_META_ETH_TYPE_15,
  };

  // Crate a raw socket for TCP/TLS meta packets
  sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock < 0) {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  // Interface index
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
  if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
    perror("SIOCGIFINDEX");
    close(sock);
    exit(EXIT_FAILURE);
  }

  // Bind the socket to the interface
  memset(&saddr, 0, sizeof(saddr));
  saddr.sll_family = AF_PACKET;
  saddr.sll_ifindex = ifr.ifr_ifindex;
  saddr.sll_protocol = htons(ETH_P_ALL);

  if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
    perror("bind");
    close(sock);
    exit(EXIT_FAILURE);
  }

  struct sock_fprog bpf = bpf_filter_for_meta(ctx);

  if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
    perror("setsockopt(SO_ATTACH_FILTER)");
    close(sock);
    exit(EXIT_FAILURE);
  }

  fprintf(stderr, "Listening for EtherType 0x%04x on interface %s\n",
          key_eth_types[ctx->core_id], iface);

  return sock;
}

int set_mig_sock(struct meta_info *meta_info) {
  int sock;
  int yes = 1, val;

  /* Make TCP socket for TCP migration */
  MEASURE("socket", sock = socket(AF_INET, SOCK_STREAM, 0););

  if (sock < 0)
    return pr_perror("socket");

  /* Set socket option - Turn on TCP repair mode & re-use option */
  MEASURE("setsockopt_set_tcp_repair",
          if (setsockopt(sock, SOL_TCP, TCP_REPAIR, &yes,
                         sizeof(yes))) return pr_perror("TCP_REPAIR"););

  MEASURE("setsockopt_set_tcp_reuseaddr",
          if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) ==
              -1) return pr_perror("setsockopt: reuseaddr"););

  MEASURE("setsockopt_set_tcp_reuseport",
          if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes)) ==
              -1) return pr_perror("setsockopt: reuseport"););

  struct linger Linger;

  Linger.l_onoff = 1;
  Linger.l_linger = 0;

  MEASURE("setsockopt_set_tcp_linger",
          if (setsockopt(sock, SOL_SOCKET, SO_LINGER, (char *)&Linger,
                         sizeof(Linger)) ==
              -1) return pr_perror("setsockopt: linger"););

  /* Set socket option - Set seq/ack num */
  val = TCP_SEND_QUEUE;
  MEASURE("setsockopt_set_tcp_send_queue",
          if (setsockopt(sock, SOL_TCP, TCP_REPAIR_QUEUE, &val,
                         sizeof(val))) return pr_perror("TCP_SEND_QUEUE"););

  val = meta_info->seq_num;
#if VERBOSE_META
  printf("seq num of server= 0x%08x\n", val);
#endif /* VERBOSE_META */
  MEASURE("setsockopt_set_tcp_seq_num",
          if (setsockopt(sock, SOL_TCP, TCP_QUEUE_SEQ, &val,
                         sizeof(val))) return pr_perror("TCP_QUEUE_SEQ"););

  val = TCP_RECV_QUEUE;
  MEASURE("setsockopt_set_tcp_recv_queue",
          if (setsockopt(sock, SOL_TCP, TCP_REPAIR_QUEUE, &val,
                         sizeof(val))) return pr_perror("TCP_RECV_QUEUE"););

  val = meta_info->ack_num;
#if VERBOSE_META
  printf("ack num of server= 0x%08x\n", val);
#endif /* VERBOSE_META */
  MEASURE("setsockopt_set_tcp_ack_num",
          if (setsockopt(sock, SOL_TCP, TCP_QUEUE_SEQ, &val,
                         sizeof(val))) return pr_perror("TCP_QUEUE_ACK"););

  return sock;
}

int mig_tcp_conn(conn_state_t *conn, int epfd) {
  struct sockaddr_in bind_addr, conn_addr;
  struct tcp_repair_opt opts[TCPOPT_NUM];
  int onr = 0, val = 0;

  MEASURE(
      "register_epoll_out_mig_sock",
      if (register_epoll_out_mig_sock(conn, epfd) < 0) {
        fprintf(stderr, "Failed to register epollout for mig_sock\n");
        return -1;
      });

  /* Bind & connect */
  MEASURE("bind", memset(&bind_addr, 0, sizeof(bind_addr));
          bind_addr.sin_family = AF_INET;
          bind_addr.sin_addr.s_addr = inet_addr("10.0.0.2");
          bind_addr.sin_port = htons(SSL_PORT);
          if (bind(conn->sock_fd, (struct sockaddr *)&bind_addr,
                   sizeof(bind_addr))) return pr_perror("bind"););

  MEASURE(
      "connect", memset(&conn_addr, 0, sizeof(conn_addr));
      conn_addr.sin_family = AF_INET;
      conn_addr.sin_addr.s_addr = htonl(conn->meta_info.client_ip);
      conn_addr.sin_port = htons(conn->meta_info.client_port);
      if (connect(conn->sock_fd, (struct sockaddr *)&conn_addr,
                  sizeof(conn_addr))) {
        fprintf(stderr, "Failed to connect %s:%d (client)\n",
                inet_ntoa(conn_addr.sin_addr), conn->meta_info.client_port);
        return pr_perror("connect");
      });

  // TODO: send TCP options (Hard coded for now)
  /* Set socket option - Set TCP option */
  opts[onr].opt_code = TCPOPT_WINDOW;
  opts[onr].opt_val = 14 + (14 << 16);
  onr++;

  opts[onr].opt_code = TCPOPT_MAXSEG;
  opts[onr].opt_val = 1460;
  onr++;

  MEASURE(
      "setsockopt_set_tcp_repair_options",
      if (setsockopt(conn->sock_fd, SOL_TCP, TCP_REPAIR_OPTIONS, opts,
                     onr * sizeof(struct tcp_repair_opt)) < 0) {
        return pr_perror("Can't repair options");
      }

      if (setsockopt(conn->sock_fd, SOL_TCP, TCP_REPAIR, &val,
                     sizeof(val))) return pr_perror("TCP_REPAIR"););

  return 0;
}

int mig_tls_conn(conn_state_t *conn) {
  // for debugging
  struct in_addr addr;
  addr.s_addr = htonl(conn->meta_info.client_ip);

  // Set TCP_ULP option to use kTLS
  MEASURE(
      "setsockopt_set_tcp_ulp", if (setsockopt(conn->sock_fd, SOL_TCP, TCP_ULP,
                                               "tls", sizeof("tls")) < 0) {
        fprintf(stderr, "Client %s:%d\n", inet_ntoa(addr),
                conn->meta_info.client_port);
        perror("Unable to set TCP_ULP");
        return -1;
      });

  // Set TCP_CORK option to avoid sending partial packets
  int opt_on = 1;
  MEASURE("setsockopt_set_tcp_cork",
          setsockopt(conn->sock_fd, IPPROTO_TCP, TCP_CORK, &opt_on,
                     sizeof(opt_on)););

  // setsockopt(conn->sock_fd, IPPROTO_TCP, TCP_QUICKACK, &opt_on,
  // sizeof(opt_on));

  // Send TLS RX info to kTLS/L5o (KTLS_RX)
  MEASURE(
      "setsockopt_set_tls_rx",
      if (setsockopt(conn->sock_fd, SOL_TLS, TLS_RX,
                     &(conn->crypto_info.crypto_info_rx),
                     sizeof(conn->crypto_info.crypto_info_rx)) < 0) {
        perror("setsockopt(TLS_RX)");
        // exit(EXIT_FAILURE);
      });

  // Send TLS TX info to kTLS/L5o (KTLS_TX)
  MEASURE(
      "setsockopt_set_tls_tx",
      if (setsockopt(conn->sock_fd, SOL_TLS, TLS_TX,
                     &(conn->crypto_info.crypto_info_tx),
                     sizeof(conn->crypto_info.crypto_info_tx)) < 0) {
        perror("setsockopt(TLS_TX)");
        // exit(EXIT_FAILURE);
      });

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
  int zcsendfile = 1;
  // Set zero-copy sendfile of kTLS
  MEASURE(
      "setsockopt_set_tls_zcsendfile",
      if (setsockopt(conn->sock_fd, SOL_TLS, TLS_TX_ZEROCOPY_RO, &zcsendfile,
                     sizeof(zcsendfile)) < 0) {
        perror("setsockopt(TLS_TX)");
        // exit(EXIT_FAILURE);
      });
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0) */

  return 0;
}

void close_tcp_conn(thread_ctx_t *ctx, struct conn_state *conn) {
  send_close_to_arm(ctx->meta_sock, conn);
  remove_epoll_mig_sock(conn, ctx->epfd);
  MEASURE(
      "close", if (close(conn->sock_fd)) {
        fprintf(stderr, "Failed to close socket %d: %s\n", conn->sock_fd,
                strerror(errno));
      });

  if (likely(ht_search(ctx->ht_conn, conn->meta_info.client_ip,
                       conn->meta_info.client_port))) {
    ht_remove(ctx->ht_conn, conn);
#if EVALUATION
    closed_conns[ctx->core_id]++;

    clock_gettime(CLOCK_MONOTONIC, &conn->conn_fin);
    total_conn_time.tv_sec += (conn->conn_fin.tv_sec - conn->conn_start.tv_sec);
    total_conn_time.tv_nsec +=
        (conn->conn_fin.tv_nsec - conn->conn_start.tv_nsec);
#endif /* EVALUATION */
  }

  conn_state_free(conn, ctx->core_id);

  return;
}
/*----------------------------------------------------------------------------*/
