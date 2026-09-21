#define _POSIX_C_SOURCE 199309L
#define _GNU_SOURCE

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <threads.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/types.h>

#include "ssloff.h"
#if USE_HASHTABLE_FOR_ACTIVE_SESSION
#include "fhash.h"
#endif /* USE_HASHTABLE_FOR_ACTIVE_SESSION */

#define B_TO_Mb(x)               ((x) * 8 / 1000 / 1000)

#define TCP_SEQ_LT(a, b)         ((int32_t)((a) - (b)) < 0)
#define TCP_SEQ_LEQ(a, b)        ((int32_t)((a) - (b)) <= 0)
#define TCP_SEQ_GT(a, b)         ((int32_t)((a) - (b)) > 0)
#define TCP_SEQ_GEQ(a, b)        ((int32_t)((a) - (b)) >= 0)
#define TCP_SEQ_BETWEEN(a, b, c) (TCP_SEQ_GEQ(a, b) && TCP_SEQ_LEQ(a, c))

#define ISN                      1234
/* for RSA 2048 bit */
#define UPPER_BOUND              300
#define LOWER_BOUND              290
/* for RSA 2048 bit with static tc rule */
/* #define UPPER_BOUND 80 */
/* #define LOWER_BOUND 78 */
/* for RSA 4096 bit */
/* #define UPPER_BOUND 35 */
/* #define LOWER_BOUND 32 */
/*---------------------------------------------------------------------------*/
// eclipse function parameter for ECC
// All of the following constants are in big-endian format.

// static char P256_p_string[] =
//     "ffffffff 00000001 00000000 00000000 00000000 ffffffff"
//     "ffffffff ffffffff";

uint8_t P256_p_buf[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// static char P256_a_string[] =
//     "ffffffff 00000001 00000000 00000000 00000000 ffffffff"
//     "ffffffff fffffffc";

uint8_t P256_a_buf[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC};

// static char P256_b_string[] =
//     "5ac635d8 aa3a93e7 b3ebbd55 769886bc 651d06b0 cc53b0f6"
//     "3bce3c3e 27d2604b";

uint8_t P256_b_buf[] = {0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7,
                        0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
                        0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
                        0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B};

// static char P256_xg_string[] =
//     "6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0"
//     "f4a13945 d898c296";

// Base_pt:
uint8_t P256_xg_buf[] = {0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
                         0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
                         0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
                         0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96};

// static char P256_yg_string[] =
//     "4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece"
//     "cbb64068 37bf51f5";

uint8_t P256_yg_buf[] = {0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
                         0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
                         0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
                         0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5};

// static char P256_n_string[] =
//     "ffffffff 00000000 ffffffff ffffffff bce6faad a7179e84"
//     "f3b9cac2 fc632551";

// Base_pt_order:
uint8_t P256_n_buf[] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
                        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};
/*---------------------------------------------------------------------------*/
/* Global Variables */
extern int host_threads_num;

int num_core;
#if VERBOSE_META_PKT
int num_sent_meta[MAX_CPUS] = {0};
int num_recv_mig_fin[MAX_CPUS] = {0};
int num_recv_close_meta[MAX_CPUS] = {0};
#endif /* VERBOSE_META_PKT */
#if VERBOSE_HWS_RULES
int num_hws_applied[MAX_CPUS] = {0};
#endif /* VERBOSE_HWS_RULES */
#if VERBOSE_RST
int num_recv_rst[MAX_CPUS] = {0};
int num_sent_rst[MAX_CPUS] = {0};
#endif /* VERBOSE_RST */
#if VERBOSE_FIN
int num_recv_fin[MAX_CPUS] = {0};
int num_sent_fin[MAX_CPUS] = {0};
#endif /* VERBOSE_FIN */
#if VERBOSE_TCP_HS || VERBOSE_CONN_LAT
int num_completed_sess[MAX_CPUS] = {0};
#endif /* VERBOSE_TCP_HS || VERBOSE_CONN_LAT */
#if VERBOSE_TCP_HS
int num_recv_syn[MAX_CPUS] = {0};
int num_sent_synack[MAX_CPUS] = {0};
#endif /* VERBOSE_TCP_HS */
#if VERBOSE_CONN_LAT
int num_key_gen[MAX_CPUS] = {0};
int num_gen_key[MAX_CPUS] = {0};
int num_ss_cal[MAX_CPUS] = {0};
int num_cal_ss[MAX_CPUS] = {0};
int num_ee_c_cv_gen[MAX_CPUS] = {0};
int num_gen_cv[MAX_CPUS] = {0};
int num_app_key_cal[MAX_CPUS] = {0};
int num_cal_app_key[MAX_CPUS] = {0};
int num_meta_tx[MAX_CPUS] = {0};
int num_meta_rx[MAX_CPUS] = {0};
int num_app_data[MAX_CPUS] = {0};

uint64_t sum_syn_key_gen_lat[MAX_CPUS] = {0}; /* SYN - ECDHE key gen req. */
uint64_t max_syn_key_gen_lat[MAX_CPUS] = {0};
uint64_t sum_key_gen_gen_key_lat[MAX_CPUS] = {0}; /* key gen latency */
uint64_t max_key_gen_gen_key_lat[MAX_CPUS] = {0};
uint64_t sum_gen_key_ss_cal_lat[MAX_CPUS] = {0}; /* key gened - ss cal req. */
uint64_t max_gen_key_ss_cal_lat[MAX_CPUS] = {0};
uint64_t sum_ss_cal_cal_ss_lat[MAX_CPUS] = {0}; /* ss cal latency */
uint64_t max_ss_cal_cal_ss_lat[MAX_CPUS] = {0};
uint64_t sum_cal_ss_ee_c_cv_gen_lat[MAX_CPUS] = {0}; /* ss caled - c sig req. */
uint64_t max_cal_ss_ee_c_cv_gen_lat[MAX_CPUS] = {0};
uint64_t sum_ee_c_cv_gen_gen_cv_lat[MAX_CPUS] = {0}; /* c sig latency */
uint64_t max_ee_c_cv_gen_gen_cv_lat[MAX_CPUS] = {0};
uint64_t sum_gen_cv_app_key_cal_lat[MAX_CPUS] = {
    0}; /* cv gened - app key cal before */
uint64_t max_gen_cv_app_key_cal_lat[MAX_CPUS] = {0};
uint64_t sum_app_key_cal_cal_app_key_lat[MAX_CPUS] = {
    0}; /* app key cal latency */
uint64_t max_app_key_cal_cal_app_key_lat[MAX_CPUS] = {0};
uint64_t sum_cal_app_key_meta_tx_lat[MAX_CPUS] = {
    0}; /* app key cal - meta tx */
uint64_t max_cal_app_key_meta_tx_lat[MAX_CPUS] = {0};
uint64_t sum_meta_tx_meta_rx_lat[MAX_CPUS] = {0}; /* meta tx/rx latency */
uint64_t max_meta_tx_meta_rx_lat[MAX_CPUS] = {0};
uint64_t sum_app_data_lat[MAX_CPUS] = {
    0}; /* server record sent - session fin */
uint64_t max_app_data_lat[MAX_CPUS] = {0};

uint64_t sum_conn_lat[MAX_CPUS] = {0};
uint64_t max_conn_lat[MAX_CPUS] = {0};
#endif /* VERBOSE_CONN_LAT */
#if VERBOSE_PKA_OP
int num_key_gen[MAX_CPUS] = {0};
int num_calc_shared_secret[MAX_CPUS] = {0};
int num_signature_cert[MAX_CPUS] = {0};
#endif /* VERBOSE_PKA_OP */
static uint16_t per_core_packet_id[MAX_CPUS] = {0};
struct timespec start_ts, cur_ts;
/*---------------------------------------------------------------------------*/
/*------------------------ Function Prototype -------------------------------*/

/* If error occurs, please remove "inline"s. */
/* I removed "inline"s for eliminating un-predictable errors, so if you
/* want to benchmark this program, please add "inline"s back at:
/* process_packet(), validate_packet_type(), validate_sequence() */
/* Or, you can re-compile the code for solving compiler's bugs. */

void
stat_add(ssl_stat_t *dst, ssl_stat_t *src);

void
print_stat();

void
update_cookie();

static uint32_t
get_cookie(uint32_t client_ip, uint16_t client_port, uint32_t server_ip,
           uint16_t server_port);

#if ONLOAD
static int
is_overloaded(thread_context_t *ctx, struct rte_ether_hdr *ethh);
#endif /* ONLOAD */

void
hex_dump(const void *data, size_t len);

static void
clear_tcp_connection(tcp_connection_t *tcp);

static void
clear_ssl_session(ssl_session_t *sess);

int
msb_value(int n);

static void
thread_local_init(int core_id);

static void
thread_local_destroy(int core_id);

static void
remove_session(ssl_session_t *sess);

static int
send_synack_packet(uint16_t core_id, uint16_t port, struct rte_ether_hdr *ethh,
                   struct rte_ipv4_hdr *iph, struct rte_tcp_hdr *tcph,
                   uint32_t cookie);

static tcp_connection_t *
insert_tcp_connection(thread_context_t *ctx, uint16_t portid,
                      const unsigned char *client_mac, uint32_t client_ip,
                      uint16_t client_port, const unsigned char *server_mac,
                      uint32_t server_ip, uint16_t server_port, uint32_t seq_no,
                      uint32_t ack_no, uint16_t window, uint16_t payload_len);

static tcp_connection_t *
search_tcp_connection(thread_context_t *ctx, uint32_t client_ip,
                      uint16_t client_port, uint32_t server_ip,
                      uint16_t server_port);

static tcp_connection_t *
pop_free_connection(thread_context_t *ctx);

#if LINUX_TCP_SERVER
int
send_key_meta(int core_id, int port, tcp_connection_t *conn);

int
send_rst_conn_meta(int core_id, int port, tcp_connection_t *conn);
#else  /* !LINUX_TCP_SERVER */
int
send_key_meta(int coreid, int port, tcp_connection_t *conn,
              uint32_t next_recv_seq, uint32_t next_recv_ack, uint8_t *payload,
              uint16_t payload_len);
#endif /* !LINUX_TCP_SERVER */

static int
validate_syn_packet(tcp_connection_t *conn, uint32_t seq_no, uint32_t ack_no);

static int
validate_sequence(tcp_connection_t *conn, uint32_t seq_no, uint32_t ack_no,
                  uint16_t payload_len);

static void
process_packet(uint16_t core_id, uint16_t port, uint8_t *pktbuf, uint16_t len);

static unsigned
check_ready(void);

static int
process_session_health_check(tcp_connection_t *conn);

void
apply_hws(tcp_connection_t *conn);

void
remove_hws(tcp_connection_t *conn);

void
handle_waiting_hws_del_conns(thread_context_t *ctx, uint16_t port);

/*---------------------------------------------------------------------------*/

void
stat_add(ssl_stat_t *dst, ssl_stat_t *src)
{
    int port;

    dst->completes += src->completes;
    dst->only_tcp += src->only_tcp;
    RTE_ETH_FOREACH_DEV(port)
    {
        dst->rx_bytes[port] += src->rx_bytes[port];
        dst->rx_pkts[port] += src->rx_pkts[port];
        dst->tx_bytes[port] += src->tx_bytes[port];
        dst->tx_pkts[port] += src->tx_pkts[port];
        dst->rtx_bytes[port] += src->rtx_bytes[port];
        dst->rtx_pkts[port] += src->rtx_pkts[port];
    }
}

void
print_stat()
{
    int i, port;
#if VERBOSE_STAT_0
    /* Print stat */
    /* Init global stat */
    memset(&cur_global_stat, 0, sizeof(cur_global_stat));

    /* From local stat to global stat */
    for (i = 0; i < num_core; i++) {
        stat_add(&cur_global_stat, &ctx_array[i]->cur_stat);
    }

    /* Per-Core Stat */
    for (i = 0; i < num_core; i++) {
        ctx_array[i]->cur_stat.throughput = ctx_array[i]->cur_stat.completes -
                                            ctx_array[i]->prev_stat.completes;
        ctx_array[i]->cur_stat.only_tcp_throughput =
            ctx_array[i]->cur_stat.only_tcp - ctx_array[i]->prev_stat.only_tcp;

        fprintf(stderr,
                "[CPU %2d] %5lu conns/s, %5lu only tcp handshake/s"
                "%4d active sessions, %4d free sessions, "
                "%4d free records, %4d free ops\n",
                i, ctx_array[i]->cur_stat.throughput,
                ctx_array[i]->cur_stat.only_tcp_throughput,
                ctx_array[i]->active_cnt, ctx_array[i]->free_cnt,
                ctx_array[i]->free_record_cnt, ctx_array[i]->free_op_cnt);

        ctx_array[i]->prev_stat.completes = ctx_array[i]->cur_stat.completes;
        ctx_array[i]->prev_stat.only_tcp = ctx_array[i]->cur_stat.only_tcp;

        RTE_ETH_FOREACH_DEV(port)
        {
            fprintf(stderr,
                    "[CPU %2d] Port %d "
                    "RX: %7lu(pps), %6.2f(Mbps), "
                    "TX: %7lu(pps), %6.2f(Mbps), "
                    "RTX: %7lu(pps), %6.2f(Mbps)\n",
                    i, port,
                    ctx_array[i]->cur_stat.rx_pkts[port] -
                        ctx_array[i]->prev_stat.rx_pkts[port],
                    B_TO_Mb((float)(ctx_array[i]->cur_stat.rx_bytes[port] -
                                    ctx_array[i]->prev_stat.rx_bytes[port])),
                    ctx_array[i]->cur_stat.tx_pkts[port] -
                        ctx_array[i]->prev_stat.tx_pkts[port],
                    B_TO_Mb((float)(ctx_array[i]->cur_stat.tx_bytes[port] -
                                    ctx_array[i]->prev_stat.tx_bytes[port])),
                    ctx_array[i]->cur_stat.rtx_pkts[port] -
                        ctx_array[i]->prev_stat.rtx_pkts[port],
                    B_TO_Mb((float)(ctx_array[i]->cur_stat.rtx_bytes[port] -
                                    ctx_array[i]->prev_stat.rtx_bytes[port])));
            ctx_array[i]->prev_stat.rx_pkts[port] =
                ctx_array[i]->cur_stat.rx_pkts[port];
            ctx_array[i]->prev_stat.rx_bytes[port] =
                ctx_array[i]->cur_stat.rx_bytes[port];
            ctx_array[i]->prev_stat.tx_pkts[port] =
                ctx_array[i]->cur_stat.tx_pkts[port];
            ctx_array[i]->prev_stat.tx_bytes[port] =
                ctx_array[i]->cur_stat.tx_bytes[port];
            ctx_array[i]->prev_stat.rtx_pkts[port] =
                ctx_array[i]->cur_stat.rtx_pkts[port];
            ctx_array[i]->prev_stat.rtx_bytes[port] =
                ctx_array[i]->cur_stat.rtx_bytes[port];
        }
    }

    /* Global Stat */
    cur_global_stat.throughput =
        cur_global_stat.completes - prev_global_stat.completes;
    cur_global_stat.only_tcp_throughput =
        cur_global_stat.only_tcp - prev_global_stat.only_tcp;

    fprintf(stderr, "\n[TOTAL] %lu conns/s, %lu only tcp handshake/s\n",
            cur_global_stat.throughput, cur_global_stat.only_tcp_throughput);

    prev_global_stat.completes = cur_global_stat.completes;
    prev_global_stat.only_tcp = cur_global_stat.only_tcp;

    RTE_ETH_FOREACH_DEV(port)
    {

        fprintf(stderr,
                "[TOTAL] Port %d "
                "RX: %7lu (pps), %6.2f(Mbps), "
                "TX: %7lu(pps), %6.2f(Mbps), "
                "RTX: %7lu(pps), %6.2f(Mbps)\n",
                port,
                cur_global_stat.rx_pkts[port] - prev_global_stat.rx_pkts[port],
                B_TO_Mb((float)(cur_global_stat.rx_bytes[port] -
                                prev_global_stat.rx_bytes[port])),
                cur_global_stat.tx_pkts[port] - prev_global_stat.tx_pkts[port],
                B_TO_Mb((float)(cur_global_stat.tx_bytes[port] -
                                prev_global_stat.tx_bytes[port])),
                cur_global_stat.rtx_pkts[port] -
                    prev_global_stat.rtx_pkts[port],
                B_TO_Mb((float)(cur_global_stat.rtx_bytes[port] -
                                prev_global_stat.rtx_bytes[port])));

        prev_global_stat.rx_pkts[port] = cur_global_stat.rx_pkts[port];
        prev_global_stat.rx_bytes[port] = cur_global_stat.rx_bytes[port];
        prev_global_stat.tx_pkts[port] = cur_global_stat.tx_pkts[port];
        prev_global_stat.tx_bytes[port] = cur_global_stat.tx_bytes[port];
        prev_global_stat.rtx_pkts[port] = cur_global_stat.rtx_pkts[port];
        prev_global_stat.rtx_bytes[port] = cur_global_stat.rtx_bytes[port];
    }
#endif /* VERBOSE_STAT_0 */

#if VERBOSE_STAT_1
    int total_active_sessions = 0;

    for (int i = 0; i < rte_lcore_count(); i++) {
        if (ctx_array[i]) {
            total_active_sessions += ctx_array[i]->active_session_table->count;
            fprintf(stderr, "Local active_sessions of core %d: %ld\n",
                    ctx_array[i]->coreid,
                    ctx_array[i]->active_session_table->count);
        }
    }

    fprintf(stderr, "Total active_sessions = %d\n", total_active_sessions);

    if (total_active_sessions < 100) {
        fprintf(stderr, "Dumping remaining sessions (total = %d):\n",
                total_active_sessions);
        for (int i = 0; i < rte_lcore_count(); i++) {
            if (ctx_array[i] && ctx_array[i]->active_session_table) {
                hashtable_t *ht = ctx_array[i]->active_session_table;
                for (int b = 0; b < ht->bins; b++) {
                    tcp_connection_t *sess;
                    TAILQ_FOREACH(sess, &ht->ht_table[b], active_session_link)
                    {
                        fprintf(
                            stderr, "Core %d bucket %d -> client_port: %u\n",
                            ctx_array[i]->coreid, b, ntohs(sess->client_port));
                    }
                }
            }
        }
    }
#endif /* VERBOSE_STAT_1 */
}

void
update_cookie()
{
    /* Cookie Timevalue Update */
    if (t_minor == 63) {
        if (t_major == 31) {
            t_major = 0;
            t_minor = 0;
        } else {
            t_major++;
            t_minor = 0;
        }
    } else
        t_minor++;
}

static uint32_t
get_cookie(uint32_t client_ip, uint16_t client_port, uint32_t server_ip,
           uint16_t server_port)
{
    uint32_t cookie;
    uint32_t input[3];
    uint8_t hash[20];

    cookie = t_major;
    cookie = cookie << 3;

    cookie += 3; /* MSS 1500 */

    /* Make hash input */
    input[0] = client_ip;
    input[1] = server_ip;
    input[2] = (uint32_t)client_port | ((uint32_t)server_port << 16);

    SHA1((uint8_t *)input, 12, hash);

    cookie = cookie << 8;
    cookie += hash[0];

    cookie = cookie << 8;
    cookie += hash[1];

    cookie = cookie << 8;
    cookie += hash[2];

    return cookie;
}

#if ONLOAD
static int
is_overloaded(thread_context_t *ctx, struct rte_ether_hdr *ethh)
{
#if !NO_TLS
    struct rte_ipv4_hdr *iph;
    struct rte_tcp_hdr *tcph;
    int ret = 0;
    int waiting_op = 0;
    int i;

    iph = (struct rte_ipv4_hdr *)(ethh + 1);
    tcph = (struct rte_tcp_hdr *)(iph + 1);
    for (i = 0; i < MAX_CPUS; i++) {
        if (ctx_array[i])
            waiting_op += ctx_array[i]->using_op_cnt;
    }

    if (waiting_op < LOWER_BOUND)
        ctx->decrease = FALSE;

    if (waiting_op > UPPER_BOUND)
        ctx->decrease = TRUE;

    if (ctx->decrease)
        ret = 1;

    // fprintf(stderr, "waiting_op: %d\n", waiting_op);

    UNUSED(ctx);
    UNUSED(tcph);
    return ret;
#else  /* !NO_TLS */
    UNUSED(ctx);
    UNUSED(ethh);
    return 1;
#endif /* NO_TLS */
}
#endif /* ONLOAD */

/* for debugging */
const uint8_t TARGET_SRC_MAC[6] = {0x38, 0x25, 0xf3, 0x56, 0x1b, 0x6e};
const uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

int
is_broadcast(const void *data)
{
    const uint8_t *buf = (const uint8_t *)data;

    // src MAC starts at offset 6
    return memcmp(&buf[0], BROADCAST_MAC, 6) == 0;
}

void
hex_dump(const void *data, size_t len)
{
    const unsigned char *buf = (const unsigned char *)data;

    flockfile(stderr);
    fprintf(stderr, "packet len: %zu\n", len);
    for (size_t i = 0; i < len; i++) {
        // Print hex value
        fprintf(stderr, "%02X ", buf[i]);

        // Newline every 16 bytes
        if ((i + 1) % 16 == 0) {
            fprintf(stderr, "\n");
        }
    }

    // If the last line was not completed
    if (len % 16 != 0) {
        fprintf(stderr, "\n");
    }
    funlockfile(stderr);

    fprintf(stderr, "\n");
}

static void
clear_tcp_connection(tcp_connection_t *conn)
{
    /* Do not touch coreid, ssl_session */
    conn->state = TCP_SESSION_IDLE;
    conn->portid = 0;

    conn->ip_id = 0;

    conn->client_ip = 0;
    conn->client_port = 0;

#if ONLOAD
    conn->onload = 0;
#endif /* ONLOAD */

    conn->server_ip = 0;
    conn->server_port = 0;

    conn->window = 0;

    conn->total_sent = 0;

    conn->last_recv_seq = 0;
    conn->last_recv_ack = 0;
    conn->last_recv_len = 0;

    conn->last_sent_seq = 0;
    conn->last_sent_ack = 0;
    conn->last_sent_len = 0;

#if USE_RTE_HWS
    conn->recv_mig_fin = 0;
    conn->hws_inserted = 0;
    conn->hws_applied = 0;
    conn->hws_ready_to_del = 0;
    conn->hws_deleted = 0;
#endif /* USE_RTE_HWS */

    conn->pending_syn.ethh = (struct rte_ether_hdr){0};
    conn->pending_syn.iph = (struct rte_ipv4_hdr){0};
    conn->pending_syn.tcph = (struct rte_tcp_hdr){0};
    conn->pending_syn.payload_len = 0;
    conn->pending_syn.tcp_option_len = 0;
    memset(conn->pending_syn.tcp_options, 0, 40);

    conn->need_to_send_rst_meta = FALSE;

#if FWD_ONLY_APPDATA
    /* test for forwarding only app data */
    conn->pending_app_data_len = 0;
#endif /* FWD_ONLY_APPDATA */

#if OFFLOAD_AES_GCM
    tcp->next_sent_seq = 0;
#endif /* OFFLOAD_AES_GCM */
}

static void
clear_ssl_session(ssl_session_t *sess)
{
    /* Do not touch parent, context_ */
    sess->state = STATE_INIT;
    sess->handshake_state = HELLO_REQUEST;

    sess->current_read_record = NULL;

    sess->version.major = 0;
    sess->version.minor = 0;

    sess->recv_seq_num_ = 0;
    sess->send_seq_num_ = 0;

    sess->handshake_msgs_len = 0;

    memset(&sess->client_write_MAC_secret, 0,
           sizeof(sess->client_write_MAC_secret));
    memset(&sess->server_write_MAC_secret, 0,
           sizeof(sess->server_write_MAC_secret));
    memset(&sess->client_write_key, 0, sizeof(sess->client_write_key));
    memset(&sess->server_write_key, 0, sizeof(sess->server_write_key));
    memset(&sess->client_write_IV, 0, sizeof(sess->client_write_IV));
    memset(&sess->server_write_IV, 0, sizeof(sess->server_write_IV));

    sess->client_write_IV_seq_num = 0;
    sess->server_write_IV_seq_num = 0;

    memset(&sess->tls13_ctx, 0, sizeof(sess->tls13_ctx));
    memset(sess->meta_hdr, 0, sizeof(sess->meta_hdr));

    memset(&sess->server_finish_digest, 0, sizeof(sess->server_finish_digest));

    sess->rand_seed = rand();

    memset(&sess->send_buffer, 0, sizeof(sess->send_buffer));
    sess->send_buffer_offset = 0;

    memset(&sess->read_sp, 0, sizeof(sess->read_sp));
    memset(&sess->write_sp, 0, sizeof(sess->write_sp));
    memset(&sess->pending_sp, 0, sizeof(sess->pending_sp));

    sess->read_sp.entity = SERVER;
    sess->write_sp.entity = SERVER;

    clear_results(sess->pka_results);
    memset(sess->pka_op, 0, sizeof(ssl_crypto_t));

    sess->waiting_crypto = 0;
    sess->completed_crypto = 0;

    /* sj added */ /* Need to maintain buf_ptr */
    // sess->rsa_operand->buf_len = MAX_BYTE_LEN + 8;
    // memset(sess->rsa_operand->buf_ptr, 0,
    //        sess->rsa_operand->buf_len);
    // memset(sess->rsa_operand, 0, sizeof(pka_operand_t));

    // sess->shared_secret_operand->buf_len = MAX_BYTE_LEN + 8;
    // memset(sess->shared_secret_operand->buf_ptr, 0,
    //        sess->shared_secret_operand->buf_len);
    // memset(sess->shared_secret_operand, 0, sizeof(pka_operand_t));

    // sess->ecdsa_transcript_hash->buf_len = MAX_BYTE_LEN + 8;
    // memset(sess->ecdsa_transcript_hash->buf_ptr, 0,
    //        sess->ecdsa_transcript_hash->buf_len);
    // memset(sess->ecdsa_transcript_hash, 0, sizeof(pka_operand_t));

    /* Remove the pending rsa op and corresponding record */
    remove_pending_pka_op(sess);

    /* Remove records from the session */
    record_t *cur, *next;
    cur = TAILQ_FIRST(&sess->recv_q);
    while (cur != NULL) {
        next = TAILQ_NEXT(cur, recv_q_link);

        /* Remove from receive queue */
        TAILQ_REMOVE(&sess->recv_q, cur, recv_q_link);

        /* Clear the record */
        memset(cur, 0, sizeof(record_t));
        cur->ctx = sess->ctx;

        /* Put the record back to the record pool */
        TAILQ_INSERT_TAIL(&sess->ctx->record_pool, cur, record_pool_link);
        sess->ctx->free_record_cnt++;
        sess->ctx->using_record_cnt--;

        cur = next;
    }

#if OFFLOAD_AES_GCM
    if (sess->tls_ctx.aead_key.key) {
        rte_eth_tls_device_free(sess->parent->portid, &sess->tls_ctx);
        memset(&sess->tls_ctx, 0, sizeof(sess->tls_ctx));
    }
#endif /* OFFLOAD_AES_GCM */

    sess->num_current_records = 0;
    sess->recv_q_cnt = 0;

    sess->waiting_crypto = FALSE;
    sess->num_cke_retransmitted = 0;

    memset(&sess->tls13_ctx, 0, sizeof(sess->tls13_ctx));

    init_random(sess, sess->id_.id, sizeof(sess->id_.id));

    sess->num_of_retransmitted_ch = 0;
    sess->num_of_retransmitted_meta_pkt = 0;
}

int
msb_value(int n)
{
    if (n == 0)
        return 0;

    int x = 1;
    while (n >>= 1) {
        x <<= 1;
    }
    return x;
}

static void
thread_local_init(int core_id)
{
    thread_context_t *ctx;
    struct dpdk_private_context *dpc;
    ssl_session_t *sess;
    int nb_ports;
    int i, j;

    nb_ports = rte_eth_dev_count_avail();

    DEBUG_PRINT("[thread local init] [core %d] local_max_conn: %u\n", core_id,
                local_max_conn);

    /* Allocate memory for thread context */
    ctx_array[core_id] = calloc(1, sizeof(thread_context_t));
    ctx = ctx_array[core_id];
    if (ctx == NULL)
        rte_exit(EXIT_FAILURE,
                 "[CPU %d] Cannot allocate memory for thread_context, "
                 "errno: %d\n",
                 rte_lcore_id(), errno);

    ctx->coreid = (uint16_t)core_id;
    ctx->if_stat[0] = calloc(1, sizeof(struct rte_eth_stats));
    if (ctx->if_stat[0] == NULL)
        rte_exit(EXIT_FAILURE,
                 "[CPU %d] Cannot allocate memory for if_stat, "
                 "errno: %d\n",
                 rte_lcore_id(), errno);

    ctx->if_stat[1] = calloc(1, sizeof(struct rte_eth_stats));
    if (ctx->if_stat[1] == NULL)
        rte_exit(EXIT_FAILURE,
                 "[CPU %d] Cannot allocate memory for if_stat, "
                 "errno: %d\n",
                 rte_lcore_id(), errno);

    /* Allocate memory for dpdk private context */
    ctx->dpc = calloc(1, sizeof(struct dpdk_private_context));
    dpc = ctx->dpc;
    if (dpc == NULL)
        rte_exit(EXIT_FAILURE,
                 "[CPU %d] Cannot allocate memory for dpdk_private_context, "
                 "errno: %d\n",
                 rte_lcore_id(), errno);

    /* Assign packet mbuf pool to dpdk private context */
    dpc->pktmbuf_pool = pktmbuf_pool[core_id];

    /* debug */
    fprintf(stderr, "nb_ports: %u, total_port: %u\n", nb_ports,
            rte_eth_dev_count_total());

    if (core_id != 0) {
        for (j = 0; j < nb_ports; j++) {
            /* Allocate wmbufs for each registered port */
            for (i = 0; i < MAX_PKT_BURST; i++) {
                dpc->wmbufs[j].m_table[i] =
                    rte_pktmbuf_alloc(pktmbuf_pool[core_id]);
                if (dpc->wmbufs[j].m_table[i] == NULL) {
                    rte_exit(EXIT_FAILURE,
                             "[CPU %d] Cannot allocate memory for "
                             "port %d wmbuf[%d]\n",
                             rte_lcore_id(), j, i);
                }
            }
            dpc->wmbufs[j].len = 0;
        }
    }

    /* Initialize Session Queues */
#if USE_HASHTABLE_FOR_ACTIVE_SESSION
    ctx->active_session_table = create_ht(NUM_BINS);
    if (unlikely(!ctx->active_session_table)) {
        fprintf(stderr,
                "Cannot allocate memory for "
                "session hashtable of core[%d]",
                rte_lcore_id());
        exit(EXIT_FAILURE);
    }
#else  /* USE_HASHTABLE_FOR_ACTIVE_SESSION */
    TAILQ_INIT(&ctx->active_session_q);
#endif /* !USE_HASHTABLE_FOR_ACTIVE_SESSION */

    TAILQ_INIT(&ctx->free_session_q);

    ctx->tcp_array = calloc(local_max_conn, sizeof(tcp_connection_t *));

    /* Initialize ssl_ctx */
    ctx->ssl_context = calloc(1, sizeof(ctx_example));
    if (ctx->ssl_context == NULL) {
        fprintf(stderr,
                "Cannot allocate memory for"
                "ssl_ctx of core[%d]\n",
                rte_lcore_id());
        exit(EXIT_FAILURE);
    }
    memcpy(ctx->ssl_context, &ctx_example, sizeof(ctx_example));

    ctx->t_hmac_ctx = HMAC_CTX_new();
    if (ctx->t_hmac_ctx == NULL) {
        fprintf(stderr,
                "Cannot allocate memory for"
                "t_hmac_ctx of core[%d]\n",
                rte_lcore_id());
        exit(EXIT_FAILURE);
    }

    // /* Initialize RSA */
    // ctx->ssl_context->rsa = RSA_new();

    // if (ctx->ssl_context->rsa == NULL) {
    //     fprintf(stderr, "Cannot allocate memory for"
    //             "%dth rsa context of core[%d]\n",
    //             0, rte_lcore_id());
    //     exit(EXIT_FAILURE);
    // }

    // ctx->ssl_context->rsa = RSAPrivateKey_dup(ctx_example.rsa);

    /* Initialize ECDSA */
    ctx->ssl_context->ecdsa = EC_KEY_new();

    if (ctx->ssl_context->ecdsa == NULL) {
        fprintf(stderr,
                "Cannot allocate memory for"
                "%dth ecdsa context of core[%d]\n",
                0, rte_lcore_id());
        exit(EXIT_FAILURE);
    }

    ctx->ssl_context->ecdsa = EC_KEY_dup(ctx_example.ecdsa);

    /* Initialize pka_t */
    ctx->ssl_context->pka = calloc(1, sizeof(pka_t));
    if (ctx->ssl_context->pka == NULL) {
        fprintf(stderr,
                "Cannot allocate memory for"
                "%dth pka context of core[%d]\n",
                0, rte_lcore_id());
        exit(EXIT_FAILURE);
    }
    memcpy(ctx->ssl_context->pka, ctx_example.pka, sizeof(pka_t));

    /* Initialize certificate_t */
    ctx->certificates = calloc(1, sizeof(certificate_t));
    if (ctx->certificates == NULL) {
        fprintf(stderr,
                "Cannot allocate memory for"
                "certificate of core[%d]\n",
                rte_lcore_id());
        exit(EXIT_FAILURE);
    }

    /* Allocate memory for tcp sessions */
    for (j = 0; j < local_max_conn; j++) {
        ctx->tcp_array[j] = calloc(1, sizeof(tcp_connection_t));
        if (ctx->tcp_array[j] == NULL) {
            fprintf(stderr,
                    "Cannot allocate memory for"
                    "%dth tcp array of core[%d]\n",
                    j, rte_lcore_id());
            exit(EXIT_FAILURE);
        }

        /* Insert Session into free_session_q */
        TAILQ_INSERT_TAIL(&ctx->free_session_q, ctx->tcp_array[j],
                          free_session_link);
        ctx->free_cnt++;

        clear_tcp_connection(ctx->tcp_array[j]);
        ctx->tcp_array[j]->ctx = ctx;
        ctx->tcp_array[j]->coreid = core_id;
        ctx->tcp_array[j]->session_id = j;

#if USE_RTE_HWS
        /* for set pattern of jump */
        ctx->tcp_array[j]->eth_spec_jump =
            calloc(1, sizeof(struct rte_flow_item_eth));
        ctx->tcp_array[j]->eth_mask_jump =
            calloc(1, sizeof(struct rte_flow_item_eth));

        ctx->tcp_array[j]->ipv4_spec_jump =
            calloc(1, sizeof(struct rte_flow_item_ipv4));
        ctx->tcp_array[j]->ipv4_mask_jump =
            calloc(1, sizeof(struct rte_flow_item_ipv4));

        ctx->tcp_array[j]->tcp_spec_jump =
            calloc(1, sizeof(struct rte_flow_item_tcp));
        ctx->tcp_array[j]->tcp_mask_jump =
            calloc(1, sizeof(struct rte_flow_item_tcp));

        /* for set pattern of hws */
        ctx->tcp_array[j]->eth_spec_hws =
            calloc(1, sizeof(struct rte_flow_item_eth));
        ctx->tcp_array[j]->eth_mask_hws =
            calloc(1, sizeof(struct rte_flow_item_eth));

        ctx->tcp_array[j]->ipv4_spec_hws =
            calloc(1, sizeof(struct rte_flow_item_ipv4));
        ctx->tcp_array[j]->ipv4_mask_hws =
            calloc(1, sizeof(struct rte_flow_item_ipv4));

        ctx->tcp_array[j]->tcp_spec_hws =
            calloc(1, sizeof(struct rte_flow_item_tcp));
        ctx->tcp_array[j]->tcp_mask_hws =
            calloc(1, sizeof(struct rte_flow_item_tcp));

        /* for set action of jump, hws */
        ctx->tcp_array[j]->group_to_jump =
            calloc(1, sizeof(struct rte_flow_action_jump));
        ctx->tcp_array[j]->fwd =
            calloc(1, sizeof(struct rte_flow_action_ethdev));

        /* for jump */
        ctx->tcp_array[j]->pattern_jump =
            calloc(1, sizeof(struct rte_flow_item) * PATTERN_NUM_JUMP);
        ctx->tcp_array[j]->action_jump =
            calloc(1, sizeof(struct rte_flow_action) * ACTION_NUM_JUMP);
        /* for hws */
        ctx->tcp_array[j]->pattern_hws =
            calloc(1, sizeof(struct rte_flow_item) * PATTERN_NUM_HWS);
        ctx->tcp_array[j]->action_hws =
            calloc(1, sizeof(struct rte_flow_action) * ACTION_NUM_HWS);
#endif /* USE_RTE_HWS */

        ctx->tcp_array[j]->ssl_session = calloc(1, sizeof(ssl_session_t));
        if (ctx->tcp_array[j]->ssl_session == NULL) {
            fprintf(stderr,
                    "Cannot allocate memory for"
                    "%dth ssl session of core[%d]\n",
                    j, rte_lcore_id());
            exit(EXIT_FAILURE);
        }

#if FWD_ONLY_APPDATA
        /* test for forwarding only app data */
        ctx->tcp_array[j]->pending_app_data = calloc(1, MAX_APP_DATA_SIZE);
        if (ctx->tcp_array[j]->pending_app_data == NULL) {
            fprintf(stderr,
                    "Cannot allocate memory for"
                    "%dth pending app data of core[%d]\n",
                    j, rte_lcore_id());
            exit(EXIT_FAILURE);
        }
#endif /* FWD_ONLY_APPDATA */

        /* Initialize SSL Session */
        sess = ctx->tcp_array[j]->ssl_session;
        sess->ctx = ctx;
        sess->parent = ctx->tcp_array[j];
        sess->coreid = ctx->tcp_array[j]->coreid;

        sess->next_record_id = 0;

        TAILQ_INIT(&sess->recv_q);
        /* TODO: sj: remove it? */
        sess->recv_q_cnt = 0;

        sess->pka_results = malloc_results(2, MAX_BYTE_LEN + 8);

        if (sess->pka_results == NULL) {
            fprintf(stderr, "malloc_results failed\n");
            exit(EXIT_FAILURE);
        }

        sess->pka_op = calloc(1, sizeof(ssl_crypto_op_t));

        sess->waiting_crypto = FALSE;
        sess->completed_crypto = FALSE;

        /* alloc meta_hdr */
        sess->meta_hdr = calloc(1, sizeof(meta_hdr_t));

        if (sess->meta_hdr == NULL) {
            fprintf(stderr,
                    "Cannot allocate memory for"
                    "%dth meta header of core[%d]\n",
                    j, rte_lcore_id());
            exit(EXIT_FAILURE);
        }

        /* alloc rsa_operand */
        sess->rsa_operand = calloc(1, sizeof(pka_operand_t));

        if (sess->rsa_operand == NULL) {
            fprintf(stderr,
                    "Cannot allocate memory for"
                    "%dth rsa operand of core[%d]\n",
                    j, rte_lcore_id());
            exit(EXIT_FAILURE);
        }

        sess->rsa_operand->buf_ptr = calloc(1, MAX_BYTE_LEN + 8);

        if (sess->rsa_operand->buf_ptr == NULL) {
            fprintf(stderr,
                    "Cannot allocate memory for"
                    "buf of %dth rsa operand of core[%d]\n",
                    j, rte_lcore_id());
            exit(EXIT_FAILURE);
        }

        sess->rsa_operand->buf_len = MAX_BYTE_LEN + 8;

        /* alloc shared secret operand */
        sess->shared_secret_operand = calloc(1, sizeof(pka_operand_t));

        if (sess->shared_secret_operand == NULL) {
            fprintf(stderr,
                    "Cannot allocate memory for"
                    "%dth shared secret operand of core[%d]\n",
                    j, rte_lcore_id());
            exit(EXIT_FAILURE);
        }

        sess->shared_secret_operand->buf_ptr = calloc(1, MAX_BYTE_LEN + 8);

        if (sess->shared_secret_operand->buf_ptr == NULL) {
            fprintf(stderr,
                    "Cannot allocate memory for"
                    "buf of %dth shared secret operand of core[%d]\n",
                    j, rte_lcore_id());
            exit(EXIT_FAILURE);
        }

        sess->shared_secret_operand->buf_len = MAX_BYTE_LEN + 8;

        /* alloc ecdsa transcript hash */
        sess->ecdsa_transcript_hash = calloc(1, sizeof(pka_operand_t));

        if (sess->ecdsa_transcript_hash == NULL) {
            fprintf(stderr,
                    "Cannot allocate memory for"
                    "%dth ecdsa transcript hash of core[%d]\n",
                    j, rte_lcore_id());
            exit(EXIT_FAILURE);
        }

        sess->ecdsa_transcript_hash->buf_ptr = calloc(1, MAX_BYTE_LEN + 8);

        if (sess->ecdsa_transcript_hash->buf_ptr == NULL) {
            fprintf(stderr,
                    "Cannot allocate memory for"
                    "buf of %dth ecdsa transcript hash of core[%d]\n",
                    j, rte_lcore_id());
            exit(EXIT_FAILURE);
        }

        sess->ecdsa_transcript_hash->buf_len = MAX_BYTE_LEN + 8;

        /* alloc ecdsa k */
        sess->ecdsa_k = calloc(1, sizeof(pka_operand_t));

        if (sess->ecdsa_k == NULL) {
            fprintf(stderr,
                    "Cannot allocate memory for"
                    "%dth ecdsa k of core[%d]\n",
                    j, rte_lcore_id());
            exit(EXIT_FAILURE);
        }

        sess->ecdsa_k->buf_ptr = calloc(1, MAX_BYTE_LEN + 8);

        if (sess->ecdsa_k->buf_ptr == NULL) {
            fprintf(stderr,
                    "Cannot allocate memory for"
                    "buf of %dth ecdsa k of core[%d]\n",
                    j, rte_lcore_id());
            exit(EXIT_FAILURE);
        }

        sess->ecdsa_k->buf_len = MAX_BYTE_LEN + 8;

        /* alloc ecdhe priv key */
        sess->ecdhe_priv_key = calloc(1, sizeof(pka_operand_t));

        if (sess->ecdhe_priv_key == NULL) {
            fprintf(stderr,
                    "Cannot allocate memory for"
                    "%dth ecdhe priv key of core[%d]\n",
                    j, rte_lcore_id());
            exit(EXIT_FAILURE);
        }

        sess->ecdhe_priv_key->buf_ptr = calloc(1, MAX_BYTE_LEN + 8);

        if (sess->ecdhe_priv_key->buf_ptr == NULL) {
            fprintf(stderr,
                    "Cannot allocate memory for"
                    "buf of %dth rsa operand of core[%d]\n",
                    j, rte_lcore_id());
            exit(EXIT_FAILURE);
        }

        sess->ecdhe_priv_key->buf_len = MAX_BYTE_LEN + 8;

        /* alloc ecdhe pub key */
        sess->ecdhe_pub_key = calloc(1, sizeof(pka_operand_t));

        if (sess->ecdhe_pub_key == NULL) {
            fprintf(stderr,
                    "Cannot allocate memory for"
                    "%dth ecdhe pub key of core[%d]\n",
                    j, rte_lcore_id());
            exit(EXIT_FAILURE);
        }

        sess->ecdhe_pub_key->buf_ptr = calloc(1, MAX_BYTE_LEN + 8);

        if (sess->ecdhe_pub_key->buf_ptr == NULL) {
            fprintf(stderr,
                    "Cannot allocate memory for"
                    "buf of %dth rsa operand of core[%d]\n",
                    j, rte_lcore_id());
            exit(EXIT_FAILURE);
        }

        sess->ecdhe_pub_key->buf_len = MAX_BYTE_LEN + 8;

        clear_ssl_session(sess);
    }

    pka_barrier_wait(&thread_start_barrier);
    if (ctx->coreid == 0) {
        pka_handle = pka_init_local(instance);

        if (pka_handle == PKA_HANDLE_INVALID) {
            fprintf(stderr, "Local PKA initialilzation failed\n");
            exit(EXIT_FAILURE);
        }

        fprintf(stderr, "PKA Locally Initialized for Core %d\n", core_id);
    }

    /* Create ring for submit pka ring */
    int ring_size = msb_value(local_max_conn);

    char submit_pka_ring_name[32];

    snprintf(submit_pka_ring_name, sizeof(submit_pka_ring_name),
             "submit_pka_ring_%u", rte_lcore_id());

    // ctx->submit_pka_ring = rte_ring_create(submit_pka_ring_name,
    //                                        local_ring_cnt,
    //                                        SOCKET_ID_ANY,
    //                                        RING_F_SP_ENQ | RING_F_SC_DEQ);
    ctx->submit_pka_ring = sj_ring_create(submit_pka_ring_name, local_ring_cnt);

    if (!ctx->submit_pka_ring)
        rte_exit(EXIT_FAILURE, "Failed to create ring for submit pka ring\n");

    /* Create rte_ring for completed_pka_ring */
    char completed_pka_ring_name[32];

    snprintf(completed_pka_ring_name, sizeof(completed_pka_ring_name),
             "completed_pka_ring_%u", rte_lcore_id());

    // ctx->completed_pka_ring = rte_ring_create(completed_pka_ring_name,
    //                                           local_ring_cnt,
    //                                           SOCKET_ID_ANY,
    //                                           RING_F_SP_ENQ | RING_F_SC_DEQ);
    ctx->completed_pka_ring =
        sj_ring_create(completed_pka_ring_name, local_ring_cnt);

    if (!ctx->completed_pka_ring)
        rte_exit(EXIT_FAILURE,
                 "Failed to create ring for completed pka ring\n");

    /* Make ecc info */
    int big_endian = pka_get_rings_byte_order(pka_handle);
    ecc_info[core_id] = calloc(1, sizeof(ecc_info_t));
    ecc_info[core_id]->X25519_curve = calloc(1, sizeof(ecc_mont_curve_t));
    ecc_mont_curve_t *X25519_curve = ecc_info[core_id]->X25519_curve;

    set_pka_operand(&X25519_curve->p, X25519_curve_p_buf,
                    sizeof(X25519_curve_p_buf), big_endian);
    set_pka_operand(&X25519_curve->A, X25519_curve_A_buf,
                    sizeof(X25519_curve_A_buf), big_endian);
    X25519_curve->type = PKA_CURVE_25519;

    ecc_info[core_id]->C255_base_pt = make_mont_ecc_point(
        X25519_curve, Curve255_bp_u_buf, sizeof(Curve255_bp_u_buf),
        Curve255_bp_v_buf, sizeof(Curve255_bp_v_buf), big_endian);

    ecc_info[core_id]->C255_base_pt_order = make_operand(
        Curve255_bp_order_buf, sizeof(Curve255_bp_order_buf), big_endian);

    ecc_info[core_id]->P256_curve = make_ecc_curve(
        P256_p_buf, sizeof(P256_p_buf), P256_a_buf, sizeof(P256_a_buf),
        P256_b_buf, sizeof(P256_b_buf), big_endian);
    ecc_curve_t *P256_curve = ecc_info[core_id]->P256_curve;

    ecc_info[core_id]->P256_base_pt =
        make_ecc_point(P256_curve, P256_xg_buf, sizeof(P256_xg_buf),
                       P256_yg_buf, sizeof(P256_yg_buf), big_endian);

    ecc_info[core_id]->P256_base_pt_order =
        make_operand(P256_n_buf, sizeof(P256_n_buf), big_endian);

    if (core_id == 0)
        C255_base_pt_order_byte_len =
            operand_byte_len(ecc_info[core_id]->C255_base_pt_order);

    /* Set pka handle & rsa result to thread ctx */
    ctx->handle = &pka_handle;
    ctx->pka_result = malloc_results(2, MAX_BYTE_LEN + 8);

    if (ctx->pka_result == NULL) {
        fprintf(stderr, "malloc_results failed\n");
        exit(EXIT_FAILURE);
    }

    /* Insert local_max_conn * 3 records into record_pool */
    TAILQ_INIT(&ctx->record_pool);
    TAILQ_INIT(&ctx->whole_record);

    if (core_id != 0) {
        for (i = 0; i < local_max_conn * 3; i++) {
            record_t *new_record = (record_t *)calloc(1, sizeof(record_t));
            new_record->ctx = ctx;
            TAILQ_INSERT_TAIL(&ctx->record_pool, new_record, record_pool_link);
            /* For memory management */
            TAILQ_INSERT_TAIL(&ctx->whole_record, new_record,
                              record_trace_link);
            ctx->free_record_cnt++;
        }
    }

    /* Insert local_max_conn * 3 ops into op_pool */
    if (ctx->coreid == 0) {
        TAILQ_INIT(&ctx->op_pool);
        TAILQ_INIT(&ctx->whole_op);

        for (i = 0; i < max_conn * 5; i++) {
            ssl_crypto_op_t *new_op =
                (ssl_crypto_op_t *)calloc(1, sizeof(ssl_crypto_op_t));
            new_op->ctx = ctx;
#if PKA_TWICE
            new_op->cnt = 2;
#endif /* PKA_TWICE */
            TAILQ_INSERT_TAIL(&ctx->op_pool, new_op, op_pool_link);
            /* For memory management */
            TAILQ_INSERT_TAIL(&ctx->whole_op, new_op, op_trace_link);
            ctx->free_op_cnt++;
        }
    } else {
        TAILQ_INIT(&ctx->op_pool);
        TAILQ_INIT(&ctx->whole_op);

        for (i = 0; i < local_max_conn * 3; i++) {
            ssl_crypto_op_t *new_op =
                (ssl_crypto_op_t *)calloc(1, sizeof(ssl_crypto_op_t));
            new_op->ctx = ctx;
            TAILQ_INSERT_TAIL(&ctx->op_pool, new_op, op_pool_link);
            /* For memory management */
            TAILQ_INSERT_TAIL(&ctx->whole_op, new_op, op_trace_link);
            ctx->free_op_cnt++;
        }
    }

    /* Create and initialize the OpenSSL AES context */
    if (unlikely(!(ctx->symmetric_crypto_ctx = EVP_CIPHER_CTX_new()))) {
        fprintf(stderr, "Wrong ssl_aes_ctx\n");
        exit(EXIT_FAILURE);
    }

    /* Create rte_ring for waiting hws dels */
    char waiting_hws_del_ring_name[32];

    snprintf(waiting_hws_del_ring_name, sizeof(waiting_hws_del_ring_name),
             "waiting_hws_del_ring_%u", rte_lcore_id());

    // ctx->waiting_hws_del_ring = rte_ring_create(waiting_hws_del_ring_name,
    //                                             local_ring_cnt,
    //                                             SOCKET_ID_ANY,
    //                                             RING_F_SP_ENQ |
    //                                             RING_F_SC_DEQ);
    ctx->waiting_hws_del_ring =
        sj_ring_create(waiting_hws_del_ring_name, local_ring_cnt);

    if (!ctx->waiting_hws_del_ring)
        rte_exit(EXIT_FAILURE, "Failed to create ring for waiting hws dels\n");
}

static void
thread_local_destroy(int core_id)
{
    thread_context_t *ctx;
    struct dpdk_private_context *dpc;
    tcp_connection_t *tcp;
    ssl_session_t *sess;
    int port, i;

    ctx = ctx_array[core_id];
    dpc = ctx->dpc;
    void *cur, *next;

    /* Free RSA result metadata buffer */
    free_results(ctx->pka_result);

    EVP_CIPHER_CTX_free(ctx->symmetric_crypto_ctx);

    /* Remove sessions from queues */
#if USE_HASHTABLE_FOR_ACTIVE_SESSION
    cur = TAILQ_FIRST(&ctx->free_session_q);

    while (cur != NULL) {
        next = (tcp_connection_t *)TAILQ_NEXT((tcp_connection_t *)cur,
                                              free_session_link);
        TAILQ_REMOVE(&ctx->free_session_q, (tcp_connection_t *)cur,
                     free_session_link);
        cur = next;
    }

#else  /* !USE_HASHTABLE_FOR_ACTIVE_SESSION */
    cur = TAILQ_FIRST(&ctx->active_session_q);

    while (cur != NULL) {
        next = (tcp_connection_t *)TAILQ_NEXT((tcp_connection_t *)cur,
                                              active_session_link);
        TAILQ_REMOVE(&ctx->active_session_q, (tcp_connection_t *)cur,
                     active_session_link);
        cur = next;
    }
#endif /* !USE_HASHTABLE_FOR_ACTIVE_SESSION */

    /* Destroy each session */
    for (i = 0; i < local_max_conn; i++) {
        tcp = ctx->tcp_array[i];
        sess = tcp->ssl_session;

        /* Destroy SSL session */

        /* Free meta header */
        if (sess->meta_hdr) {
            free(sess->meta_hdr);
        }

        /* Free RSA operand metadata buffer */
        if (sess->rsa_operand) {
            if (sess->rsa_operand->buf_ptr)
                free(sess->rsa_operand->buf_ptr);
            free(sess->rsa_operand);
        }

        /* Remove records from recv queue */
        cur = TAILQ_FIRST(&sess->recv_q);

        while (cur != NULL) {
            next = (record_t *)TAILQ_NEXT((record_t *)cur, recv_q_link);
            TAILQ_REMOVE(&sess->recv_q, (record_t *)cur, recv_q_link);
            cur = next;
        }

        /* Destroy SSL session */
        free(sess);

        /* Destroy sessions */
        free(tcp);
    }

    free(ctx->tcp_array);

    /* Remove records and ops from their pools. */
    cur = TAILQ_FIRST(&ctx->op_pool);

    while (cur != NULL) {
        next =
            (ssl_crypto_op_t *)TAILQ_NEXT((ssl_crypto_op_t *)cur, op_pool_link);
        TAILQ_REMOVE(&ctx->op_pool, (ssl_crypto_op_t *)cur, op_pool_link);
        cur = next;
    }

    cur = TAILQ_FIRST(&ctx->record_pool);

    while (cur != NULL) {
        next = (record_t *)TAILQ_NEXT((record_t *)cur, record_pool_link);
        TAILQ_REMOVE(&ctx->record_pool, (record_t *)cur, record_pool_link);
        cur = next;
    }

    /* Free ops and records */
    cur = TAILQ_FIRST(&ctx->whole_op);

    while (cur != NULL) {
        next = (ssl_crypto_op_t *)TAILQ_NEXT((ssl_crypto_op_t *)cur,
                                             op_trace_link);
        TAILQ_REMOVE(&ctx->whole_op, (ssl_crypto_op_t *)cur, op_trace_link);
        free(cur);
        cur = next;
    }

    cur = TAILQ_FIRST(&ctx->whole_record);

    while (cur != NULL) {
        next = (record_t *)TAILQ_NEXT((record_t *)cur, record_trace_link);
        TAILQ_REMOVE(&ctx->whole_record, (record_t *)cur, record_trace_link);
        free(cur);
        cur = next;
    }

    /* Free dpdk private context */
    RTE_ETH_FOREACH_DEV(port)
    {
        if (dpc->rmbufs[port].len != 0) {
            free_pkts(dpc->rmbufs[port].m_table, dpc->rmbufs[port].len);
            dpc->rmbufs[port].len = 0;
        }
    }

    rte_mempool_free(dpc->pktmbuf_pool);
    free(ctx->dpc);

    /* Free thread context */
    free(ctx);
}

static void
remove_session(ssl_session_t *sess)
{
    /* DEBUG_PRINT("[remove_session] [core %u]\n", rte_lcore_id()); */
#if VERBOSE_TCP_HS || VERBOSE_CONN_LAT
    num_completed_sess[sess->ctx->coreid]++;
#endif /* VERBOSE_TCP_HS || VERBOSE_CONN_LAT */

#if VERBOSE_CONN_LAT
    struct timespec conn_end_time;
    clock_gettime(CLOCK_MONOTONIC, &conn_end_time);
    uint64_t conn_lat =
        (conn_end_time.tv_sec - sess->parent->conn_start_time.tv_sec) *
            1000000000L +
        (conn_end_time.tv_nsec - sess->parent->conn_start_time.tv_nsec);

    if (conn_lat > max_conn_lat[sess->coreid]) {
        max_conn_lat[sess->coreid] = conn_lat;
    }

    sum_conn_lat[sess->coreid] += conn_lat;

    uint64_t app_data_lat =
        (conn_end_time.tv_sec - sess->meta_rx_time.tv_sec) * 1000000000L +
        (conn_end_time.tv_nsec - sess->meta_rx_time.tv_nsec);

    if (app_data_lat > max_app_data_lat[sess->coreid]) {
        max_app_data_lat[sess->coreid] = app_data_lat;
    }

    sum_app_data_lat[sess->coreid] += app_data_lat;
    num_app_data[sess->coreid]++;
#endif /* VERBOSE_CONN_LAT */

    thread_context_t *ctx = ctx_array[sess->coreid];

    assert(ctx->active_cnt > 0);

#if USE_HASHTABLE_FOR_ACTIVE_SESSION
    ht_remove(ctx->active_session_table, sess->parent);
#else  /* !USE_HASHTABLE_FOR_ACTIVE_SESSION */
    TAILQ_REMOVE(&ctx->active_session_q, sess->parent, active_session_link);
#endif /* !USE_HASHTABLE_FOR_ACTIVE_SESSION */

    ctx->active_cnt--;

    /* Destroy SSL session */
    clear_ssl_session(sess);
    clear_tcp_connection(sess->parent);

    /* Insert back to free session queue */
    TAILQ_INSERT_TAIL(&ctx->free_session_q, sess->parent, free_session_link);
    ctx->free_cnt++;
}

int
abort_session(ssl_session_t *sess)
{
    fprintf(stderr, "abort session called!\n");
    /* Send RST packet */
    if (unlikely(send_tcp_packet(sess->parent, NULL, 0,
                                 TCP_FLAG_RST | TCP_FLAG_ACK, 0) < 0)) {
        fprintf(stderr, "sending reset packet error!\n");
        return -1;
    }

    remove_session(sess);

    return 0;
}

static int
send_synack_packet(uint16_t core_id, uint16_t port, struct rte_ether_hdr *ethh,
                   struct rte_ipv4_hdr *iph, struct rte_tcp_hdr *tcph,
                   uint32_t cookie)
{
    uint32_t seq_no = ntohl(tcph->sent_seq);

    uint8_t *option;
    uint16_t option_len;
    uint8_t *payload;
    int i;

    option = (uint8_t *)(tcph + 1);
    payload = (uint8_t *)tcph + ((tcph->data_off & 0xf0) >> 2);

    option_len = payload - option;

    uint8_t *buf;

    buf = get_wptr(core_id, port, TOTAL_HEADER_LEN + option_len, 1, option_len);
    if (unlikely(!buf)) {
        fprintf(stderr, "Allocating memory for syn-ack failed.\n");
        exit(EXIT_FAILURE);
    }

    struct rte_ether_hdr *syn_ethh = (struct rte_ether_hdr *)buf;
    struct rte_ipv4_hdr *syn_iph = (struct rte_ipv4_hdr *)(syn_ethh + 1);
    struct rte_tcp_hdr *syn_tcph = (struct rte_tcp_hdr *)(syn_iph + 1);

    uint8_t *syn_option;

    /* update dst & src MAC address */
    for (i = 0; i < 6; i++) {
        syn_ethh->dst_addr.addr_bytes[i] = ethh->src_addr.addr_bytes[i];
        syn_ethh->src_addr.addr_bytes[i] = ethh->dst_addr.addr_bytes[i];
    }
    syn_ethh->ether_type = ethh->ether_type;

    /* update ip address */
    syn_iph->dst_addr = iph->src_addr;
    syn_iph->src_addr = iph->dst_addr;

    syn_iph->version_ihl = 0x45;
    syn_iph->type_of_service = 0x00;
    syn_iph->total_length = htons(IP_HEADER_LEN + TCP_HEADER_LEN);
    // syn_iph->packet_id = htons(per_core_packet_id[core_id]++);
    syn_iph->packet_id = (uint16_t)rand();
    syn_iph->fragment_offset = htons(0x4000);
    syn_iph->time_to_live = 0x40;
    syn_iph->next_proto_id = IPPROTO_TCP;

    /* update tcp port */
    syn_tcph->dst_port = tcph->src_port;
    syn_tcph->src_port = tcph->dst_port;

    /* update tcp flags */
    syn_tcph->tcp_flags = TCP_FLAG_SYN | TCP_FLAG_ACK;

    syn_tcph->rx_win = tcph->rx_win;

    /* update seq and ack */
    syn_tcph->recv_ack = htonl(seq_no + 1);
    syn_tcph->sent_seq = htonl(cookie);
    syn_tcph->data_off = ((TCP_HEADER_LEN) >> 2) << 4;

    /* Attach option */
    syn_iph->total_length = htons(IP_HEADER_LEN + TCP_HEADER_LEN + option_len);
    syn_option = (uint8_t *)(syn_tcph + 1);

    // rdtsc()
    memcpy(syn_option, option, option_len);
    syn_tcph->data_off = ((TCP_HEADER_LEN + option_len) >> 2) << 4;

#if VERBOSE_TCP
    char syn_dst_hw[20];
    char syn_src_hw[20];

    memset(syn_dst_hw, 0, 10);
    memset(syn_src_hw, 0, 10);

    sprintf(syn_dst_hw, "%x:%x:%x:%x:%x:%x", syn_ethh->dst_addr.addr_bytes[0],
            syn_ethh->dst_addr.addr_bytes[1], syn_ethh->dst_addr.addr_bytes[2],
            syn_ethh->dst_addr.addr_bytes[3], syn_ethh->dst_addr.addr_bytes[4],
            syn_ethh->dst_addr.addr_bytes[5]);

    sprintf(syn_src_hw, "%x:%x:%x:%x:%x:%x", syn_ethh->src_addr.addr_bytes[0],
            syn_ethh->src_addr.addr_bytes[1], syn_ethh->src_addr.addr_bytes[2],
            syn_ethh->src_addr.addr_bytes[3], syn_ethh->src_addr.addr_bytes[4],
            syn_ethh->src_addr.addr_bytes[5]);

    fprintf(stderr,
            "\nSYN-ACK Sending Info---------------------------------\n"
            "core: %d\n"
            "dest hwaddr: %s\n"
            "source hwaddr: %s\n"
            "%x : %u -> %x : %u, id: %u\n"
            "len: %d, seq: %u, ack: %u, flag: %x\n\n",
            core_id, syn_dst_hw, syn_src_hw, ntohl(syn_iph->src_addr),
            ntohs(syn_tcph->src_port), ntohl(syn_iph->dst_addr),
            ntohs(syn_tcph->dst_port), ntohs(syn_iph->packet_id),
            TOTAL_HEADER_LEN + option_len, ntohl(syn_tcph->sent_seq),
            ntohl(syn_tcph->recv_ack), syn_tcph->tcp_flags);

    hex_dump(buf, TOTAL_HEADER_LEN + option_len);
#endif /* VERBOSE_TCP */

#if VERBOSE_TCP_HS
    num_sent_synack[core_id]++;
#endif /* VERBOSE_TCP_HS */

    return TOTAL_HEADER_LEN + option_len;
}

static int
send_synack_packet_for_saved_new_syn(uint16_t core_id, uint16_t port,
                                     struct rte_ether_hdr *ethh,
                                     struct rte_ipv4_hdr *iph,
                                     struct rte_tcp_hdr *tcph, uint8_t *option,
                                     uint16_t option_len, uint32_t cookie)
{
    uint32_t seq_no = ntohl(tcph->sent_seq);
    int i;

    uint8_t *buf;

    buf = get_wptr(core_id, port, TOTAL_HEADER_LEN + option_len, 1, option_len);
    if (unlikely(!buf)) {
        fprintf(stderr, "Allocating memory for syn-ack failed.\n");
        exit(EXIT_FAILURE);
    }

    struct rte_ether_hdr *syn_ethh = (struct rte_ether_hdr *)buf;
    struct rte_ipv4_hdr *syn_iph = (struct rte_ipv4_hdr *)(syn_ethh + 1);
    struct rte_tcp_hdr *syn_tcph = (struct rte_tcp_hdr *)(syn_iph + 1);

    uint8_t *syn_option;

    /* update dst & src MAC address */
    for (i = 0; i < 6; i++) {
        syn_ethh->dst_addr.addr_bytes[i] = ethh->src_addr.addr_bytes[i];
        syn_ethh->src_addr.addr_bytes[i] = ethh->dst_addr.addr_bytes[i];
    }
    syn_ethh->ether_type = ethh->ether_type;

    /* update ip address */
    syn_iph->dst_addr = iph->src_addr;
    syn_iph->src_addr = iph->dst_addr;

    syn_iph->version_ihl = 0x45;
    syn_iph->type_of_service = 0x00;
    syn_iph->total_length = htons(IP_HEADER_LEN + TCP_HEADER_LEN);
    // syn_iph->packet_id = htons(per_core_packet_id[core_id]++);
    syn_iph->packet_id = (uint16_t)rand();
    syn_iph->fragment_offset = htons(0x4000);
    syn_iph->time_to_live = 0x40;
    syn_iph->next_proto_id = IPPROTO_TCP;

    /* update tcp port */
    syn_tcph->dst_port = tcph->src_port;
    syn_tcph->src_port = tcph->dst_port;

    /* update tcp flags */
    syn_tcph->tcp_flags = TCP_FLAG_SYN | TCP_FLAG_ACK;

    syn_tcph->rx_win = tcph->rx_win;

    /* update seq and ack */
    syn_tcph->recv_ack = htonl(seq_no + 1);
    syn_tcph->sent_seq = htonl(cookie);
    syn_tcph->data_off = ((TCP_HEADER_LEN) >> 2) << 4;

    /* Attach option */
    syn_iph->total_length = htons(IP_HEADER_LEN + TCP_HEADER_LEN + option_len);
    syn_option = (uint8_t *)(syn_tcph + 1);

    // rdtsc()
    memcpy(syn_option, option, option_len);
    syn_tcph->data_off = ((TCP_HEADER_LEN + option_len) >> 2) << 4;

#if VERBOSE_TCP
    char syn_dst_hw[20];
    char syn_src_hw[20];

    memset(syn_dst_hw, 0, 10);
    memset(syn_src_hw, 0, 10);

    sprintf(syn_dst_hw, "%x:%x:%x:%x:%x:%x", syn_ethh->dst_addr.addr_bytes[0],
            syn_ethh->dst_addr.addr_bytes[1], syn_ethh->dst_addr.addr_bytes[2],
            syn_ethh->dst_addr.addr_bytes[3], syn_ethh->dst_addr.addr_bytes[4],
            syn_ethh->dst_addr.addr_bytes[5]);

    sprintf(syn_src_hw, "%x:%x:%x:%x:%x:%x", syn_ethh->src_addr.addr_bytes[0],
            syn_ethh->src_addr.addr_bytes[1], syn_ethh->src_addr.addr_bytes[2],
            syn_ethh->src_addr.addr_bytes[3], syn_ethh->src_addr.addr_bytes[4],
            syn_ethh->src_addr.addr_bytes[5]);

    fprintf(stderr,
            "\nSYN-ACK Sending Info---------------------------------\n"
            "core: %d\n"
            "dest hwaddr: %s\n"
            "source hwaddr: %s\n"
            "%x : %u -> %x : %u, id: %u\n"
            "len: %d, seq: %u, ack: %u, flag: %x\n\n",
            core_id, syn_dst_hw, syn_src_hw, ntohl(syn_iph->src_addr),
            ntohs(syn_tcph->src_port), ntohl(syn_iph->dst_addr),
            ntohs(syn_tcph->dst_port), ntohs(syn_iph->packet_id),
            TOTAL_HEADER_LEN + option_len, ntohl(syn_tcph->sent_seq),
            ntohl(syn_tcph->recv_ack), syn_tcph->tcp_flags);

    hex_dump(buf, TOTAL_HEADER_LEN + option_len);
#endif /* VERBOSE_TCP */

#if VERBOSE_TCP_HS
    num_sent_synack[core_id]++;
#endif /* VERBOSE_TCP_HS */

    // fprintf(stderr, "send_synack_packet_for_saved_new_syn called! - "
    //                 "client ip: %08x, client port: %u\n"
    //                 "packet id: %u (%02x)\n",
    //                 ntohl(iph->src_addr), ntohs(tcph->src_port),
    //                 ntohs(syn_iph->packet_id), ntohs(syn_iph->packet_id));

    return TOTAL_HEADER_LEN + option_len;
}

#if LINUX_TCP_SERVER
int
send_key_meta(int core_id, int port, tcp_connection_t *conn)
{
#if VERBOSE_META_PKT
    /* for debugging */
    num_sent_meta[core_id]++;
#endif /* VERBOSE_META_PKT */

#if VERBOSE_CONN_LAT
    clock_gettime(CLOCK_MONOTONIC, &conn->ssl_session->meta_tx_time);
    uint64_t cal_app_key_meta_tx_lat =
        (conn->ssl_session->meta_tx_time.tv_sec -
         conn->ssl_session->cal_app_key_time.tv_sec) *
            1000000000L +
        (conn->ssl_session->meta_tx_time.tv_nsec -
         conn->ssl_session->cal_app_key_time.tv_nsec);

    if (cal_app_key_meta_tx_lat > max_cal_app_key_meta_tx_lat[conn->coreid]) {
        max_cal_app_key_meta_tx_lat[conn->coreid] = cal_app_key_meta_tx_lat;
    }

    sum_cal_app_key_meta_tx_lat[conn->coreid] += cal_app_key_meta_tx_lat;
    num_meta_tx[conn->coreid]++;
#endif /* VERBOSE_CONN_LAT */

    static const uint16_t key_eth_types[] = {
        KEY_META_ETH_TYPE_0,  KEY_META_ETH_TYPE_1,  KEY_META_ETH_TYPE_2,
        KEY_META_ETH_TYPE_3,  KEY_META_ETH_TYPE_4,  KEY_META_ETH_TYPE_5,
        KEY_META_ETH_TYPE_6,  KEY_META_ETH_TYPE_7,  KEY_META_ETH_TYPE_8,
        KEY_META_ETH_TYPE_9,  KEY_META_ETH_TYPE_10, KEY_META_ETH_TYPE_11,
        KEY_META_ETH_TYPE_12, KEY_META_ETH_TYPE_13, KEY_META_ETH_TYPE_14,
        KEY_META_ETH_TYPE_15,
    };

    int mac_len = 12;
    int eth_type_len = 2;
    int client_port_len = 2;
    int byte_of_send_buffer_offset = 4;
    int total_len = mac_len + eth_type_len + client_port_len +
                    sizeof(conn_meta_t) + byte_of_send_buffer_offset +
                    conn->ssl_session->send_buffer_offset;

    meta_hdr_t *meta_hdr = conn->ssl_session->meta_hdr;

    uint16_t idx = conn->client_port % (host_threads_num);

    meta_hdr->client_ip = conn->client_ip;
    meta_hdr->server_ip = conn->server_ip;
    meta_hdr->client_port = conn->client_port;
    meta_hdr->server_port = conn->server_port;
    meta_hdr->server_seq_num =
        htonl(conn->last_recv_ack + conn->ssl_session->send_buffer_offset);
    meta_hdr->server_ack_num =
        htonl(conn->last_recv_seq + conn->last_recv_len + 80);

    meta_hdr->custom_eth_type = htons(key_eth_types[idx]);

    // fprintf(stderr, "eth type: %d\n", meta_hdr->custom_eth_type);

    build_connection_meta(conn->ssl_session, &meta_hdr->conn_meta);

    uint8_t *buf = get_wptr(core_id, port, sizeof(meta_hdr_t), 0, 0);
    if (unlikely(!buf)) {
        fprintf(stderr, "Allocating memory for meta packet failed.\n");
        return -1;
    }

    memcpy(buf, meta_hdr, sizeof(meta_hdr_t));

#if VERBOSE_TCP
    else
    {
        fprintf(stderr,
                "\nTCP/TLS Meta Sending Info---------------------------------\n"
                "core: %d\n"
                "ip: %u.%u.%u.%u\n"
                "port: %u -> %u\n"
                "eth type: %02x%02x\n"
                "total_len: %d\n",
                core_id, ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3],
                (port_info[0] << 8) | port_info[1],
                (port_info[2] << 8) | port_info[3], buf[mac_len],
                buf[mac_len + 1], total_len);
    }
#endif /* VERBOSE_TCP */

    return 0;
}

int
send_rst_conn_meta(int core_id, int port, tcp_connection_t *conn)
{
#if VERBOSE_META_PKT
    /* for debugging */
    num_sent_meta[core_id]++;
#endif /* VERBOSE_META_PKT */

    // fprintf(stderr, "send_rst_conn_meta called! - "
    //                 "client ip: %08x, client port: %u\n",
    //                 ntohl(conn->client_ip), ntohs(conn->client_port));

    /* Vars for TCP meta info */
    int mac_len = 12;
    int eth_type_len = 2;
    int client_port_len = 2;
    int byte_of_send_buffer_offset = 4;
    int total_len = mac_len + eth_type_len + client_port_len +
                    sizeof(conn_meta_t) + byte_of_send_buffer_offset +
                    conn->ssl_session->send_buffer_offset;

    meta_hdr_t *meta_hdr = conn->ssl_session->meta_hdr;

    meta_hdr->client_ip = conn->client_ip;
    meta_hdr->client_port = conn->client_port;

    meta_hdr->server_seq_num =
        htonl(conn->last_recv_ack + conn->ssl_session->send_buffer_offset);
    meta_hdr->server_ack_num = htonl(conn->last_recv_seq + conn->last_recv_len);

    // fprintf(stderr, "send_key_meta: server_seq_num = 0x%08x, last_recv_ack =
    // 0x%08x\n",
    //                 meta_hdr->server_seq_num,
    //                 meta_hdr->server_ack_num);

    meta_hdr->custom_eth_type = htons(RST_CONN_META_ETH_TYPE);

    build_connection_meta(conn->ssl_session, &meta_hdr->conn_meta);

    uint8_t *buf = get_wptr(core_id, port, sizeof(meta_hdr_t), 0, 0);
    if (unlikely(!buf)) {
        fprintf(stderr, "Allocating memory for meta packet failed.\n");
        return -1;
    }

    memcpy(buf, meta_hdr, sizeof(meta_hdr_t));

#if VERBOSE_TCP
    else
    {
        fprintf(stderr,
                "\nTCP/TLS Meta Sending Info---------------------------------\n"
                "core: %d\n"
                "ip: %u.%u.%u.%u\n"
                "port: %u -> %u\n"
                "eth type: %02x%02x\n"
                "total_len: %d\n",
                core_id, ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3],
                (port_info[0] << 8) | port_info[1],
                (port_info[2] << 8) | port_info[3], buf[mac_len],
                buf[mac_len + 1], total_len);
    }
#endif /* VERBOSE_TCP */

    return 0;
}
#else /* !LINUX_TCP_SERVER */
int
send_key_meta(int coreid, int port, tcp_connection_t *conn,
              uint32_t next_recv_seq, uint32_t next_recv_ack, uint8_t *payload,
              uint16_t payload_len)
{

    uint8_t *buf;
    struct rte_ether_hdr *ethh;
    struct rte_ipv4_hdr *iph;
    struct rte_tcp_hdr *tcph;
#if VERBOSE_TCP
    char dst_hw[20];
    char src_hw[20];
#endif /* VERBOSE_TCP */
    int send_cnt;

    buf = get_wptr(coreid, port, TOTAL_HEADER_LEN + payload_len, 0,
                   TCP_HEADER_LEN);
    assert(buf != NULL);

    ethh = (struct rte_ether_hdr *)buf;

    int i;

    for (i = 0; i < 6; i++) {
        ethh->dst_addr.addr_bytes[i] = conn->server_mac[i];
        ethh->src_addr.addr_bytes[i] = conn->client_mac[i];
    }

    ethh->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    iph = (struct rte_ipv4_hdr *)(ethh + 1);
    iph->version_ihl = 0x45;
    iph->type_of_service = 0xff;
    iph->total_length = htons(IP_HEADER_LEN + TCP_HEADER_LEN + payload_len);
    iph->packet_id = 0;
    iph->fragment_offset = htons(0x4000);
    iph->time_to_live = 0x40;
    iph->next_proto_id = IPPROTO_TCP;
    iph->src_addr = conn->client_ip;
    iph->dst_addr = conn->server_ip;

    tcph = (struct rte_tcp_hdr *)(iph + 1);

    tcph->src_port = conn->client_port;
    tcph->dst_port = conn->server_port;
    tcph->tcp_flags = 0;

    tcph->recv_ack = next_recv_ack;
    tcph->sent_seq = next_recv_seq;

    tcph->data_off = (TCP_HEADER_LEN >> 2) << 4;
    tcph->rx_win = conn->window;
    tcph->cksum = 0;

    if (payload_len > 0)
        memcpy((uint8_t *)tcph + TCP_HEADER_LEN, payload, payload_len);

    /* Send Immediately */
    send_cnt = send_pkts(coreid, port);

    if (unlikely(!send_cnt)) {
        fprintf(stderr, "Why no packets are sent?");
        exit(EXIT_FAILURE);
    }
#if VERBOSE_TCP
    else {
        sprintf(dst_hw, "%x:%x:%x:%x:%x:%x", ethh->dst_addr.addr_bytes[0],
                ethh->dst_addr.addr_bytes[1], ethh->dst_addr.addr_bytes[2],
                ethh->dst_addr.addr_bytes[3], ethh->dst_addr.addr_bytes[4],
                ethh->dst_addr.addr_bytes[5]);

        sprintf(src_hw, "%x:%x:%x:%x:%x:%x", ethh->src_addr.addr_bytes[0],
                ethh->src_addr.addr_bytes[1], ethh->src_addr.addr_bytes[2],
                ethh->src_addr.addr_bytes[3], ethh->src_addr.addr_bytes[4],
                ethh->src_addr.addr_bytes[5]);

        fprintf(stderr,
                "\nMeta Sending Info---------------------------------\n"
                "core: %d\n"
                "dest hwaddr: %s\n"
                "source hwaddr: %s\n"
                "%x : %u -> %x : %u, "
                "id: %u\n"
                "next_recv_seq: %u, next_recv_ack: %u, flag: %x\n\n"
                "total_len: %d, payload_len: %d\n",
                coreid, dst_hw, src_hw, ntohl(iph->src_addr),
                ntohs(tcph->src_port), ntohl(iph->dst_addr),
                ntohs(tcph->dst_port), ntohs(iph->packet_id),
                ntohl(tcph->sent_seq), ntohl(tcph->recv_ack), tcph->tcp_flags,
                TOTAL_HEADER_LEN + payload_len, payload_len);
    }
#endif /* VERBOSE_TCP */

    return 0;
}
#endif /* !LINUX_TCP_SERVER */

static int
send_raw_reset(int coreid, int portid, const uint8_t *hw_src,
               const uint8_t *hw_dst, uint32_t ip_src, uint32_t ip_dst,
               uint16_t tcp_src, uint16_t tcp_dst, uint32_t seq, uint32_t ack)
{
    int i;
    uint8_t *buf;
    struct rte_ether_hdr *ethh;
    struct rte_ipv4_hdr *iph;
    struct rte_tcp_hdr *tcph;

#if VERBOSE_TCP
    char dst_hw[20];
    char src_hw[20];
#endif /* VERBOSE_TCP */

    buf = get_wptr(coreid, portid, TOTAL_HEADER_LEN, 1, TCP_HEADER_LEN);
    assert(buf != NULL);

    ethh = (struct rte_ether_hdr *)buf;
    for (i = 0; i < 6; i++) {
        ethh->dst_addr.addr_bytes[i] = hw_dst[i];
        ethh->src_addr.addr_bytes[i] = hw_src[i];
    }
    ethh->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    iph = (struct rte_ipv4_hdr *)(ethh + 1);
    iph->version_ihl = 69;
    iph->type_of_service = 0;
    iph->total_length = htons(IP_HEADER_LEN + TCP_HEADER_LEN);
    iph->packet_id = htons(0xffff);
    iph->fragment_offset = htons(0x4000);
    iph->time_to_live = 64;
    iph->next_proto_id = IPPROTO_TCP;
    iph->src_addr = ip_src;
    iph->dst_addr = ip_dst;

    tcph = (struct rte_tcp_hdr *)(iph + 1);

    tcph->src_port = tcp_src;
    tcph->dst_port = tcp_dst;
    tcph->tcp_flags = TCP_FLAG_RST | TCP_FLAG_ACK;

    tcph->recv_ack = htonl(ack);
    tcph->sent_seq = htonl(seq);

    tcph->data_off = (TCP_HEADER_LEN >> 2) << 4;
    tcph->rx_win = htons(8192);

#if VERBOSE_TCP
    sprintf(dst_hw, "%x:%x:%x:%x:%x:%x", ethh->dst_addr.addr_bytes[0],
            ethh->dst_addr.addr_bytes[1], ethh->dst_addr.addr_bytes[2],
            ethh->dst_addr.addr_bytes[3], ethh->dst_addr.addr_bytes[4],
            ethh->dst_addr.addr_bytes[5]);

    sprintf(src_hw, "%x:%x:%x:%x:%x:%x", ethh->src_addr.addr_bytes[0],
            ethh->src_addr.addr_bytes[1], ethh->src_addr.addr_bytes[2],
            ethh->src_addr.addr_bytes[3], ethh->src_addr.addr_bytes[4],
            ethh->src_addr.addr_bytes[5]);

    fprintf(stderr,
            "\nReset Sending Info---------------------------------\n"
            "core: %d\n"
            "dest hwaddr: %s\n"
            "source hwaddr: %s\n"
            "%x : %u -> %x : %u, "
            "id: %u\n"
            "seq: %u, ack: %u, flag: %x\n\n",
            coreid, dst_hw, src_hw, ntohl(iph->src_addr), ntohs(tcph->src_port),
            ntohl(iph->dst_addr), ntohs(tcph->dst_port), ntohs(iph->packet_id),
            ntohl(tcph->sent_seq), ntohl(tcph->recv_ack), tcph->tcp_flags);
#endif /* VERBOSE_TCP */

    return 0;
}

int
send_tcp_packet(tcp_connection_t *conn, uint8_t *payload, uint16_t payload_len,
                uint8_t flags, uint8_t offl_flag)
{

    int i;
    uint8_t *buf;
    struct rte_ether_hdr *ethh;
    struct rte_ipv4_hdr *iph;
    struct rte_tcp_hdr *tcph;

#if VERBOSE_TCP
    char send_dst_hw[20];
    char send_src_hw[20];
#endif /* VERBOSE_TCP */

    int left_to_send = payload_len;
    int already_to_send = 0;
    int byte_to_send;

    do {
        byte_to_send =
            MIN(left_to_send, MAX_PKT_SIZE - IP_HEADER_LEN - TCP_HEADER_LEN);

#if OFFLOAD_AES_GCM
        if (offl_flag & TCP_OFFL_TLS_AES) {
            struct rte_mbuf *mbuf;

            if (byte_to_send != left_to_send) {
                fprintf(stderr, "error: can't process TLS AES offl!\n");
                exit(EXIT_FAILURE);
            }

            mbuf = get_wmbuf(conn->coreid, conn->portid,
                             TOTAL_HEADER_LEN + byte_to_send);
            mbuf->l2_len = ETHERNET_HEADER_LEN;
            mbuf->l3_len = IP_HEADER_LEN;
            mbuf->l4_len = TCP_HEADER_LEN;
            mbuf->tso_segsz = MAX_PKT_SIZE - (mbuf->l3_len + mbuf->l4_len);

            mbuf->tls_ctx = &conn->ssl_session->tls_ctx;
            buf = rte_pktmbuf_mtod(mbuf, uint8_t *);
        } else {
            buf = get_wptr(conn->coreid, conn->portid,
                           TOTAL_HEADER_LEN + byte_to_send, 1, TCP_HEADER_LEN);
        }
#else  /* OFFLOAD_AES_GCM */
        buf = get_wptr(conn->coreid, conn->portid,
                       TOTAL_HEADER_LEN + byte_to_send, 1, TCP_HEADER_LEN);
#endif /* !OFFLOAD_AES_GCM */

        assert(buf != NULL);

        ethh = (struct rte_ether_hdr *)buf;

        memcpy(ethh->dst_addr.addr_bytes, conn->client_mac, 6);
        memcpy(ethh->src_addr.addr_bytes, conn->server_mac, 6);

        ethh->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

        iph = (struct rte_ipv4_hdr *)(ethh + 1);
        iph->version_ihl = 0x45;
        iph->type_of_service = 0x00;
        iph->total_length =
            htons(IP_HEADER_LEN + TCP_HEADER_LEN + byte_to_send);
        iph->packet_id = htons(conn->ip_id++);
        iph->fragment_offset = htons(0x4000);
        iph->time_to_live = 0x40;
        iph->next_proto_id = IPPROTO_TCP;
        iph->src_addr = conn->server_ip;
        iph->dst_addr = conn->client_ip;

        tcph = (struct rte_tcp_hdr *)(iph + 1);

        tcph->src_port = conn->server_port;
        tcph->dst_port = conn->client_port;
        tcph->tcp_flags = flags;

        /* Now the tcp connection should be always "TCP_SESSION_RECEIVED" */
        // tcph->recv_ack = htonl(conn->last_recv_seq + conn->last_recv_len);
        uint32_t recv_ack = conn->last_recv_seq + conn->last_recv_len;
        if (conn->ssl_session->state == STATE_ACTIVE &&
            conn->last_recv_len > 126)
            recv_ack -= 126;
        tcph->recv_ack = htonl(recv_ack);

#if OFFLOAD_AES_GCM
        tcph->sent_seq = htonl(MAX(conn->last_recv_ack, conn->next_sent_seq) +
                               already_to_send);
#else  /* OFFLOAD_AES_GCM */
        tcph->sent_seq = htonl(conn->last_recv_ack + already_to_send);
#endif /* !OFFLOAD_AES_GCM */

        conn->last_sent_seq = ntohl(tcph->sent_seq);
        conn->last_sent_ack = ntohl(tcph->recv_ack);

        tcph->data_off = (TCP_HEADER_LEN >> 2) << 4;
        if (byte_to_send > 0)
            memcpy((uint8_t *)tcph + TCP_HEADER_LEN, payload + already_to_send,
                   byte_to_send);

        conn->last_sent_len = byte_to_send;

        tcph->rx_win = htons(8192);

        conn->total_sent += byte_to_send;
        conn->state = TCP_SESSION_SENT;

        /* Intended Packet Drop */
#if 0
		if ((conn->ssl_session->handshake_state == SERVER_CIPHER_SPEC) && test_flag) {
			memset(buf, 0, TOTAL_HEADER_LEN + byte_to_send);
			test_flag = 0;
		}
#endif /* 0 */

#if VERBOSE_TCP
        memset(send_dst_hw, 0, 10);
        memset(send_src_hw, 0, 10);

        sprintf(send_dst_hw, "%x:%x:%x:%x:%x:%x", ethh->dst_addr.addr_bytes[0],
                ethh->dst_addr.addr_bytes[1], ethh->dst_addr.addr_bytes[2],
                ethh->dst_addr.addr_bytes[3], ethh->dst_addr.addr_bytes[4],
                ethh->dst_addr.addr_bytes[5]);

        sprintf(send_src_hw, "%x:%x:%x:%x:%x:%x", ethh->src_addr.addr_bytes[0],
                ethh->src_addr.addr_bytes[1], ethh->src_addr.addr_bytes[2],
                ethh->src_addr.addr_bytes[3], ethh->src_addr.addr_bytes[4],
                ethh->src_addr.addr_bytes[5]);

        fprintf(stderr,
                "\nPacket Sending Info---------------------------------\n"
                "core: %d, port: %u\n"
                "dest hwaddr: %s\n"
                "source hwaddr: %s\n"
                "%x : %u -> %x : %u, id: %u\n"
                "seq: %u, ack: %u, flag: %x\n"
                "total len: %u, payload_len: %u\n"
                "ssl handshake state: %u\n\n",
                conn->coreid, conn->portid, send_dst_hw, send_src_hw,
                ntohl(iph->src_addr), ntohs(tcph->src_port),
                ntohl(iph->dst_addr), ntohs(tcph->dst_port),
                ntohs(iph->packet_id), ntohl(tcph->sent_seq),
                ntohl(tcph->recv_ack), tcph->tcp_flags,
                TOTAL_HEADER_LEN + byte_to_send, byte_to_send,
                conn->ssl_session->handshake_state);
#endif /* VERBOSE_TCP */

        left_to_send -= byte_to_send;
        already_to_send += byte_to_send;

    } while (left_to_send > 0);

#if OFFLOAD_AES_GCM
    conn->next_sent_seq = conn->last_recv_ack + payload_len;
#endif /* OFFLOAD_AES_GCM */

    return 0;
}

static tcp_connection_t *
insert_tcp_connection(thread_context_t *ctx, uint16_t portid,
                      const unsigned char *client_mac, uint32_t client_ip,
                      uint16_t client_port, const unsigned char *server_mac,
                      uint32_t server_ip, uint16_t server_port, uint32_t seq_no,
                      uint32_t ack_no, uint16_t window, uint16_t payload_len)
{
    tcp_connection_t *target;
    int j;

    target = pop_free_connection(ctx);
    assert(target);
    assert(target->state == TCP_SESSION_IDLE);

    for (j = 0; j < 6; j++) {
        target->client_mac[j] = client_mac[j];
        target->server_mac[j] = server_mac[j];
    }

    target->state = TCP_SESSION_RECEIVED;
    target->portid = portid;

    target->client_ip = client_ip;
    target->client_port = client_port;
    target->server_ip = server_ip;
    target->server_port = server_port;

#if LINUX_TCP_SERVER
    /* Insert session at SYN-received timing */
    /* Make cookie with 4 tuples */
    target->cookie = get_cookie(client_ip, client_port, server_ip, server_port);

    target->last_recv_ack = target->cookie + 1;
    target->last_recv_seq = seq_no + 1;
    target->last_recv_len = payload_len;

    target->last_sent_ack = seq_no + 1;
    target->last_sent_seq = target->cookie;
    target->last_sent_len = 0;
#else  /* !LINUX_TCP_SERVER */
    /* Insert session at ACK-received timing */
    target->last_recv_ack = ack_no;
    target->last_recv_seq = seq_no;
    target->last_recv_len = payload_len;

    target->last_sent_ack = seq_no;
    target->last_sent_seq = cookie;
    target->last_sent_len = 0;
#endif /* !LINUX_TCP_SERVER */

    target->window = window;
    target->ip_id = 1;

#if USE_HASHTABLE_FOR_ACTIVE_SESSION
    ht_insert(ctx->active_session_table, target, ctx);
#else  /* USE_HASHTABLE_FOR_ACTIVE_SESSION */
    TAILQ_INSERT_TAIL(&ctx->active_session_q, target, active_session_link);
#endif /* !USE_HASHTABLE_FOR_ACTIVE_SESSION */

    ctx->active_cnt++;

#if VERBOSE_STAT_0
    ctx->cur_stat.only_tcp++;
#endif /* VERBOSE_STAT_0 */

#if VERBOSE_TCP_HS || VERBOSE_CONN_LAT
    // num_completed_sess[ctx->coreid]++;
#endif /* VERBOSE_TCP_HS || VERBOSE_CONN_LAT */

#if VERBOSE_CONN_LAT
    clock_gettime(CLOCK_MONOTONIC, &target->conn_start_time);
#endif /* VERBOSE_CONN_LAT */

    return target;
}

static tcp_connection_t *
search_tcp_connection(thread_context_t *ctx, uint32_t client_ip,
                      uint16_t client_port, uint32_t server_ip,
                      uint16_t server_port)
{
    tcp_connection_t *target, *ret;

#if USE_HASHTABLE_FOR_ACTIVE_SESSION
    ret = ht_search(ctx->active_session_table, client_ip, client_port,
                    server_ip, server_port);
    UNUSED(target);
#else  /* USE_HASHTABLE_FOR_ACTIVE_SESSION */
    ret = NULL;
    TAILQ_FOREACH(target, &ctx->active_session_q, active_session_link)
    {
        assert(target->state != TCP_SESSION_IDLE);

        if ((target->client_ip == client_ip) &&
            (target->client_port == client_port) &&
            (target->server_ip == server_ip) &&
            (target->server_port == server_port)) {
            ret = target;
            break;
        }
    }
#endif /* !USE_HASHTABLE_FOR_ACTIVE_SESSION */

    return ret;
}

static tcp_connection_t *
pop_free_connection(thread_context_t *ctx)
{
    tcp_connection_t *target;

    target = TAILQ_FIRST(&ctx->free_session_q);
    if (unlikely(!target)) {
        fprintf(stderr, "Not enough session, and this must not happen!\n");
        exit(EXIT_FAILURE);
    }

    TAILQ_REMOVE(&ctx->free_session_q, target, free_session_link);
    ctx->free_cnt--;

    return target;
}

#if !LINUX_TCP_SERVER
static void
process_init_meta(uint8_t *meta_pkt)
{
    meta_hdr_t *metah;
    uint8_t *meta_host_key, *meta_host_iv;

    metah = (meta_hdr_t *)meta_pkt;
    host_key_size = metah->key_size;
    host_iv_size = metah->iv_size;

    meta_host_key = (uint8_t *)(metah + 1);
    meta_host_iv = (uint8_t *)(meta_host_key + host_key_size);

    memcpy(host_key, meta_host_key, host_key_size);
    memcpy(host_iv, meta_host_iv, host_iv_size);

#if VERBOSE_INIT
    fprintf(stderr, "host key (size: %u)\n", host_key_size);
    for (unsigned z = 0; z < host_key_size; z++)
        fprintf(stderr, "%02X%c", host_key[z], ((z + 1) % 16 ? ' ' : '\n'));
    fprintf(stderr, "\n");

    fprintf(stderr, "host iv (size: %u)\n", host_iv_size);
    for (unsigned z = 0; z < host_iv_size; z++)
        fprintf(stderr, "%02X%c", host_iv[z], ((z + 1) % 16 ? ' ' : '\n'));
    fprintf(stderr, "\n");

#endif /* VERBOSE_INIT */
}

static void
send_init_meta(uint16_t core_id, uint16_t port)
{
    uint8_t *buf;
    meta_hdr_t *metah;
    uint8_t *meta_nic_key, *meta_nic_iv;
    uint16_t payload_len;

    payload_len = nic_key_size + nic_iv_size;

    buf = get_wptr(core_id, port, sizeof(meta_hdr_t) + payload_len, 0, 0);

    if (unlikely(!buf)) {
        fprintf(stderr, "Packet Allocation Failed!\n");
        exit(0);
    }

    metah = (meta_hdr_t *)buf;
    metah->key_size = nic_key_size;
    metah->iv_size = nic_iv_size;
    metah->h_proto = rte_cpu_to_be_16(ETHER_TYPE_META);

    meta_nic_key = (uint8_t *)(metah + 1);
    meta_nic_iv = (uint8_t *)(meta_nic_key + nic_key_size);

    memcpy(meta_nic_key, nic_key, nic_key_size);
    memcpy(meta_nic_iv, nic_iv, nic_iv_size);

#if VERBOSE_INIT
    fprintf(stderr, "nic key (size: %u)\n", nic_key_size);
    for (unsigned z = 0; z < nic_key_size; z++)
        fprintf(stderr, "%02X%c", nic_key[z], ((z + 1) % 16 ? ' ' : '\n'));
    fprintf(stderr, "\n");

    fprintf(stderr, "nic iv (size: %u)\n", nic_iv_size);
    for (unsigned z = 0; z < nic_iv_size; z++)
        fprintf(stderr, "%02X%c", nic_iv[z], ((z + 1) % 16 ? ' ' : '\n'));
    fprintf(stderr, "\n");

#endif /* VERBOSE_INIT */
}
#endif /* !LINUX_TCP_SERVER */

static int
validate_packet_type(uint16_t port, uint8_t *pktbuf,
                     uint16_t payload_len) /* TODO: readability */
{
    struct rte_ether_hdr *ethh;
    struct rte_ipv4_hdr *iph;
    struct rte_tcp_hdr *tcph;

    ethh = (struct rte_ether_hdr *)pktbuf;

    if (ethh->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
        iph = (struct rte_ipv4_hdr *)(ethh + 1);
        /* Filtering handshake packet*/
        if (iph->type_of_service == IPTOS_PREC_ROUTINE) {
            if (iph->next_proto_id == IPPROTO_TCP) {
                /* The packet is a TCP packet */
                tcph = (struct rte_tcp_hdr *)(iph + 1);
                if (port % 2 == 0) {
                    if (tcph->dst_port != htons(SSL_PORT)) {
#if VERBOSE_TCP
                        fprintf(stderr, "Only HTTPS is supported\n");
#endif /* VERBOSE_TCP */

                        return -1;
                    }

                    if (payload_len > 0 && payload_len < MAX_HANDSHAKE_LENGTH)
                        return SSL_HANDSHAKE;

                    if ((tcph->tcp_flags & TCP_FLAG_SYN) &&
                        !(tcph->tcp_flags & TCP_FLAG_ACK))
                        return TCP_SYN;

                    if (tcph->tcp_flags & TCP_FLAG_FIN)
                        return TCP_FIN;

                    if (tcph->tcp_flags & TCP_FLAG_RST)
                        return TCP_RST;

                    if ((tcph->tcp_flags & TCP_FLAG_SYN) &&
                        (tcph->tcp_flags & TCP_FLAG_ACK)) {
#if VERBOSE_TCP
                        /* We do not currently support client side */
                        fprintf(stderr, "SYN ACK is not supported\n");
#endif /* VERBOSE_TCP */

                        return TCP_SYNACK;
                    }

                    if (!(tcph->tcp_flags & TCP_FLAG_SYN) &&
                        (tcph->tcp_flags & TCP_FLAG_ACK))
                        return TCP_ACK;
                }
            } else {
#if VERBOSE_TCP
                fprintf(stderr, "\nOnly TCP packet supported\n");
#endif /* VERBOSE_TCP */

                return -1;
            }
        } else {
            if (port % 2 == 1) {
                switch (iph->type_of_service) {
#if LINUX_TCP_SERVER
                case IP_TOS_HOST_MIG_FIN:
                    return HOST_MIG_FIN;
                case IP_TOS_HOST_CLOSE:
                    return HOST_CLOSE;
#else  /* !LINUX_TCP_SERVER */
                case IP_TOS_MTCP_HOST_CLOSE:
                    return MTCP_HOST_CLOSE;
                case IP_TOS_MTCP_TC_RULE:
                    return META_TC_RULE;
#endif /* !LINUX_TCP_SERVER */
                default:
                    return -1;
                }
            }
        }
    }

#if !LINUX_TCP_SERVER
    if (ethh->ether_type == rte_cpu_to_be_16(ETHER_TYPE_META)) {
        return MTCP_META_PACKET;
    }
#endif /* !LINUX_TCP_SERVER */

    return -1;
}

static int /* modified for tls 1.3 */
validate_syn_packet(tcp_connection_t *conn, uint32_t seq_no, uint32_t ack_no)
{
    if ((seq_no + 1) == conn->last_recv_seq) { /* at insert_tcp_connection,
                                                  last_recv_seq is ++ed. */
#if VERBOSE_TCP
        fprintf(stderr, "Retransmitted SYN Packet!\n");
#endif /* VERBOSE_TCP */
        // fprintf(stderr, "Retransmitted SYN Packet!\n");
        // fprintf(stderr, "client port: %u, seq_no: %u, last: %u,\n"
        //         "ack_no: %u, last: %u\n",
        //         htons(conn->client_port));
        return TCP_SYN_RETRANS;
    }

    return TCP_SYN_NEW;
}

static int
validate_sequence(tcp_connection_t *conn, uint32_t seq_no, uint32_t ack_no,
                  uint16_t payload_len)
{
    if (seq_no == conn->last_recv_seq && ack_no == conn->last_recv_ack &&
        payload_len == conn->last_recv_len)
        return TCP_SEQ_OK;

    if (((conn->last_sent_ack == seq_no)) ||
        (conn->last_recv_seq + conn->last_recv_len == seq_no))
        return TCP_SEQ_OK;

#if VERBOSE_TCP
    fprintf(stderr,
            "Invalid Seqence! \n"
            "seq_no: %u\n"
            "should be: %u or %u\n"
            "last_sent_seq: %u, last_sent_ack: %u, last_sent_len: %u\n"
            "last_recv_seq: %u, last_recv_ack: %u, last_recv_len: %u\n",
            seq_no, conn->last_sent_ack,
            conn->last_recv_seq + conn->last_recv_len, conn->last_sent_seq,
            conn->last_sent_ack, conn->last_sent_len, conn->last_recv_seq,
            conn->last_recv_ack, conn->last_recv_len);
#endif /* VERBOSE_TCP */

    // if (SEQ_LT(seq_no, conn->last_recv_seq) ||
    //     SEQ_LT(ack_no, conn->last_recv_ack) ||
    //     (seq_no == conn->last_recv_seq &&
    //     ack_no == conn->last_recv_ack &&
    //     payload_len == conn->last_recv_len))
    //     return TCP_SEQ_UNDER;
    if (SEQ_LT(seq_no, conn->last_recv_seq) ||
        SEQ_LT(ack_no, conn->last_recv_ack))
        return TCP_SEQ_UNDER;

    if (SEQ_GT(seq_no, conn->last_sent_ack) &&
        SEQ_GT(seq_no, (conn->last_recv_seq + conn->last_recv_len))) {
        // fprintf(stderr, "Over Seq Case of client 0x%08x:%u\n"
        //     "Expected seq_no: 0x%08x, ack_no: 0x%08x\n"
        //     "Recv seq: 0x%08x, recv ack: 0x%08x\n",
        //     htonl(conn->client_ip), htons(conn->client_port),
        //     conn->last_recv_seq, conn->last_recv_ack,
        //     seq_no, ack_no
        // );
        return TCP_SEQ_OVER;
    }

    fprintf(stderr, "Weird Sequence Case Detected! (dropped)\n");
    return -1;
}

static void
process_normal_seq_case(tcp_connection_t *result, uint32_t seq_no,
                        uint32_t ack_no, uint8_t *pktbuf, uint8_t *payload,
                        uint16_t payload_len)
{
    int ret;

    /* Handle Established Packet */
    result->last_recv_ack = ack_no;
    result->last_recv_seq = seq_no;
    result->last_recv_len = payload_len;

    result->state = TCP_SESSION_RECEIVED;

    /* Record the time of last response (only for SSL handshake case) */
    clock_gettime(CLOCK_MONOTONIC, &result->last_interaction);

    /* Got a payload */
    if (unlikely(process_ssl_packet(result, payload, payload_len) < 0)) {
        /* We need next packet */
        ret = send_tcp_packet(result, NULL, 0, TCP_FLAG_ACK, 0);

        fprintf(stderr, "We need next packet for SSL processing.\n");

        if (unlikely(ret < 0)) {
            fprintf(stderr, "Sending ACK Failed.\n");
            exit(EXIT_FAILURE);
        }
    }

    return;
}

static void
process_under_seq_case(tcp_connection_t *conn, uint32_t seq_no, uint32_t ack_no,
                       uint16_t payload_len)
{
    int ret;
    return;
}

static void
process_over_seq_case(tcp_connection_t *result)
{
    int ret = 0;

#if VERBOSE_TCP
    fprintf(stderr, "Over Sequence Case\n");
#endif /* VERBOSE_TCP */

    /* Over Seq Case: Intend client retransmission */
    ret = send_tcp_packet(result, NULL, 0, TCP_FLAG_ACK, 0);

    // fprintf(stderr, "ACK for Over Seq Case Sent.\n");

    if (unlikely(ret < 0)) {
        fprintf(stderr, "Sending ACK Failed.\n");
        exit(EXIT_FAILURE);
    }
}

static void
process_weird_seq_case()
{
    // fprintf(stderr, "Weird Sequence Case\n");
    // exit(EXIT_FAILURE);
}

static void
process_handshake_packet(thread_context_t *ctx, uint16_t port, uint8_t *pktbuf,
                         uint8_t *payload, uint16_t payload_len,
                         struct rte_ether_hdr *ethh, struct rte_ipv4_hdr *iph,
                         struct rte_tcp_hdr *tcph, uint32_t seq_no,
                         uint32_t ack_no)
{
    tcp_connection_t *result;
    int seq_case;
    uint8_t *wbuf;

    /* Handle Established Packet */
    result = search_tcp_connection(ctx, iph->src_addr, tcph->src_port,
                                   iph->dst_addr, tcph->dst_port);

    /* Connection is not found */
    if (result == NULL) {
#if VERBOSE_TCP
        /* Weird Packet */
        fprintf(stderr, "Weird Packet!\n"
                        "Maybe the packet of aborted session.\n");
#endif /* VERBOSE_TCP */
        return;
    }

#if ONLOAD
#if !FWD_ONLY_APPDATA
    /* test for forwarding only app data */
    /* Forward onloaded packet */
    if (unlikely(result->onload)) {
        /* The connection is already onloaded to host */
        assert(!(result->portid % 2));

        struct rte_tcp_hdr *tcph =
            (struct rte_tcp_hdr *)(pktbuf + sizeof(struct rte_ether_hdr) +
                                   sizeof(struct rte_ipv4_hdr));

        uint16_t tcp_hdr_len = (tcph->data_off >> 4) << 2;

        uint16_t len = sizeof(struct rte_ether_hdr) +
                       sizeof(struct rte_ipv4_hdr) + tcp_hdr_len + payload_len;

        wbuf =
            get_wptr(result->coreid, result->portid + 1, len, 1, tcp_hdr_len);
        assert(wbuf != NULL);
#if VERBOSE_TCP
        fprintf(stderr,
                "Packet with length %d forwarded from network to host.\n", len);
#endif /* VERBOSE_TCP */

        memcpy(wbuf, pktbuf, len);
        return;
    }
#else  /* !FWD_ONLY_APPDATA */
    if (result->onload) {
        struct rte_tcp_hdr *tcph =
            (struct rte_tcp_hdr *)(pktbuf + sizeof(struct rte_ether_hdr) +
                                   sizeof(struct rte_ipv4_hdr));

        uint16_t tcp_hdr_len = (tcph->data_off >> 4) << 2;

        uint16_t len = sizeof(struct rte_ether_hdr) +
                       sizeof(struct rte_ipv4_hdr) + tcp_hdr_len + payload_len;

        memcpy(result->pending_app_data, pktbuf, len);
        result->pending_app_data_len = len;

        return;
    }
#endif /* !FWD_ONLY_APPDATA */
#else  /* ONLOAD */
    UNUSED(wbuf);
#endif /* !ONLOAD */

    /* Validate sequence number of the packet */
    seq_case = validate_sequence(result, seq_no, ack_no, payload_len);

    switch (seq_case) {
    case TCP_SEQ_OK:
        process_normal_seq_case(result, seq_no, ack_no, pktbuf, payload,
                                payload_len);
        return;
    case TCP_SEQ_UNDER:
        process_under_seq_case(result, seq_no, ack_no, payload_len);
        return;
    case TCP_SEQ_OVER:
        process_over_seq_case(result);
        return;

    default:
        process_weird_seq_case();
        return;
    }
}

static void
save_new_syn(tcp_connection_t *conn, struct rte_ether_hdr *ethh,
             struct rte_ipv4_hdr *iph, struct rte_tcp_hdr *tcph,
             uint16_t payload_len)
{
    conn->pending_syn.ethh = *ethh;
    conn->pending_syn.iph = *iph;
    conn->pending_syn.tcph = *tcph;
    memcpy(conn->pending_syn.tcp_options, (uint8_t *)(tcph + 1),
           (tcph->data_off >> 4) * 4 - TCP_HEADER_LEN);
    conn->pending_syn.tcp_option_len =
        (tcph->data_off >> 4) * 4 - TCP_HEADER_LEN;
    conn->pending_syn.payload_len = payload_len;

    return;
}

static void
process_syn_packet(thread_context_t *ctx, uint16_t port, uint8_t *pktbuf,
                   uint16_t payload_len, uint16_t len,
                   struct rte_ether_hdr *ethh, struct rte_ipv4_hdr *iph,
                   struct rte_tcp_hdr *tcph, uint32_t seq_no, uint32_t ack_no)
{
    tcp_connection_t *result;
    int ret;

#if VERBOSE_TCP_HS
    num_recv_syn[ctx->coreid]++;
#endif /* VERBOSE_TCP_HS */

    /* check if connection is not removed */
    result = search_tcp_connection(ctx, iph->src_addr, tcph->src_port,
                                   iph->dst_addr, tcph->dst_port);

    if (unlikely(result != NULL)) {
#if VERBOSE_TCP
        fprintf(stderr, "Duplicated SYN received!\n");
#endif /* VERBOSE_TCP */

        /* Validate SYN for classifying retransmitted SYN & new SYN */
        ret = validate_syn_packet(result, seq_no, ack_no);

        switch (ret) {
        case TCP_SYN_RETRANS:
            /* Retransmit SYNACK */
            // fprintf(stderr, "retransmit SYNACK\n");
            send_synack_packet(ctx->coreid, port, ethh, iph, tcph,
                               result->cookie);
            return;
        case TCP_SYN_NEW:
            // fprintf(stderr, "Previous close meta packet was not received - "
            //                 "client ip: 0x%08X, client port: %u\n",
            //                 htonl(iph->src_addr), htons(tcph->src_port));
            // Save new SYN
            save_new_syn(result, ethh, iph, tcph, payload_len);
            // Don't change the location of save_new_syn()
#if !REMOVE_HWS
            if (result->hws_applied) {
                del_hws_async(result);
                // if (rte_ring_enqueue(ctx->waiting_hws_del_ring, result) < 0)
                if (sj_ring_enqueue(ctx->waiting_hws_del_ring, result) < 0)
                    fprintf(stderr, "Waiting HWS Del ring is full\n");
                return;
            } else {
                del_hws_async(result); // ?
#endif                                 /* !REMOVE_HWS */
                remove_session(result->ssl_session);
                send_synack_packet(ctx->coreid, port, ethh, iph, tcph,
                                   result->cookie);
                insert_tcp_connection(ctx, port, ethh->src_addr.addr_bytes,
                                      iph->src_addr, tcph->src_port,
                                      ethh->dst_addr.addr_bytes, iph->dst_addr,
                                      tcph->dst_port, seq_no, ack_no,
                                      ntohs(tcph->rx_win), payload_len);
                if (unlikely(!result)) {
                    fprintf(stderr, "insert_tcp_connection failed.\n");
                    exit(EXIT_FAILURE);
                }

                // fprintf(stderr, "Weird SYN Packet!\n");
                return;
#if !REMOVE_HWS
            }
            // // Weird case
            // abort_session(result->ssl_session);
            // return;
#endif /* !REMOVE_HWS */
        }
    }

#if LINUX_TCP_SERVER
    result = insert_tcp_connection(
        ctx, port, ethh->src_addr.addr_bytes, iph->src_addr, tcph->src_port,
        ethh->dst_addr.addr_bytes, iph->dst_addr, tcph->dst_port, seq_no,
        ack_no, ntohs(tcph->rx_win), payload_len);
#if VERBOSE_HOST
    fprintf(stderr, "TCP connection is inserted:\n");
    fprintf(stderr, "client_ip: 0x%08X, client_port: %u (0x%04X)\n",
            htonl(iph.src_addr), htons(tcph.src_port), htons(tcph.src_port));
#endif /* VERBOSE_HOST */

    if (unlikely(!result)) {
        fprintf(stderr, "insert_tcp_connection failed.\n");
        exit(EXIT_FAILURE);
    }
#endif /* LINUX_TCP_SERVER */

    /* Handle TCP SYN Packet */
    send_synack_packet(ctx->coreid, port, ethh, iph, tcph, result->cookie);

    return;
}

static void
process_ack_packet(thread_context_t *ctx, uint16_t port, uint8_t *pktbuf,
                   uint16_t payload_len, struct rte_ether_hdr *ethh,
                   struct rte_ipv4_hdr *iph, struct rte_tcp_hdr *tcph,
                   uint32_t seq_no, uint32_t ack_no)
{
    tcp_connection_t *result;
    result = search_tcp_connection(ctx, iph->src_addr, tcph->src_port,
                                   iph->dst_addr, tcph->dst_port);
    /* Session is not found */
    if (unlikely(!result)) {
        tcp_connection_t target;
        /* TODO: Send RST packet */
        return;
    }

    /* Handle Handshake ACK or Established Packet */
    if (ack_no == (result->cookie + 1) && payload_len == 0) {
        /* Handle Handshake ACK */

        /* Record the time of last response */
        clock_gettime(CLOCK_MONOTONIC, &result->last_interaction);

        return;
    }

    if (result->onload) {
        struct rte_tcp_hdr *tcph =
            (struct rte_tcp_hdr *)(pktbuf + sizeof(struct rte_ether_hdr) +
                                   sizeof(struct rte_ipv4_hdr));

        uint16_t tcp_hdr_len = (tcph->data_off >> 4) << 2;

        uint16_t len = sizeof(struct rte_ether_hdr) +
                       sizeof(struct rte_ipv4_hdr) + tcp_hdr_len + payload_len;

        memcpy(result->pending_app_data, pktbuf, len);
        result->pending_app_data_len = len;

        return;
    }
}

#if ONLOAD
#if LINUX_TCP_SERVER
#if USE_RTE_HWS
static int
process_host_mig_fin(thread_context_t *ctx, struct rte_ether_hdr *ethh,
                     struct rte_ipv4_hdr *iph, struct rte_tcp_hdr *tcph,
                     int len, int pkt_type)
{
#if VERBOSE_META_PKT
    num_recv_mig_fin[ctx->coreid]++;
#endif /* VERBOSE_META_PKT */

    tcp_connection_t *target;

    /* Mig fin packet of host core */
    PRINT_CUR_TIME("receive host ACK");
    target = search_tcp_connection(ctx, iph->src_addr, tcph->src_port,
                                   iph->dst_addr, tcph->dst_port);

#if VERBOSE_HOST
    fprintf(stderr,
            "Try to find connection for mig fin packet from host in core %d\n",
            ctx->coreid);
    fprintf(stderr, "client_ip: 0x%08X, client_port: 0x%04X\n", iph->src_addr,
            tcph->src_port);
    fprintf(stderr, "server_ip: 0x%08X, server_port: 0x%04X\n", iph->dst_addr,
            tcph->dst_port);
#endif /* VERBOSE_HOST */

    if (target) {
        uint8_t *buf = (uint8_t *)ethh;
        if (tcph->sent_seq == target->ssl_session->meta_hdr->server_seq_num &&
            tcph->recv_ack == target->ssl_session->meta_hdr->server_ack_num) {
            target->recv_mig_fin = TRUE;
            PRINT_CUR_TIME("set hws available");

#if VERBOSE_CONN_LAT
            clock_gettime(CLOCK_MONOTONIC, &target->ssl_session->meta_rx_time);
            uint64_t meta_tx_meta_rx_lat =
                (target->ssl_session->meta_rx_time.tv_sec -
                 target->ssl_session->meta_tx_time.tv_sec) *
                    1000000000L +
                (target->ssl_session->meta_rx_time.tv_nsec -
                 target->ssl_session->meta_tx_time.tv_nsec);

            if (meta_tx_meta_rx_lat > max_meta_tx_meta_rx_lat[target->coreid]) {
                max_meta_tx_meta_rx_lat[target->coreid] = meta_tx_meta_rx_lat;
            }

            sum_meta_tx_meta_rx_lat[target->coreid] += meta_tx_meta_rx_lat;
            num_meta_rx[target->coreid]++;
#endif /* VERBOSE_CONN_LAT */
        } else {
            send_raw_reset(ctx->coreid, target->portid + 1, target->client_mac,
                           target->server_mac, target->client_ip,
                           target->server_ip, target->client_port,
                           target->server_port, *(uint32_t *)&buf[48], 0);
            send_rst_conn_meta(ctx->coreid, target->portid + 1, target);
            struct timespec cur_time;
            clock_gettime(CLOCK_MONOTONIC, &cur_time);
            target->need_to_send_rst_meta = TRUE;
        }
    } else {
        // fprintf(stderr, "No session found for mig fin from host.\n");
        // fprintf(stderr, "client_ip: 0x%08X, client_port: %u\n",
        // htonl(iph->src_addr), htons(tcph->src_port));
    }

    return 0;
}

static int
process_host_close(thread_context_t *ctx, struct rte_ether_hdr *ethh,
                   struct rte_ipv4_hdr *iph, struct rte_tcp_hdr *tcph, int len,
                   int pkt_type)
{
    tcp_connection_t *target;
    int ret;

    PRINT_CUR_TIME("receive host Close");

    target = search_tcp_connection(ctx, iph->src_addr, tcph->src_port,
                                   iph->dst_addr, tcph->dst_port);

    if (target) {
        if (tcph->sent_seq == target->ssl_session->meta_hdr->server_seq_num &&
            tcph->recv_ack == target->ssl_session->meta_hdr->server_ack_num) {
            target->hws_ready_to_del = TRUE;
        } else {
            // fprintf(stderr, "Close packet seq/ack mismatch from host.\n"
            //                 "Expected seq: 0x%04x, ack: 0x%04xu\n"
            //                 "Received seq: 0x%04x, ack: 0x%04xu\n",
            //                 target->ssl_session->meta_hdr->server_seq_num,
            //                 target->ssl_session->meta_hdr->server_ack_num,
            //                 tcph->sent_seq,
            //                 tcph->recv_ack);
        }

#if VERBOSE_META_PKT
        num_recv_close_meta[ctx->coreid]++;
#endif /* VERBOSE_META_PKT */
    }
    // else
    // fprintf(stderr, "No connection found for Close packet from host.\n");

    return 0;
}
#endif /* USE_RTE_HWS */

#else /* LINUX_TCP_SERVER */
static int
process_mtcp_host_close(thread_context_t *ctx, struct rte_ether_hdr *ethh,
                        struct rte_ipv4_hdr *iph, struct rte_tcp_hdr *tcph,
                        int len, int pkt_type)
{
    tcp_connection_t *target;

    /* Remove the session if exist */
    target = search_tcp_connection(ctx, iph->dst_addr, tcph->dst_port,
                                   iph->src_addr, tcph->src_port);
    if (target) {
        remove_session(target->ssl_session);

#if VERBOSE_TCP
        fprintf(stderr, "len = %d\n", len);
        fprintf(stderr,
                "TCP Session (with client %x.%d) is removed. flag = %x\n",
                ntohl(iph->dst_addr), ntohs(tcph->dst_port), tcph->tcp_flags);
#endif /* VERBOSE_TCP */
    }

    /* this special packet should be consumed, not forwarded to network */
    if (iph->type_of_service == IP_TOS_MTCP_HOST_CLOSE)
        return 0;
}
#endif /* !LINUX_TCP_SERVER */

static int
process_host_packet(thread_context_t *ctx, uint16_t port, uint8_t *pktbuf,
                    int len, int pkt_type)
{
    uint8_t *wbuf;
    struct rte_ether_hdr *ethh = (struct rte_ether_hdr *)pktbuf;
    struct rte_ipv4_hdr *iph = (struct rte_ipv4_hdr *)(ethh + 1);
    struct rte_tcp_hdr *tcph = (struct rte_tcp_hdr *)(iph + 1);

#if VERBOSE_TCP
    fprintf(stderr, "Process %d length host packet.\n", len);
#endif /* VERBOSE_TCP */

    /* Check if the packet is from host */
    if (unlikely(!(port % 2)))
        return 0;

#if VERBOSE_HOST
    fprintf(stderr, "Contents of host packet (core: %d)\n", core_id);
    hex_dump(pktbuf, len);
    fprintf(stderr, "ip_tos: 0x%04X %s 0x0800\n", htons(iph->type_of_service),
            (htons(iph->type_of_service) == 0x00) ? "==" : "!=");
    if (htons(iph->type_of_service) == (0xfd || 0xfc))
        fprintf(stderr, "Meta packet\n");
#endif /* VERBOSE_HOST */

    switch (pkt_type) {
#if LINUX_TCP_SERVER
#if USE_RTE_HWS
    case HOST_MIG_FIN:
        return process_host_mig_fin(ctx, ethh, iph, tcph, len, pkt_type);
    case HOST_CLOSE:
        return process_host_close(ctx, ethh, iph, tcph, len, pkt_type);
#endif /* USE_RTE_HWS */
#else  /* LINUX_TCP_SERVER */
    /* After host successfully terminate the connection,
    it sends special packet with all TCP flag but URG */
    case MTCP_HOST_CLOSE:
    case TCP_RST:
        return process_mtcp_host_close(ctx, ethh, iph, tcph, len, pkt_type);
#endif /* !LINUX_TCP_SERVER */
    }

    /* Forward to corresponding network interface */
    wbuf = get_wptr(ctx->coreid, port - 1, len, 1, (tcph->data_off >> 4) << 2);
    if (unlikely(!wbuf))
        return 0;

    memcpy(wbuf, pktbuf, len);

#if VERBOSE_TCP
    fprintf(stderr,
            "Packet with length %d is forwarded from host to network.\n", len);
#endif /* VERBOSE_TCP */

    return len;
}
#endif /* ONLOAD */

static int
process_fin_packet(thread_context_t *ctx, uint16_t port, uint8_t *pktbuf,
                   int len)
{
    tcp_connection_t *target;
    int ret = FALSE;

    struct rte_ether_hdr *ethh = (struct rte_ether_hdr *)pktbuf;
    struct rte_ipv4_hdr *iph = (struct rte_ipv4_hdr *)(ethh + 1);
    struct rte_tcp_hdr *tcph = (struct rte_tcp_hdr *)(iph + 1);

    uint32_t seq_no = ntohl(tcph->sent_seq);
    uint32_t ack_no = ntohl(tcph->recv_ack);

    uint16_t payload_len = ntohs(iph->total_length) - IP_HEADER_LEN -
                           ((tcph->data_off & 0xf0) >> 2);

    uint8_t *buf;

    target = search_tcp_connection(ctx, iph->src_addr, tcph->src_port,
                                   iph->dst_addr, tcph->dst_port);

    if (target) {
        // fprintf(stderr, "FIN packet from %08x:%u\n",
        //         htonl(iph->src_addr), htons(tcph->src_port));
        if (target->onload == TRUE) {
            /* forward fin to the host */
            buf = get_wptr(ctx->coreid, port + 1, len, 1,
                           (tcph->data_off >> 4) << 2);
            assert(buf != NULL);
            memcpy(buf, pktbuf, len);
        } else {
            /* Remove session info and send reset to network side */
            ret = TRUE;
            // remove_session(target->ssl_session);
            // send_raw_reset(ctx->coreid, port,
            // 			   ethh->dst_addr.addr_bytes,
            // ethh->src_addr.addr_bytes, iph->dst_addr, iph->src_addr,
            // 			   tcph->dst_port, tcph->src_port,
            // 			   ack_no, seq_no + payload_len);
        }
    } else {
        // fprintf(stderr, "No session found for FIN packet from %08x:%u\n",
        //         htonl(iph->src_addr), htons(tcph->src_port));
        /* just send reset to network side */
        send_raw_reset(ctx->coreid, port, ethh->dst_addr.addr_bytes,
                       ethh->src_addr.addr_bytes, iph->dst_addr, iph->src_addr,
                       tcph->dst_port, tcph->src_port, ack_no,
                       seq_no + payload_len);
    }

#if VERBOSE_TCP
    fprintf(stderr, "A session is removed by FIN packet.\n");
#endif /* VERBOSE_TCP */

#if VERBOSE_FIN
    num_recv_fin[ctx->coreid]++;
#endif /* VERBOSE_FIN */

    return ret;
}

static int
process_rst_packet(thread_context_t *ctx, uint16_t port, uint8_t *pktbuf,
                   int len)
{
    tcp_connection_t *target;
    int ret = FALSE;

    struct rte_ether_hdr *ethh = (struct rte_ether_hdr *)pktbuf;
    struct rte_ipv4_hdr *iph = (struct rte_ipv4_hdr *)(ethh + 1);
    struct rte_tcp_hdr *tcph = (struct rte_tcp_hdr *)(iph + 1);

    uint32_t seq_no = ntohl(tcph->sent_seq);
    uint32_t ack_no = ntohl(tcph->recv_ack);
    uint8_t *buf;

    target = search_tcp_connection(ctx, iph->src_addr, tcph->src_port,
                                   iph->dst_addr, tcph->dst_port);

    if (target) {
        if (target->onload == TRUE) {
            // fprintf(stderr, "RST packet from %08x:%u\n",
            //     htonl(iph->src_addr), htons(tcph->src_port));
            /* forward rst to the host */
            buf = get_wptr(ctx->coreid, port + 1, len, 1,
                           (tcph->data_off >> 4) << 2);
            assert(buf != NULL);
            memcpy(buf, pktbuf, len);
        } else {
            /* Remove session info and send reset to network side */
            // remove_session(target->ssl_session);
            // send_raw_reset(ctx->coreid, port,
            // 			   ethh->src_addr.addr_bytes,
            // ethh->dst_addr.addr_bytes, iph->src_addr, iph->dst_addr,
            // 			   tcph->src_port, tcph->dst_port,
            // 			   seq_no, ack_no);
            // ret = TRUE;
        }
    } else {
        // buf = get_wptr(ctx->coreid, port + 1, len, 1, (tcph->data_off >> 4)
        // << 2); assert(buf != NULL); memcpy(buf, pktbuf, len);

        // fprintf(stderr, "No session found for RST packet from %08x:%u\n",
        //         htonl(iph->src_addr), htons(tcph->src_port));
        // /* just send reset to network side */
        // send_raw_reset(ctx->coreid, port,
        // 			   ethh->src_addr.addr_bytes,
        // ethh->dst_addr.addr_bytes, 			   iph->src_addr,
        // iph->dst_addr, 			   tcph->src_port,
        // tcph->dst_port, 			   seq_no, ack_no);
    }

#if VERBOSE_TCP
    fprintf(stderr, "A session is removed by RST packet.\n");
#endif /* VERBOSE_TCP */

#if VERBOSE_RST
    num_recv_rst[ctx->coreid]++;
#endif /* VERBOSE_RST */

    return ret;
}

static void
process_packet(uint16_t core_id, uint16_t port, uint8_t *pktbuf, uint16_t len)
{
    struct rte_ether_hdr *ethh;
    struct rte_ipv4_hdr *iph;
    uint16_t ip_len;
    struct rte_tcp_hdr *tcph;
    uint8_t *option;
    uint16_t option_len;
    uint8_t *payload;
    uint16_t payload_len;
    uint32_t seq_no, ack_no;
    int pkt_type;

    thread_context_t *ctx;
    int ret;
    tcp_connection_t *result;

#if VERBOSE_TCP
    char recv_dst_hw[20];
    char recv_src_hw[20];
#endif /* VERBOSE_TCP */

    ctx = ctx_array[core_id];

    /* Parse the packet */
    ethh = (struct rte_ether_hdr *)pktbuf;
    iph = (struct rte_ipv4_hdr *)(ethh + 1);
    ip_len = ntohs(iph->total_length);

    tcph = (struct rte_tcp_hdr *)(iph + 1);
    seq_no = ntohl(tcph->sent_seq);
    ack_no = ntohl(tcph->recv_ack);

    option = (uint8_t *)(tcph + 1);
    payload = (uint8_t *)tcph + ((tcph->data_off & 0xf0) >> 2);

    option_len = payload - option;
    payload_len = ip_len - (payload - (uint8_t *)iph);

    /* Filter invalid packets */
    pkt_type = validate_packet_type(port, pktbuf, payload_len);

    /* Packet recv info */
#if VERBOSE_TCP
    sprintf(recv_dst_hw, "%x:%x:%x:%x:%x:%x", ethh->dst_addr.addr_bytes[0],
            ethh->dst_addr.addr_bytes[1], ethh->dst_addr.addr_bytes[2],
            ethh->dst_addr.addr_bytes[3], ethh->dst_addr.addr_bytes[4],
            ethh->dst_addr.addr_bytes[5]);

    sprintf(recv_src_hw, "%x:%x:%x:%x:%x:%x", ethh->src_addr.addr_bytes[0],
            ethh->src_addr.addr_bytes[1], ethh->src_addr.addr_bytes[2],
            ethh->src_addr.addr_bytes[3], ethh->src_addr.addr_bytes[4],
            ethh->src_addr.addr_bytes[5]);

    fprintf(stderr,
            "\nPacket Receive Info---------------------------------\n"
            "core: %d, port: %u\n"
            "dest hwaddr: %s\n"
            "source hwaddr: %s\n"
            "%x : %u -> %x : %u\n"
            "seq: %u, ack: %u, flag: %x\n"
            "len: %u, option_len: %u, payload_len: %u\n\n",
            core_id, port, recv_dst_hw, recv_src_hw, ntohl(iph->src_addr),
            ntohs(tcph->src_port), ntohl(iph->dst_addr), ntohs(tcph->dst_port),
            seq_no, ack_no, tcph->tcp_flags, len, option_len, payload_len);
#else  /* VERBOSE_TCP */
    UNUSED(option_len);
#endif /* !VERBOSE_TCP */

    /* Process packets from the network or host */
    switch (pkt_type) {
    case SSL_HANDSHAKE:
        process_handshake_packet(ctx, port, pktbuf, payload, payload_len, ethh,
                                 iph, tcph, seq_no, ack_no);
        return;
    case TCP_SYN:
        process_syn_packet(ctx, port, pktbuf, payload_len, len, ethh, iph, tcph,
                           seq_no, ack_no);
        return;
    case TCP_ACK:
        process_ack_packet(ctx, port, pktbuf, payload_len, ethh, iph, tcph,
                           seq_no, ack_no);
        return;
#if ONLOAD
#if LINUX_TCP_SERVER
    case HOST_MIG_FIN:
        process_host_packet(ctx, port, pktbuf, len, pkt_type);
        return;
    case HOST_CLOSE:
        process_host_packet(ctx, port, pktbuf, len, pkt_type);
        return;
#else  /* LINUX_TCP_SERVER */
    case MTCP_META_PACKET:
        process_init_meta(pktbuf);
        send_init_meta(core_id, port);
        return;
    case MTCP_HOST_CLOSE:
        process_host_packet(ctx, port, pktbuf, len, pkt_type);
        return;
    case META_TC_RULE:
        process_host_packet(ctx, port, pktbuf, len, pkt_type);

        return;
#endif /* !LINUX_TCP_SERVER */
#endif /* ONLOAD */
    case TCP_FIN:
        process_fin_packet(ctx, port, pktbuf, len);
        return;
    case TCP_RST:
        process_rst_packet(ctx, port, pktbuf, len);
        return;
    case TCP_SYNACK:
        fprintf(stderr, "We don't support processing SYNACK.\n");
        return;

    default:
        // fprintf(stderr, "Unknown packet type.\n");
        return;
    }
#if !ONLOAD
    UNUSED(len);
#endif /* !ONLOAD */

    return;
}

static unsigned
check_ready(void)
{
    unsigned ready = 0;
    unsigned i;

    for (i = 0; i < rte_lcore_count(); i++)
        ready += ctx_array[i]->ready;

    if (ready > rte_lcore_count())
        assert(0);

    if (ready == rte_lcore_count())
        return true;

    return false;
}

static int
process_session_health_check(tcp_connection_t *conn)
{
    int ret;
    long diff;

#if ONLOAD
    if (conn->onload) {
        return 0;
    }
#endif /* ONLOAD */

    /* ToDo: implement timeout */
    struct timespec cur_ts;
    clock_gettime(CLOCK_MONOTONIC, &cur_ts);
    diff = ((cur_ts.tv_sec - conn->last_interaction.tv_sec) * 1000000000) +
           cur_ts.tv_nsec - conn->last_interaction.tv_nsec;

    if (unlikely(diff > (uint64_t)HEALTH_CHECK * 1000000ULL)) {
        /* Probe if it is alive */
        ret = send_tcp_packet(conn, NULL, 0, TCP_FLAG_ACK, 0);

        if (unlikely(ret < 0)) {
            fprintf(stderr, "Sending RST Failed.\n");
            exit(EXIT_FAILURE);
        }

        /* Update Last Interaction */
        conn->last_interaction.tv_sec = cur_ts.tv_sec;
        conn->last_interaction.tv_nsec = cur_ts.tv_nsec;

        return -1;
    }

    return 0;
}

void
apply_hws(tcp_connection_t *conn)
{
    int ret = 0;

    if (conn->ssl_session->state == STATE_ACTIVE && conn->recv_mig_fin &&
        !(conn->hws_inserted)) {
        /* Insert flow rule */
        PRINT_CUR_TIME("insert hws rule");

#if !REMOVE_HWS
        /* testing - does hws matter? */
        MEASURE("HWS rule insertion",
                ret = ins_async_hws_recv(conn, template_table_jump,
                                         template_table_hws););
#endif /* !REMOVE_HWS */

        if (unlikely(ret < 0)) {
            fprintf(stderr, "Failed to insert flow rule for port %d\n",
                    conn->portid);
            return;
        }

        conn->hws_inserted = TRUE;
#if REMOVE_HWS
        conn->hws_applied = TRUE;
#endif /* REMOVE_HWS */

#if VERBOSE_HWS
        clock_gettime(CLOCK_MONOTONIC, &conn->hws_start);
#endif /* VERBOSE_HWS */

#if VERBOSE_HWS_RULES
        num_hws_applied[conn->coreid]++;
#endif /* VERBOSE_HWS_RULES */
    }

    return;
}

void
remove_hws(tcp_connection_t *conn)
{
    int ret = 0;

    if (conn->hws_applied && conn->hws_ready_to_del) {
#if !REMOVE_HWS
        MEASURE("delete hws rule", ret = del_hws_async(conn););
#else  /* REMOVE_HWS */
        conn->hws_deleted = TRUE;
#endif /* REMOVE_HWS */

        if (unlikely(ret < 0)) {
            fprintf(stderr,
                    "Failed to delete flow rule for"
                    " client ip: 0x%08X, client port: 0x%04X\n",
                    conn->client_ip, conn->client_port);
            return;
        }

        remove_session(conn->ssl_session);

#if VERBOSE_HWS_RULES
        num_hws_applied[conn->coreid]--;
#endif /* VERBOSE_HWS_RULES */
    }

    return;
}

#if FWD_ONLY_APPDATA
/* test for forwarding only app data */
void
forward_app_data(tcp_connection_t *conn)
{
    if (conn->hws_applied && conn->pending_app_data_len > 0) {
        /* Forward onloaded packet */
        uint8_t *wbuf;
        uint8_t *pktbuf = conn->pending_app_data;

        struct rte_tcp_hdr *tcph =
            (struct rte_tcp_hdr *)(pktbuf + sizeof(struct rte_ether_hdr) +
                                   sizeof(struct rte_ipv4_hdr));

        uint16_t tcp_hdr_len = (tcph->data_off >> 4) << 2;

        uint16_t len = conn->pending_app_data_len;

        wbuf = get_wptr(conn->coreid, conn->portid + 1, len, 1, tcp_hdr_len);
        assert(wbuf != NULL);

        memcpy(wbuf, pktbuf, len);

        conn->pending_app_data_len = 0;

        return;
    }
}
#endif /* FWD_ONLY_APPDATA */

void
handle_waiting_hws_del_conns(thread_context_t *ctx, uint16_t port)
{
    tcp_connection_t *conn;

    for (int i = 0; i < ctx->waiting_hws_del_ring->size; i++) {
        // if (rte_ring_dequeue(ctx->waiting_hws_del_ring, (void **)&conn) < 0)
        if (sj_ring_dequeue(ctx->waiting_hws_del_ring, (void **)&conn) < 0)
            continue;

        if (conn->hws_deleted) {
            struct rte_ether_hdr ethh = conn->pending_syn.ethh;
            struct rte_ipv4_hdr iph = conn->pending_syn.iph;
            struct rte_tcp_hdr tcph = conn->pending_syn.tcph;
            uint8_t tcp_options[40];
            memcpy(tcp_options, conn->pending_syn.tcp_options, 40);
            uint16_t tcp_option_len = conn->pending_syn.tcp_option_len;
            uint16_t payload_len = conn->pending_syn.payload_len;

            uint32_t seq_no = ntohl(tcph.sent_seq);
            uint32_t ack_no = ntohl(tcph.recv_ack);

            remove_session(conn->ssl_session);

#if LINUX_TCP_SERVER
            tcp_connection_t *result = insert_tcp_connection(
                ctx, port, ethh.src_addr.addr_bytes, iph.src_addr,
                tcph.src_port, ethh.dst_addr.addr_bytes, iph.dst_addr,
                tcph.dst_port, seq_no, ack_no, ntohs(tcph.rx_win), payload_len);
#if VERBOSE_HOST
            fprintf(stderr, "TCP connection is inserted:\n");
            fprintf(stderr, "client_ip: 0x%08X, client_port: %u (0x%04X)\n",
                    htonl(iph.src_addr), htons(tcph.src_port),
                    htons(tcph.src_port));
#endif /* VERBOSE_HOST */

            if (unlikely(!result)) {
                fprintf(stderr, "insert_tcp_connection failed.\n");
                exit(EXIT_FAILURE);
            }
#endif /* LINUX_TCP_SERVER */

            send_synack_packet_for_saved_new_syn(
                ctx->coreid, port, &ethh, &iph, &tcph, tcp_options,
                tcp_option_len, result->cookie);
        } else {
            // rte_ring_enqueue(ctx->waiting_hws_del_ring, conn);
            sj_ring_enqueue(ctx->waiting_hws_del_ring, conn);
        }
    }
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
int
ssloff_main_loop(__attribute__((unused)) void *arg)
{
    uint16_t port, core_id;
    thread_context_t *ctx;

    int i;
    int recv_cnt, send_cnt, sent_cnt;
    int processed_cnt;

    int per_sec_task = 0;
    int thread_recv_q_cnt = 0;

    tcp_connection_t *target;
    struct timespec prev_ts = {0};

    uint64_t call_pka_get_result = 0;
    int processed_submitted_pka;
    int processed_completed_pka;

#if VERBOSE_EFFECTIVE_LOOP
    uint64_t total_loop_cnt = 0;
    uint64_t eff_loop_cnt = 0;
    uint64_t eff_sub_loop_cnt = 0;
    uint64_t eff_com_loop_cnt = 0;
#endif /* VERBOSE_EFFECTIVE_LOOP */

    /* Initialize thread context */
    core_id = rte_lcore_id();
    thread_local_init(core_id);

    ctx = ctx_array[core_id];
    ctx->ready = TRUE;

    if (check_ready()) {
        fprintf(stderr,
                "CPU[%d] Initialization finished\n"
                "Now start forwarding.\n\n",
                rte_lcore_id());
    } else {
        fprintf(stderr,
                "CPU[%d] Initialization finished\n"
                "Wait for other cores.\n\n",
                rte_lcore_id());
        while (!check_ready()) {
        }
        sleep(1);
    }

    fprintf(stderr, "Core %u forwarding packets. [Ctrl+C to quit]\n\n",
            rte_lcore_id());

    clock_gettime(CLOCK_MONOTONIC, &start_ts);

    num_core = rte_lcore_count();

    /* Run until the application is quit or killed. */
    for (;;) {
        /* Do PKA-related tasks in core 0 */
        if (core_id == 0) {
#if VERBOSE_EFFECTIVE_LOOP
            if (eff_loop_cnt)
                total_loop_cnt++;
            processed_submitted_pka = 0;
            processed_completed_pka = 0;
#endif /* VERBOSE_EFFECTIVE_LOOP */

            call_pka_get_result++;

            processed_submitted_pka = handle_submitted_pka(ctx);
            processed_completed_pka = handle_completed_pka(ctx);

            // if (call_pka_get_result % 30 == 0)
            // processed_completed_pka = handle_completed_pka(ctx);

#if VERBOSE_EFFECTIVE_LOOP
            if (processed_submitted_pka)
                eff_sub_loop_cnt++;

            if (processed_completed_pka)
                eff_com_loop_cnt++;

            if (processed_submitted_pka || processed_completed_pka)
                eff_loop_cnt++;
#endif /* VERBOSE_EFFECTIVE_LOOP */

            goto pka_core;
        }

        /* Do per-sec tasks in core 1 (update cookie, print logs) */
        if (core_id == 1) {
            clock_gettime(CLOCK_MONOTONIC, &cur_ts);

            if (unlikely(cur_ts.tv_sec > prev_ts.tv_sec)) {
                update_cookie();

#if VERBOSE_PER_SEC
                per_sec_task = TRUE;
#endif /* VERBOSE_PER_SEC */

#if VERBOSE_STAT
                print_stat();
#endif /* VERBOSE_STAT */
                fprintf(stderr, "\n");
            }

            prev_ts = cur_ts;
        }

        send_cnt = 0;
        RTE_ETH_FOREACH_DEV(port)
        {
            uint16_t len;
            uint8_t *pktbuf;

            /* Receive packets */
            recv_cnt = recv_pkts(core_id, port);

#if VERBOSE_TCP
            if (recv_cnt > 0)
                fprintf(stderr, "recv_pkts: %d\n", recv_cnt);
#endif /* VERBOSE_TCP */

            /* Process received packets */
            for (i = 0; i < recv_cnt; i++) {
                pktbuf = get_rptr(core_id, port, i, &len);

                if (likely(pktbuf != NULL)) {
#if VERBOSE_RECV
                    if (ctx->active_cnt < 10) {
                        if (!is_broadcast(pktbuf)) {
                            fprintf(stderr, "\nReceived Packet from port %d\n",
                                    port);
                            fprintf(stderr, "Packet length: %u\n", len);
                            hex_dump(pktbuf, len);
                        }
                    }
#endif /* VERBOSE_RECV */
                    process_packet(core_id, port, pktbuf, len);
                }
            }

#if VERBOSE_TCP
            if (processed_cnt)
                fprintf(stderr, "\nprocessed: %d\n", processed_cnt);
#else  /* VERBOSE_TCP */
            UNUSED(processed_cnt);
#endif /* !VERBOSE_TCP */

#if USE_HASHTABLE_FOR_ACTIVE_SESSION
            for (i = 0; i < NUM_BINS; i++) {
                hashtable_t *ht = ctx->active_session_table;
                TAILQ_FOREACH(target, &ht->ht_table[i], active_session_link)
                {
#if VERBOSE_RECV_Q_CNT
                    if (unlikely(per_sec_task)) {
                        thread_recv_q_cnt += target->ssl_session->recv_q_cnt;
                    }
#endif /* VERBOSE_RECV_Q_CNT */

                    process_session_read(target->ssl_session);
                    // process_session_health_check(target);
                    get_processed_crypto(target->ssl_session);
                    apply_hws(target);
                    remove_hws(target);
#if FWD_ONLY_APPDATA
                    /* test for forwarding only app data */
                    forward_app_data(target);
#endif /* FWD_ONLY_APPDATA */
                    send_remain_server_records(target->ssl_session);
                }
            }

            /* Process done-cryptos by PKA Engine */
            handle_waiting_hws_del_conns(ctx, port);

#if VERBOSE_RECV_Q_CNT
            if (unlikely(per_sec_task && (port == 0))) {
                fprintf(stderr, "Per-thread recv_q_cnt: %d\n",
                        thread_recv_q_cnt);
                thread_recv_q_cnt = 0;
            }
#endif /* VERBOSE_RECV_Q_CNT */

#if VERBOSE_IF_STAT
            if (unlikely(per_sec_task && ((port == 0) || (port == 1)))) {
                int ret = rte_eth_stats_get(port, ctx->if_stat[port]);

                if (ret < 0) {
                    fprintf(stderr, "rte_eth_stats_get failed for port %u\n",
                            port);
                    exit(EXIT_FAILURE);
                }

                uint64_t total_imissed = 0;
                uint64_t total_oerrors = 0;

                for (int i = 0; i < rte_lcore_count(); i++) {
                    total_imissed += ctx_array[i]->if_stat[port]->imissed;
                    total_oerrors += ctx_array[i]->if_stat[port]->oerrors;
                }

                if (total_imissed && ctx->coreid == 1) {
                    for (int i = 0; i < rte_lcore_count(); i++) {
                        fprintf(stderr,
                                "[Thread %d] - imissed pkts of port %u: %lu,\n",
                                ctx_array[i]->coreid, port,
                                ctx_array[i]->if_stat[port]->imissed);
                    }

                    fprintf(stderr, "Total imissed pkts of port %u: %lu,\n",
                            port, total_imissed);
                }

                if (total_oerrors && ctx->coreid == 1) {
                    for (int i = 0; i < rte_lcore_count(); i++) {
                        fprintf(stderr,
                                "[Thread %d] - oerrors pkts of port %u: %lu,\n",
                                ctx_array[i]->coreid, port,
                                ctx_array[i]->if_stat[port]->oerrors);
                    }

                    fprintf(stderr, "Total oerrors pkts of port %u: %lu,\n",
                            port, total_oerrors);
                }
            }
#endif /* VERBOSE_IF_STAT */

#else  /* USE_HASHTABLE_FOR_ACTIVE_SESSION */
            /* Process SSL Steps of Each Session */
            TAILQ_FOREACH(target, &ctx->active_session_q, active_session_link)
            {
                process_session_read(target->ssl_session);
                process_session_health_check(target);
                apply_hws(target);
            }
#endif /* !USE_HASHTABLE_FOR_ACTIVE_SESSION */

            /* Send Packets */
            sent_cnt = send_pkts(core_id, port);

#if VERBOSE_TCP
            if (sent_cnt > 0)
                fprintf(stderr, "send_pkts: %d\n", sent_cnt);
#else  /* VERBOSE_TCP */
            UNUSED(sent_cnt);
#endif /* !VERBOSE_TCP */
        }

#if USE_RTE_HWS
        rte_flow_pull_and_push(ctx);
#endif /* USE_RTE_HWS */

#if VERBOSE_META_PKT
        if (unlikely(per_sec_task)) {
            int tot_num_sent_meta = 0;
            int tot_num_recv_mig_fin = 0;
            int tot_num_recv_close_meta = 0;

            for (int i = 0; i < MAX_CPUS; i++) {
                tot_num_sent_meta += num_sent_meta[i];
                tot_num_recv_mig_fin += num_recv_mig_fin[i];
                tot_num_recv_close_meta += num_recv_close_meta[i];
            }

            fprintf(stderr, "num_sent_meta: %d, num_recv_mig_fin: %d\n",
                    tot_num_sent_meta, tot_num_recv_mig_fin);
            fprintf(stderr, "num_recv_close_meta: %d\n",
                    tot_num_recv_close_meta);
        }
#endif /* VERBOSE_META_PKT */

#if VERBOSE_HWS_RULES
        if (unlikely(per_sec_task)) {
            int tot_num_hws_applied = 0;

            for (int i = 0; i < MAX_CPUS; i++) {
                tot_num_hws_applied += num_hws_applied[i];
            }

            fprintf(stderr, "num_hws_applied: %d\n", tot_num_hws_applied);
        }
#endif /* VERBOSE_HWS_RULES */

#if VERBOSE_RST
        if (unlikely(per_sec_task)) {
            int tot_num_recv_rst = 0;

            for (int i = 0; i < MAX_CPUS; i++) {
                tot_num_recv_rst += num_recv_rst[i];
            }

            fprintf(stderr, "num_recv_rst: %d\n", tot_num_recv_rst);
        }
#endif /* VERBOSE_RST */

#if VERBOSE_FIN
        if (unlikely(per_sec_task)) {
            int tot_num_recv_fin = 0;

            for (int i = 0; i < MAX_CPUS; i++) {
                tot_num_recv_fin += num_recv_fin[i];
            }

            fprintf(stderr, "num_recv_fin: %d\n", tot_num_recv_fin);
        }
#endif /* VERBOSE_FIN */

#if VERBOSE_TCP_HS
        if (unlikely(per_sec_task)) {
            int tot_num_recv_syn = 0;
            int tot_num_sent_synack = 0;
            int tot_num_completed_sess = 0;

            for (int i = 0; i < MAX_CPUS; i++) {
                tot_num_recv_syn += num_recv_syn[i];
                tot_num_sent_synack += num_sent_synack[i];
                tot_num_completed_sess += num_completed_sess[i];
            }

            fprintf(stderr, "num_recv_syn: %d\n", tot_num_recv_syn);
            fprintf(stderr, "num_sent_synack: %d\n", tot_num_sent_synack);
            fprintf(stderr, "num_completed_sess: %d\n", tot_num_completed_sess);
        }
#endif /* VERBOSE_TCP_HS */

#if VERBOSE_CONN_LAT
        if (unlikely(per_sec_task)) {
            int tot_num_completed_sess = 0;
            int tot_num_key_gen = 0;
            int tot_num_gen_key = 0;
            int tot_num_ss_cal = 0;
            int tot_num_cal_ss = 0;
            int tot_num_ee_c_cv_gen = 0;
            int tot_num_gen_cv = 0;
            int tot_num_app_key_cal = 0;
            int tot_num_cal_app_key = 0;
            int tot_num_meta_tx = 0;
            int tot_num_meta_rx = 0;
            int tot_num_app_data = 0;

            uint64_t tot_sum_conn_lat = 0;
            uint64_t tot_sum_syn_key_gen_lat = 0;
            uint64_t tot_sum_key_gen_gen_key_lat = 0;
            uint64_t tot_sum_gen_key_ss_cal_lat = 0;
            uint64_t tot_sum_ss_cal_cal_ss_lat = 0;
            uint64_t tot_sum_cal_ss_ee_c_cv_gen_lat = 0;
            uint64_t tot_sum_ee_c_cv_gen_gen_cv_lat = 0;
            uint64_t tot_sum_gen_cv_app_key_cal_lat = 0;
            uint64_t tot_sum_app_key_cal_cal_app_key_lat = 0;
            uint64_t tot_sum_cal_app_key_meta_tx_lat = 0;
            uint64_t tot_sum_meta_tx_meta_rx_lat = 0;
            uint64_t tot_sum_app_data_lat = 0;

            uint64_t max_max_syn_key_gen_lat = 0;
            uint64_t max_max_key_gen_gen_key_lat = 0;
            uint64_t max_max_gen_key_ss_cal_lat = 0;
            uint64_t max_max_ss_cal_cal_ss_lat = 0;
            uint64_t max_max_cal_ss_ee_c_cv_gen_lat = 0;
            uint64_t max_max_ee_c_cv_gen_gen_cv_lat = 0;
            uint64_t max_max_gen_cv_app_key_cal_lat = 0;
            uint64_t max_max_app_key_cal_cal_app_key_lat = 0;
            uint64_t max_max_cal_app_key_meta_tx_lat = 0;
            uint64_t max_max_meta_tx_meta_rx_lat = 0;
            uint64_t max_max_app_data_lat = 0;

            for (int i = 0; i < MAX_CPUS; i++) {
                tot_sum_syn_key_gen_lat += sum_syn_key_gen_lat[i];
                tot_sum_key_gen_gen_key_lat += sum_key_gen_gen_key_lat[i];
                tot_sum_gen_key_ss_cal_lat += sum_gen_key_ss_cal_lat[i];
                tot_sum_ss_cal_cal_ss_lat += sum_ss_cal_cal_ss_lat[i];
                tot_sum_cal_ss_ee_c_cv_gen_lat += sum_cal_ss_ee_c_cv_gen_lat[i];
                tot_sum_ee_c_cv_gen_gen_cv_lat += sum_ee_c_cv_gen_gen_cv_lat[i];
                tot_sum_gen_cv_app_key_cal_lat += sum_gen_cv_app_key_cal_lat[i];
                tot_sum_app_key_cal_cal_app_key_lat +=
                    sum_app_key_cal_cal_app_key_lat[i];
                tot_sum_cal_app_key_meta_tx_lat +=
                    sum_cal_app_key_meta_tx_lat[i];
                tot_sum_meta_tx_meta_rx_lat += sum_meta_tx_meta_rx_lat[i];
                tot_sum_app_data_lat += sum_app_data_lat[i];

                tot_num_key_gen += num_key_gen[i];
                tot_num_gen_key += num_gen_key[i];
                tot_num_ss_cal += num_ss_cal[i];
                tot_num_cal_ss += num_cal_ss[i];
                tot_num_ee_c_cv_gen += num_ee_c_cv_gen[i];
                tot_num_gen_cv += num_gen_cv[i];
                tot_num_app_key_cal += num_app_key_cal[i];
                tot_num_cal_app_key += num_cal_app_key[i];
                tot_num_meta_tx += num_meta_tx[i];
                tot_num_meta_rx += num_meta_rx[i];
                tot_num_app_data += num_app_data[i];
            }

            for (int i = 0; i < MAX_CPUS; i++) {
                max_max_syn_key_gen_lat =
                    max_max_syn_key_gen_lat < max_syn_key_gen_lat[i]
                        ? max_syn_key_gen_lat[i]
                        : max_max_syn_key_gen_lat;
                max_max_key_gen_gen_key_lat =
                    max_max_key_gen_gen_key_lat < max_key_gen_gen_key_lat[i]
                        ? max_key_gen_gen_key_lat[i]
                        : max_max_key_gen_gen_key_lat;
                max_max_gen_key_ss_cal_lat =
                    max_max_gen_key_ss_cal_lat < max_gen_key_ss_cal_lat[i]
                        ? max_gen_key_ss_cal_lat[i]
                        : max_max_gen_key_ss_cal_lat;
                max_max_ss_cal_cal_ss_lat =
                    max_max_ss_cal_cal_ss_lat < max_ss_cal_cal_ss_lat[i]
                        ? max_ss_cal_cal_ss_lat[i]
                        : max_max_ss_cal_cal_ss_lat;
                max_max_cal_ss_ee_c_cv_gen_lat =
                    max_max_cal_ss_ee_c_cv_gen_lat <
                            max_cal_ss_ee_c_cv_gen_lat[i]
                        ? max_cal_ss_ee_c_cv_gen_lat[i]
                        : max_max_cal_ss_ee_c_cv_gen_lat;
                max_max_ee_c_cv_gen_gen_cv_lat =
                    max_max_ee_c_cv_gen_gen_cv_lat <
                            max_ee_c_cv_gen_gen_cv_lat[i]
                        ? max_ee_c_cv_gen_gen_cv_lat[i]
                        : max_max_ee_c_cv_gen_gen_cv_lat;
                max_max_gen_cv_app_key_cal_lat =
                    max_max_gen_cv_app_key_cal_lat <
                            max_gen_cv_app_key_cal_lat[i]
                        ? max_gen_cv_app_key_cal_lat[i]
                        : max_max_gen_cv_app_key_cal_lat;
                max_max_app_key_cal_cal_app_key_lat =
                    max_max_app_key_cal_cal_app_key_lat <
                            max_app_key_cal_cal_app_key_lat[i]
                        ? max_app_key_cal_cal_app_key_lat[i]
                        : max_max_app_key_cal_cal_app_key_lat;
                max_max_cal_app_key_meta_tx_lat =
                    max_max_cal_app_key_meta_tx_lat <
                            max_cal_app_key_meta_tx_lat[i]
                        ? max_cal_app_key_meta_tx_lat[i]
                        : max_max_cal_app_key_meta_tx_lat;
                max_max_meta_tx_meta_rx_lat =
                    max_max_meta_tx_meta_rx_lat < max_meta_tx_meta_rx_lat[i]
                        ? max_meta_tx_meta_rx_lat[i]
                        : max_max_meta_tx_meta_rx_lat;
                max_max_app_data_lat =
                    max_max_app_data_lat < max_app_data_lat[i]
                        ? max_app_data_lat[i]
                        : max_max_app_data_lat;
            }

            fprintf(
                stderr,
                "Latency breakdown (ns)\n"
                "syn to key_gen (max): %.3f (%lu)\n"
                "key_gen to gen_key (max): %.3f (%lu)\n"
                "gen_key to ss_cal (max): %.3f (%lu)\n"
                "ss_cal to cal_ss (max): %.3f (%lu)\n"
                "cal_ss to ee_c_cv_gen (max): %.3f (%lu)\n"
                "ee_c_cv_gen to gen_cv (max): %.3f (%lu)\n"
                "gen_cv to app_key_cal (max): %.3f (%lu)\n"
                "app_key_cal to cal_app_key (max): %.3f (%lu)\n"
                "cal_app_key to meta_tx (max): %.3f (%lu)\n"
                "meta_tx to meta_rx (max): %.3f (%lu)\n"
                "app_data processing (max): %.3f (%lu)\n",
                tot_num_key_gen
                    ? (double)tot_sum_syn_key_gen_lat / tot_num_key_gen
                    : 0,
                max_max_syn_key_gen_lat,
                tot_num_gen_key
                    ? (double)tot_sum_key_gen_gen_key_lat / tot_num_gen_key
                    : 0,
                max_max_key_gen_gen_key_lat,
                tot_num_ss_cal
                    ? (double)tot_sum_gen_key_ss_cal_lat / tot_num_ss_cal
                    : 0,
                max_max_gen_key_ss_cal_lat,
                tot_num_cal_ss
                    ? (double)tot_sum_ss_cal_cal_ss_lat / tot_num_cal_ss
                    : 0,
                max_max_ss_cal_cal_ss_lat,
                tot_num_ee_c_cv_gen ? (double)tot_sum_cal_ss_ee_c_cv_gen_lat /
                                          tot_num_ee_c_cv_gen
                                    : 0,
                max_max_cal_ss_ee_c_cv_gen_lat,
                tot_num_gen_cv
                    ? (double)tot_sum_ee_c_cv_gen_gen_cv_lat / tot_num_gen_cv
                    : 0,
                max_max_ee_c_cv_gen_gen_cv_lat,
                tot_num_app_key_cal ? (double)tot_sum_gen_cv_app_key_cal_lat /
                                          tot_num_app_key_cal
                                    : 0,
                max_max_gen_cv_app_key_cal_lat,
                tot_num_cal_app_key
                    ? (double)tot_sum_app_key_cal_cal_app_key_lat /
                          tot_num_cal_app_key
                    : 0,
                max_max_app_key_cal_cal_app_key_lat,
                tot_num_meta_tx
                    ? (double)tot_sum_cal_app_key_meta_tx_lat / tot_num_meta_tx
                    : 0,
                max_max_cal_app_key_meta_tx_lat,
                tot_num_meta_rx
                    ? (double)tot_sum_meta_tx_meta_rx_lat / tot_num_meta_rx
                    : 0,
                max_max_meta_tx_meta_rx_lat,
                tot_num_app_data
                    ? (double)tot_sum_app_data_lat / tot_num_app_data
                    : 0,
                max_max_app_data_lat);

            for (int i = 0; i < MAX_CPUS; i++) {
                tot_sum_conn_lat += sum_conn_lat[i];
                tot_num_completed_sess += num_completed_sess[i];
            }

            fprintf(stderr, "avg conn lat: %.3fs\n",
                    (double)tot_sum_conn_lat / tot_num_completed_sess / 1e9);

            // for (int i = 0; i < MAX_CPUS; i++) {
            //     fprintf(stderr, "max conn lat of core %d: %.3fs\n",
            //             i, (double)max_conn_lat[i] / 1e9);
            // }
        }
#endif /* VERBOSE_CONN_LAT */

#if VERBOSE_PKA_OP
        if (unlikely(per_sec_task)) {
            int tot_num_key_gen = 0;
            int tot_num_calc_shared_secret = 0;
            int tot_num_signature_cert = 0;

            for (int i = 0; i < MAX_CPUS; i++) {
                tot_num_key_gen += num_key_gen[i];
                tot_num_calc_shared_secret += num_calc_shared_secret[i];
                tot_num_signature_cert += num_signature_cert[i];
            }

            fprintf(stderr, "num_key_gen: %d\n", tot_num_key_gen);
            fprintf(stderr, "num_calc_shared_secret: %d\n",
                    tot_num_calc_shared_secret);
            fprintf(stderr, "num_signature_cert: %d\n", tot_num_signature_cert);
        }
#endif /* VERBOSE_PKA_OP */

#if VERBOSE_PENDING_PKA_OP
        if (unlikely(per_sec_task)) {
            int tot_num_pending_pka_op = 0;

            fprintf(stderr, "/*---------------------------------*/\n");

            for (int i = 0; i < rte_lcore_count(); i++) {
                fprintf(stderr, "core %d - cur_crypto_cnt: %u\n", i,
                        ctx_array[i]->cur_crypto_cnt);
                tot_num_pending_pka_op += ctx_array[i]->cur_crypto_cnt;
            }

            fprintf(stderr, "tot_num_pending_pka_op: %u\n",
                    tot_num_pending_pka_op);

            fprintf(stderr, "/*---------------------------------*/\n");
        }
#endif /* VERBOSE_PENDING_PKA_OP */

#if VERBOSE_PKA_GET_RESULT
        if (unlikely(per_sec_task)) {
            fprintf(stderr, "/*---------------------------------*/\n");

            clock_gettime(CLOCK_MONOTONIC, &cur_ts);

            double elapsed_sec = (cur_ts.tv_nsec - start_ts.tv_nsec) / 1e9 +
                                 (cur_ts.tv_sec - start_ts.tv_sec);

            fprintf(stderr,
                    "pka_get_result min=%lu, max=%lu, avg=%lu\n"
                    "pka_get_result cnt per sec=%lu, total cnt=%lu\n"
                    "pka_get_result fail cnt=%lu, success cnt=%lu\n",
                    pka_get_result_min, pka_get_result_max,
                    (pka_get_result_sum / pka_get_result_cnt),
                    (unsigned long)(pka_get_result_cnt / elapsed_sec),
                    pka_get_result_cnt, pka_get_result_fail_cnt,
                    pka_get_result_success_cnt);

            fprintf(stderr, "/*---------------------------------*/\n");
        }
#endif /* VERBOSE_PKA_GET_RESULT */

#if VERBOSE_RTE_RING_EQ
        if (unlikely(per_sec_task)) {
            fprintf(stderr, "/*---------------------------------*/\n");

            clock_gettime(CLOCK_MONOTONIC, &cur_ts);

            double elapsed_sec = (cur_ts.tv_nsec - start_ts.tv_nsec) / 1e9 +
                                 (cur_ts.tv_sec - start_ts.tv_sec);

            fprintf(stderr,
                    "ring enqueue min=%lu, max=%lu, avg=%lu\n"
                    "ring enqueue cnt per sec=%lu, total cnt=%lu\n"
                    "ring enqueue fail cnt=%lu, success cnt=%lu\n",
                    ring_eq_min, ring_eq_max, (ring_eq_sum / ring_eq_cnt),
                    (unsigned long)(ring_eq_cnt / elapsed_sec), ring_eq_cnt,
                    ring_eq_fail_cnt, ring_eq_success_cnt);
            fprintf(stderr, "/*---------------------------------*/\n");
        }
#endif /* VERBOSE_RTE_RING_EQ */

#if VERBOSE_RTE_RING_DQ
        if (unlikely(per_sec_task)) {
            fprintf(stderr, "/*---------------------------------*/\n");

            clock_gettime(CLOCK_MONOTONIC, &cur_ts);

            double elapsed_sec = (cur_ts.tv_nsec - start_ts.tv_nsec) / 1e9 +
                                 (cur_ts.tv_sec - start_ts.tv_sec);

            fprintf(stderr,
                    "ring dequeue min=%lu, max=%lu, avg=%lu\n"
                    "ring dequeue cnt per sec=%lu, total cnt=%lu\n"
                    "ring dequeue fail cnt=%lu, success cnt=%lu\n",
                    ring_dq_min, ring_dq_max, (ring_dq_sum / ring_dq_cnt),
                    (unsigned long)(ring_dq_cnt / elapsed_sec), ring_dq_cnt,
                    ring_dq_fail_cnt, ring_dq_success_cnt);

            fprintf(stderr, "/*---------------------------------*/\n");
        }
#endif /* VERBOSE_RTE_RING_DQ */

#if VERBOSE_PER_SEC
        per_sec_task = FALSE;
#endif /* VERBOSE_PER_SEC */

    pka_core:
#if VERBOSE_EFFECTIVE_LOOP
        if (core_id == 0) {
            clock_gettime(CLOCK_MONOTONIC, &cur_ts);

            if (unlikely(cur_ts.tv_sec > prev_ts.tv_sec)) {
                fprintf(stderr, "/*---------------------------------*/\n");

                fprintf(
                    stderr,
                    "total_loop_cnt: %lu, eff_sub_loop_cnt: %lu, "
                    "eff_com_loop_cnt: %lu\n"
                    "eff_sub_loop_ratio: %.2f%%, eff_com_loop_ratio: %.2f%%\n"
                    "eff_loop_ratio: %.2f%%\n",
                    total_loop_cnt, eff_sub_loop_cnt, eff_com_loop_cnt,
                    (double)eff_sub_loop_cnt / total_loop_cnt * 100,
                    (double)eff_com_loop_cnt / total_loop_cnt * 100,
                    (double)eff_loop_cnt / total_loop_cnt * 100);

                fprintf(stderr, "/*---------------------------------*/\n");

                prev_ts = cur_ts;
            }
        }
#endif /* VERBOSE_EFFECTIVE_LOOP */
    }

    thread_local_destroy(rte_lcore_id());
    return 0;
}
