#ifndef __SSLOFF_H__
#define __SSLOFF_H__

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <gmp.h>
#include <assert.h>
#include <byteswap.h>
#include <pthread.h>
#include <sched.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_flow.h>
#include <rte_mbuf.h>
#include <rte_version.h>
#include <rte_thash.h>

#include "option.h"
#include "ssl.h"
#include "cert.h"
#include "ssl_crypto.h"
#include "ring.h"
#include <openssl/rsa.h>

#if ONLOAD
#include "host.h"
#endif /* ONLOAD */

#define RTE_TEST_RX_DESC_DEFAULT 4096
#define RTE_TEST_TX_DESC_DEFAULT 4096

#define NUM_MBUFS           8192

#define MBUF_CACHE_SIZE     250
#define BURST_SIZE          32

#define MAX_PKT_BURST       64
#define MAX_CPUS            16
#define MAX_DPDK_PORT       8
#define MAX_TCP_PORT        65536
#define MAX_OUTSTANDING_PKA_REQ 32
#define MAX_HOST_THREADS    16

#define INIT_KEY_SIZE       16
#define INIT_IV_SIZE        16

#define RX_PTHRESH          8
#define RX_HTHRESH          8
#define RX_WTHRESH          4

#define TX_PTHRESH          36
#define TX_HTHRESH          0
#define TX_WTHRESH          0

#define RX_IDLE_ENABLE      TRUE

#if USE_RTE_HWS
#define MAX_RESULTS         1024
#endif /* USE_RTE_HWS */

#define ETHER_TYPE_META     0x080F
#define KEY_META_ETH_TYPE_0     0x0801
#define KEY_META_ETH_TYPE_1     0x0802
#define KEY_META_ETH_TYPE_2     0x0803
#define KEY_META_ETH_TYPE_3     0x0804
#define KEY_META_ETH_TYPE_4     0x0805
#define KEY_META_ETH_TYPE_5     0x0806
#define KEY_META_ETH_TYPE_6     0x0807
#define KEY_META_ETH_TYPE_7     0x0808
#define KEY_META_ETH_TYPE_8     0x0809
#define KEY_META_ETH_TYPE_9     0x080A
#define KEY_META_ETH_TYPE_10    0x080B
#define KEY_META_ETH_TYPE_11    0x080C
#define KEY_META_ETH_TYPE_12    0x080D
#define KEY_META_ETH_TYPE_13    0x080E
#define KEY_META_ETH_TYPE_14    0x080F
#define KEY_META_ETH_TYPE_15    0x0810
#define RST_CONN_META_ETH_TYPE  0x08FF

/* Host meta packets */
#if !LINUX_TCP_SERVER
#define IP_TOS_MTCP_HOST_CLOSE 0xff
#define IP_TOS_META_TC_RULE 0xfe
#else /* !LINUX_TCP_SERVER */
#define IP_TOS_HOST_MIG_FIN 0xfd
#define IP_TOS_HOST_CLOSE   0xfc
#endif /* LINUX_TCP_SERVER */

/* TCP Flags */
#define TCP_FLAG_FIN        0x01
#define TCP_FLAG_SYN        0x02
#define TCP_FLAG_RST        0x04
#define TCP_FLAG_PSH        0x08
#define TCP_FLAG_ACK        0x10

/* TCP Send Offload Flags */
#define TCP_OFFL_TSO        0x01
#define TCP_OFFL_TLS_AES    0x02

/* Hard-coded Constants */
#define SSL_PORT            443
#define HTTP_PORT           80
#define MIG_PKT_LEN         66
#define SVR_CCS_FIN_SEG_LEN  51     /* 51: TCP seg len of server change cipher spec, finished*/
#define CLI_KEX_CCS_FIN_SEG_LEN 318     /* 318: TCP seg len of client key exchange, change cipher spec, finished*/

#if USE_RTE_HWS
/* for HWS */
#define PATTERN_NUM_SYNC        3
#define ACTION_NUM_SYNC         2
#define PATTERN_NUM_JUMP        4
#define ACTION_NUM_JUMP         2
#define PATTERN_NUM_NOOP        4
#define ACTION_NUM_NOOP         2
#define PATTERN_NUM_HWS         4
#define ACTION_NUM_HWS          2

#endif /* USE_RTE_HWS */

#define htonll(x)   ((((uint64_t)htonl(x)) << 32) + htonl(x >> 32))
#define ntohll(x)   ((((uint64_t)ntohl(x)) << 32) + ntohl(x >> 32))

#ifdef MIN
#else
#define MIN(x, y)   ((int32_t)((x)-(y)) < 0 ? (x) : (y))
#endif /* MIN */

#ifdef MAX
#else
#define MAX(x, y)   ((int32_t)((x)-(y)) > 0 ? (x) : (y))
#endif /* MAX */

#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))

static inline bool
SEQ_LT(uint32_t a, uint32_t b)
{
    return (int32_t)(a - b) < 0;
}

static inline bool
SEQ_LEQ(uint32_t a, uint32_t b)
{
    return (int32_t)(a - b) <= 0;
}

static inline bool
SEQ_GT(uint32_t a, uint32_t b)
{
    return (int32_t)(a - b) > 0;
}

static inline bool
SEQ_GEQ(uint32_t a, uint32_t b)
{
    return (int32_t)(a - b) >= 0;
}

static inline uint32_t
SEQ_DIFF(uint32_t a, uint32_t b)
{
    return (uint32_t)((int32_t)(a - b));
}

#define true 1
#define false 0

#define MAX_PKT_SIZE 1500
#define TCP_RTO 1000 /* unit: ms */
#define HEALTH_CHECK 10000 /* unit: ms */

#define ETHERNET_HEADER_LEN 14
#define IP_HEADER_LEN 20
#define TCP_HEADER_LEN 20
#define TOTAL_HEADER_LEN 54

typedef
struct ssl_stat {
    uint64_t completes;
    uint64_t throughput;

    uint64_t only_tcp;
    uint64_t only_tcp_throughput;

    uint64_t rx_bytes[MAX_DPDK_PORT];
    uint64_t rx_pkts[MAX_DPDK_PORT];

    uint64_t tx_bytes[MAX_DPDK_PORT];
    uint64_t tx_pkts[MAX_DPDK_PORT];

    uint64_t rtx_bytes[MAX_DPDK_PORT];
    uint64_t rtx_pkts[MAX_DPDK_PORT];
} ssl_stat_t;

enum tcp_syn_check {
    TCP_SYN_RETRANS,
    TCP_SYN_NEW,
};

enum tcp_sequence_check {
    TCP_SEQ_OK,
    TCP_SEQ_UNDER,
    TCP_SEQ_OVER,
};

enum tcp_connection_state {
    TCP_SESSION_IDLE,
    TCP_SESSION_RECEIVED,
    TCP_SESSION_SENT,
};

enum recv_packet_type {
    SSL_HANDSHAKE,
    TCP_SYN,
    TCP_ACK,
#if LINUX_TCP_SERVER
    HOST_MIG_FIN,
    HOST_CLOSE,
#else /* LINUX_TCP_SERVER */
    MTCP_META_PACKET,
    MTCP_HOST_CLOSE,
#endif /* !LINUX_TCP_SERVER */
    TCP_FIN,
    TCP_RST,
    TCP_SYNACK,
#if OFFLOAD_AES_GCM
    PKT_TYPE_OFFL_TLS_AES,
#endif /* OFFLOAD_AES_GCM */
};

enum ssl_session_state {
    STATE_INIT,
    STATE_HANDSHAKE,
    STATE_ACTIVE,
};

enum ssl_packet_type {
    PKT_TYPE_NONE,
    PKT_TYPE_HELLO,
    PKT_TYPE_FINISH,
#if OFFLOAD_AES_GCM
    PKT_TYPE_OFFL_TLS_AES,
#endif /* OFFLOAD_AES_GCM */
};

typedef
struct pending_pkt_hdr {
    struct rte_ether_hdr ethh;
    struct rte_ipv4_hdr iph;
    struct rte_tcp_hdr tcph;
    uint16_t payload_len;
} pending_pkt_hdr_t;

typedef
struct tcp_connection {
    struct thread_context* ctx;

    int             state; // little endian
    int             onload; // little endian

    uint16_t        coreid; // little endian
    uint16_t        portid; // little endian
    uint16_t        session_id; // little endian
    uint16_t        ip_id; // little endian

    struct timespec conn_start_time;
    
    struct timespec last_interaction;

    unsigned char   client_mac[6]; // big endian
    unsigned char   server_mac[6]; // big endian

    uint32_t        client_ip; // little endian
    uint32_t        server_ip; // little endian

    uint16_t        client_port; // little endian
    uint16_t        server_port; // little endian

    uint32_t        cookie; // little endian

    uint32_t        last_recv_seq; // little endian
    uint32_t        last_recv_ack; // little endian
    uint32_t        last_recv_len; // little endian

    uint32_t        last_sent_seq; // little endian
    uint32_t        last_sent_ack; // little endian
    uint32_t        last_sent_len; // little endian

#if OFFLOAD_AES_GCM
    uint32_t        next_sent_seq;
#endif /* OFFLOAD_AES_GCM */

    uint32_t        total_sent;

    uint16_t        window;

#if USE_RTE_HWS
    /* for set pattern of jump */
    struct rte_flow_item_eth* eth_spec_jump;
    struct rte_flow_item_eth* eth_mask_jump;

    struct rte_flow_item_ipv4* ipv4_spec_jump;
    struct rte_flow_item_ipv4* ipv4_mask_jump;
    
    struct rte_flow_item_tcp* tcp_spec_jump;
    struct rte_flow_item_tcp* tcp_mask_jump;

    /* for set pattern of hws */
    struct rte_flow_item_eth* eth_spec_hws;
    struct rte_flow_item_eth* eth_mask_hws;

    struct rte_flow_item_ipv4* ipv4_spec_hws;
    struct rte_flow_item_ipv4* ipv4_mask_hws;

    struct rte_flow_item_tcp* tcp_spec_hws;
    struct rte_flow_item_tcp* tcp_mask_hws;

    /* for set action of jump, hws */
    struct rte_flow_action_jump* group_to_jump;
    struct rte_flow_action_ethdev* fwd;

    /* for jump */
    struct rte_flow_item* pattern_jump;
    struct rte_flow_action* action_jump;

    /* for hws */
    struct rte_flow_item* pattern_hws;
    struct rte_flow_action* action_hws;

    /* for destroy */
    struct rte_flow* flow_jump;
    struct rte_flow* flow_hws;

    /* for managing hws */
    int             recv_mig_fin;
    int             hws_inserted;
    int             hws_applied;
    int             hws_ready_to_del;
    int             hws_deleted;
#endif /* USE_RTE_HWS */

    pending_pkt_hdr_t pending_pkt_hdr;

    struct ssl_session* ssl_session;
    
    TAILQ_ENTRY(tcp_connection) active_session_link;
    TAILQ_ENTRY(tcp_connection) free_session_link;
} tcp_connection_t;

typedef struct ssl_crypto_op ssl_crypto_op_t;

typedef
struct ssl_session {
    uint16_t            coreid;
    int                 state;
    int                 handshake_state;
    uint16_t            num_current_records;
    int                 next_record_id;

    struct thread_context* ctx;
    tcp_connection_t*   parent;
    record_t*           current_read_record;

#if OFFLOAD_AES_GCM
	uint8_t is_offl_aead;
	struct rte_eth_tls_ctx tls_ctx;
#endif /* OFFLOAD_AES_GCM */

    protocol_version_t  version;

    session_id_t        id_;

    sequence_num_t      send_seq_num_;
    sequence_num_t      recv_seq_num_;

    uint8_t             handshake_msgs[MAX_HANDSHAKE_LENGTH];
    int                 handshake_msgs_len;

    uint8_t             send_buffer[MAX_RECORD_SIZE];
    int                 send_buffer_offset;

    uint8_t             client_write_MAC_secret[MAX_KEY_SIZE];
    uint8_t             server_write_MAC_secret[MAX_KEY_SIZE];
    uint8_t             client_write_key[MAX_KEY_SIZE];
    uint8_t             server_write_key[MAX_KEY_SIZE];
    uint8_t             client_write_IV[MAX_KEY_SIZE];
    uint8_t             server_write_IV[MAX_KEY_SIZE];
    sequence_num_t      client_write_IV_seq_num;
    sequence_num_t      server_write_IV_seq_num;

    uint8_t             server_finish_digest[12];

    uint64_t            rand_seed;

    pka_results_t*      pka_results;
    ssl_crypto_op_t*    pka_op;
    int                 waiting_crypto;
    int                 completed_crypto;

    pka_operand_t*      rsa_operand;

    security_params_t   pending_sp;
    security_params_t   read_sp;
    security_params_t   write_sp;

    TAILQ_HEAD(recv_q_head, record) recv_q;
    int                 recv_q_cnt;

    void*               pending_rsa_op;	/* ssl_crypto_op_t* */
    int                 num_cke_retransmitted;

#if VERBOSE_CONN_LAT
    struct timespec ch_time;
    struct timespec sh_sc_shd_time;
    struct timespec cke_time;
    struct timespec rsa_decrypt_time;
    struct timespec decrypt_rsa_time;
    struct timespec meta_tx_time;
    struct timespec meta_rx_time;
    struct timespec hws_insert_time;
    struct timespec hws_apply_time;
#endif /* VERBOSE_CONN_LAT */
} ssl_session_t;

typedef
struct mbuf_table {
    uint16_t len; /* length of queued packets */
    struct rte_mbuf* m_table[MAX_PKT_BURST];
} mbuf_table_t;

typedef
struct dpdk_private_context {
    mbuf_table_t rmbufs[RTE_MAX_ETHPORTS];
    mbuf_table_t wmbufs[RTE_MAX_ETHPORTS];
    struct rte_mempool* pktmbuf_pool;
    struct rte_mbuf* pkts_burst[MAX_PKT_BURST];
#ifdef RX_IDLE_ENABLE
    uint8_t rx_idle;
#endif /* RX_IDLE_ENABLE */
} dpdk_private_context_t __rte_cache_aligned;

typedef
struct thread_context {
    int ready;
    uint16_t coreid;
    struct rte_eth_stats* if_stat[MAX_DPDK_PORT];

	EVP_CIPHER_CTX* symmetric_crypto_ctx;

    struct dpdk_private_context* dpc;
    tcp_connection_t** tcp_array;

    pka_handle_t* handle;
    pka_results_t* rsa_result;
    // struct rte_ring *submit_pka_ring;
    sj_ring_t* submit_pka_ring;
    unsigned cur_crypto_cnt;
    // struct rte_ring *completed_pka_ring;
    sj_ring_t* completed_pka_ring;
    unsigned completed_crypto_cnt;

	ssl_context_t* ssl_context;
    certificate_t* certificates;

    TAILQ_HEAD(record_pool_head, record) record_pool;
    int free_record_cnt;
    int using_record_cnt;

    TAILQ_HEAD(op_pool_head, ssl_crypto_op) op_pool;
    int free_op_cnt;
    int using_op_cnt;

    int decrease;

    TAILQ_HEAD(record_trace_head, record) whole_record;
    TAILQ_HEAD(op_trace_head, ssl_crypto_op) whole_op;

#if USE_HASHTABLE_FOR_ACTIVE_SESSION
    struct hashtable* active_session_table;
#else /* !USE_HASHTABLE_FOR_ACTIVE_SESSION */
    TAILQ_HEAD(active_head, tcp_connection) active_session_q;
#endif /* !USE_HASHTABLE_FOR_ACTIVE_SESSION */
    int active_cnt;

    TAILQ_HEAD(free_head, tcp_connection) free_session_q;
    int free_cnt;

#if VERBOSE_STAT
    ssl_stat_t cur_stat;
    ssl_stat_t prev_stat;
#endif /* VERBOSE_STAT */

#if USE_RTE_HWS
    // struct rte_ring *waiting_hws_del_ring;
    sj_ring_t* waiting_hws_del_ring;
#endif /* USE_RTE_HWS */
} thread_context_t;

static const struct rte_eth_rxconf rx_conf = {
    .rx_thresh = {
        .pthresh    =   RX_PTHRESH,
        .hthresh    =   RX_HTHRESH,
        .wthresh    =   RX_WTHRESH,
    },
    .rx_free_thresh =   32,
};

static const struct rte_eth_txconf tx_conf = {
    .tx_thresh = {
        .pthresh    =   TX_PTHRESH,
        .hthresh    =   TX_HTHRESH,
        .wthresh    =   TX_WTHRESH,
    },
    .tx_free_thresh =   0,
    .tx_rs_thresh   =   0,
#if RTE_VERSION < RTE_VERSION_NUM(18, 5, 0, 0)
    .txq_flags      =   0x0,
#endif /* RTE_VERSION < RTE_VERSION_NUM(18, 5, 0, 0) */
};

#define OFF_PROTO 1234

/* Global variables */
extern ssl_stat_t cur_global_stat, prev_global_stat;

extern uint8_t nic_key[MAX_KEY_SIZE];
extern uint8_t nic_key_size;
extern uint8_t nic_iv[MAX_KEY_SIZE];
extern uint8_t nic_iv_size;
extern uint8_t host_key[MAX_KEY_SIZE];
extern uint8_t host_key_size;
extern uint8_t host_iv[MAX_KEY_SIZE];
extern uint8_t host_iv_size;

extern struct rte_mempool* pktmbuf_pool[MAX_CPUS];
extern thread_context_t* ctx_array[MAX_CPUS];
extern uint32_t complete_conn[MAX_CPUS];
extern uint8_t port_type[MAX_DPDK_PORT];
extern int max_conn;
extern int local_max_conn;

extern uint8_t t_major;
extern uint8_t t_minor;

extern pka_instance_t instance;
extern pka_barrier_t thread_start_barrier;
extern pka_handle_t pka_handle;

extern ssl_context_t ctx_example;

extern uint64_t pka_get_result_min;
extern uint64_t pka_get_result_max;
extern uint64_t pka_get_result_sum;
extern uint64_t pka_get_result_cnt;
extern uint64_t pka_get_result_fail_cnt;
extern uint64_t pka_get_result_success_cnt;

/* Functions */
/*--------------------------------------------------------------------------*/
/* main.c */
void
global_destroy(void);

/*--------------------------------------------------------------------------*/
/* tcp.c */
void
hex_dump(const void* data, size_t len);

int
ssloff_main_loop(__attribute__((unused)) void* arg);

int
abort_session(ssl_session_t* sess);

#if LINUX_TCP_SERVER
int
send_meta_packet(int core_id, int port, tcp_connection_t* conn);
#else /* !LINUX_TCP_SERVER */
int
send_meta_packet(int coreid, int port, tcp_connection_t* conn,
				 uint32_t next_recv_seq, uint32_t next_recv_ack,
				 uint8_t* payload, uint16_t payload_len);
#endif /* !LINUX_TCP_SERVER */

int
send_tcp_packet(tcp_connection_t* conn, uint8_t* payload,
                uint16_t len, uint8_t flags, uint8_t offl_flags);

/*--------------------------------------------------------------------------*/
/* dpdk_io.c */
void
free_pkts(struct rte_mbuf** mtable, unsigned len);

int32_t
recv_pkts(uint16_t core_id, uint16_t port);

uint8_t*
get_rptr(uint16_t core_id, uint16_t port, int index, uint16_t* len);

int
send_pkts(uint16_t core_id, uint16_t port);

#if OFFLOAD_AES_GCM
struct rte_mbuf *
get_wmbuf(uint16_t core_id, uint16_t port, uint16_t pktsize);
#endif /* OFFLOAD_AES_GCM */

uint8_t*
get_wptr(uint16_t core_id, uint16_t port, uint16_t pktsize, int hw_csum, int l4_len);

#if USE_RTE_HWS
/* rte_flow (sync) */
int
ins_sync_hws_recv(uint16_t port, tcp_connection_t *conn);
/* rte_flow_async */
/* init stage (recv) */
static int
flow_configure(uint16_t port_id);

static struct rte_flow_pattern_template *
create_pattern_template_jump_recv(uint16_t port_id, struct rte_flow_error *error);

static struct rte_flow_pattern_template *
create_pattern_template_hws_recv(uint16_t port_id, struct rte_flow_error *error);

static struct rte_flow_actions_template *
create_actions_template_jump_recv(uint16_t port_id, struct rte_flow_error *error);

static struct rte_flow_actions_template *
create_actions_template_hws_recv(uint16_t port_id, struct rte_flow_error *error);

struct rte_flow_template_table *
create_table_jump_recv(uint16_t port_id);

struct rte_flow_template_table *
create_table_hws_recv(uint16_t port_id);

/* runtime (recv) */
void
fill_pattern_jump_recv(tcp_connection_t *conn);

void
fill_pattern_hws_recv(tcp_connection_t *conn);

void
fill_action_jump_recv(tcp_connection_t *conn);

void
fill_action_hws_recv(tcp_connection_t *conn);

int
ins_async_hws_recv(tcp_connection_t *conn, 
              struct rte_flow_template_table *table_jump, 
              struct rte_flow_template_table *table_hws);

/* init stage (send) */
static struct rte_flow_pattern_template *
create_pattern_template_hws_send(uint16_t port_id, struct rte_flow_error *error);

static struct rte_flow_actions_template *
create_actions_template_hws_send(uint16_t port_id, struct rte_flow_error *error);

struct rte_flow_template_table *
create_table_hws_send(uint16_t port_id);

/* runtime (send) */
struct rte_flow_item *
fill_pattern_hws_send();

struct rte_flow_action *
fill_action_hws_send();

int
ins_async_hws_send(struct rte_flow_template_table *table_jump, 
                   struct rte_flow_template_table *table_hws);

int
ins_sync_hws_send();

/* deletion */
int
del_hws_async(tcp_connection_t *conn);

/* push & pull */
void
rte_flow_pull_and_push(thread_context_t* ctx);

extern struct rte_flow_template_table *template_table_jump;
extern struct rte_flow_template_table *template_table_hws;
extern struct rte_flow_template_table *template_table_hws_send;

#endif /* USE_RTE_HWS */
/*--------------------------------------------------------------------------*/
/* ssl.c */

pka_results_t*
malloc_results(uint32_t result_cnt, uint32_t buf_len);

void
clear_results(pka_results_t* results);

void
free_results(pka_results_t* results);

void
handle_submitted_pka(thread_context_t* ctx);

void
handle_completed_pka(thread_context_t* ctx);

int
get_processed_crypto(ssl_session_t* sess);

void
handle_pending_pka(thread_context_t* ctx);

int
process_ssl_packet(tcp_connection_t* tcp_conn,
                   uint8_t* payload, uint16_t payload_len);
void
init_random(ssl_session_t* sess, uint8_t* random, unsigned size);

void
remove_pending_rsa_op(ssl_session_t* sess);
 
int
process_session_read(ssl_session_t* sess);

int
send_server_hello(ssl_session_t* sess);

int
send_certificate(ssl_session_t* sess);

int
send_server_hello_done(ssl_session_t* sess);

int
send_change_cipher_spec(ssl_session_t* sess);

int
send_server_finish(ssl_session_t* sess);

#endif /* __SSLOFF_H__ */
