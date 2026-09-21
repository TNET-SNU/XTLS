#pragma once

#include <stdint.h>
#include <linux/tls.h>
#include <unistd.h>
#include <time.h>
#include <sys/queue.h>
#include <dirent.h>
/*---------------------------------------------------------------------------*/
/* Constants */
#define MAX_THREAD_NUM              16
/* IP related */
#define SERVER_IP                   0x0A000002
/* TCP related */
#define MAX_CONN                    65536
#define TCP_BUF_SIZE                1460
#define TCPOPT_NUM                  4
#define ACK_BUF_SIZE                14
/* SSL related */
#define SSL_PORT                    443
#define MAX_KEY_SIZE                128
#define TLS_HDR_SIZE                5
#define TLS_CLOSE_BUF_SIZE          1024
/* HTTP related */
#define HTTP_HEADER_LEN             1460
#define HTTP_GET                    "GET"
#define URL_LEN                     256
/* File related */
#define MAX_FILES                   256
#define NAME_LIMIT                  256
#define FULL_PATH_LIMIT             512
#define FILE_SIZE_THRESHOLD         0 // 0 // 1000000000000 // 1 TB
/* Meta packet related */
#define WEIRD_SYN                   0x0800
#define KEY_META_ETH_TYPE_0         0x0801
#define KEY_META_ETH_TYPE_1         0x0802
#define KEY_META_ETH_TYPE_2         0x0803
#define KEY_META_ETH_TYPE_3         0x0804
#define KEY_META_ETH_TYPE_4         0x0805
#define KEY_META_ETH_TYPE_5         0x0806
#define KEY_META_ETH_TYPE_6         0x0807
#define KEY_META_ETH_TYPE_7         0x0808
#define KEY_META_ETH_TYPE_8         0x0809
#define KEY_META_ETH_TYPE_9         0x080A
#define KEY_META_ETH_TYPE_10        0x080B
#define KEY_META_ETH_TYPE_11        0x080C
#define KEY_META_ETH_TYPE_12        0x080D
#define KEY_META_ETH_TYPE_13        0x080E
#define KEY_META_ETH_TYPE_14        0x080F
#define KEY_META_ETH_TYPE_15        0x0810
#define RST_CONN_META_ETH_TYPE      0x08FF
#define RECV_META_BUF_SIZE          1460
#define SND_META_PKT_SIZE           64
#define MAX_DPU_CORE                16
/* Etc. */
#define E9                          1000000000L
#define E6                          1000000L
#define WARM_UP_SEC                 15
/*---------------------------------------------------------------------------*/
/* Enums & structs */
typedef struct hashtable hashtable_t;

/* Thread-related */
typedef struct thread_args {
    const char* www_main;
    int core_id;
} thread_args_t;

typedef struct thread_ctx {
    int core_id;
    int meta_sock;
    int epfd;
    hashtable_t* ht_conn;
    DIR* dir;
} thread_ctx_t;

/* SSL-related */
typedef struct protocol_version {
    uint8_t major;
    uint8_t minor;
} protocol_version_t;

typedef enum {
    NO_CIPHER = 0,
    RC4 = 1,
    RC2 = 2,
    DES = 3,
    DES3 = 4,
    DES40 = 5,
    AES = 6
} bulk_cipher_algorithm_t;

typedef enum {
    STREAM = 1,
    BLOCK = 2,
    AEAD = 3
} cipher_type_t;

typedef enum {
    NO_MAC      = 0,
    MAC_MD5     = 1,
    MAC_SHA1    = 2,
	MAC_SHA256  = 3,
	MAC_SHA384  = 4,
	MAC_SHA512  = 5
} mac_algorithm_t;

typedef struct ssl_crypto_info {
    struct tls12_crypto_info_aes_gcm_256 crypto_info_rx;
    struct tls12_crypto_info_aes_gcm_256 crypto_info_tx;
} ssl_crypto_info_t;

/* Conn. state-related */
typedef enum sock_state {
    DEFAULT,
    INIT,
    CONNECTED,
    READY_TO_RECV,
    TLS_HS_RECVED,
    HTTP_REQ_RECVED,
    HTTP_RESP_SENT,
    CLOSE_META_PKT_SENT,
    WAIT_TCP_FIN,
    CLOSED,
    ERRORED,
} sock_state_t;

typedef enum req_handler_result {
    RECV_ERR = -2,
    RECV_CONTINUE = -1,
    RECV_OK = 0,
    RECV_TLS = 1,
    RECV_CLOSE_NOTIFY = 2,
    RECV_FIN = 3,
} req_handler_result_t;

/* Meta packet-related */
typedef enum meta_type {
    META_TYPE_UNKNOWN = -1,
    META_TYPE_KEY = 0,
    META_TYPE_RST_CONN = 1,
    META_TYPE_WEIRD_SYN = 2,
} meta_type_t;

typedef struct ssl_meta {
    uint16_t session_id; // 2B

    protocol_version_t  version; // 2B

    bulk_cipher_algorithm_t bulk_cipher_algorithm; // 4B
    cipher_type_t cipher_type; // 4B
    mac_algorithm_t mac_algorithm; // 4B

    uint8_t mac_key_size; // 1B
    uint8_t client_write_MAC_secret[MAX_KEY_SIZE]; // 128B
    uint8_t server_write_MAC_secret[MAX_KEY_SIZE]; // 128B

    uint8_t enc_key_size; // 1B
    uint8_t client_write_key[MAX_KEY_SIZE]; // 128B
    uint8_t server_write_key[MAX_KEY_SIZE]; // 128B

    uint8_t fixed_iv_length; // 1B
    uint8_t client_write_IV[MAX_KEY_SIZE]; // 128B
    uint8_t server_write_IV[MAX_KEY_SIZE]; // 128B
} ssl_meta_t;

typedef struct meta_info {
    uint32_t client_ip;     // big-endian
    uint16_t client_port;   // big-endian
    uint32_t seq_num;
    uint32_t ack_num;
    ssl_meta_t *ssl_meta;
} meta_info_t;

typedef struct conn_state {
    int sock_fd;
    uint32_t sock_state;
    ssize_t recv_bytes;
    meta_info_t meta_info;
    struct ssl_crypto_info crypto_info;
    int keep_alive; // for HTTP keep-alive
    int scode;
    uint8_t sccs_sf_buf[RECV_META_BUF_SIZE];
    int record_len;

    int hdr_sent;
    size_t hdr_len;
    off_t hdr_offset;
    size_t hdr_remain;
    char hdr_buf[HTTP_HEADER_LEN];

    int file_idx; // file index in file cache
    size_t file_size; // file size in file cache (4GB is limitation)
    char req_buf[HTTP_HEADER_LEN]; // buffer for http request
    size_t req_len; // length for http request
    int resp_fd; // file descriptor for response file
    off_t resp_offset; // offset for http response
    size_t resp_remain; // remaining bytes to send

    int num_of_recved_key_meta_pkt;

    TAILQ_ENTRY(conn_state) active_connection_link;

#if EVALUATION
    struct timespec conn_start, conn_fin;
#endif /* EVALUATION */
} conn_state_t;
/*---------------------------------------------------------------------------*/
/* Macro functs */
#define UNUSED(x) (void)(x)

#define pr_perror(fmt, ...) ({ fprintf(stderr, "%s:%d: " fmt " : %m\n", __func__, __LINE__, ##__VA_ARGS__); -1; })

#define TRACE_CONFIG(f, m...) fprintf(stdout, f, ##m)

#define TRACE_INFO(f, m...) (void)0

#define TRACE_ERROR(f, ...) do { fprintf(stderr, f, ##__VA_ARGS__); } while (0)

#define SPACE_OR_TAB(x)  ((x) == ' '  || (x) == '\t')

#if MEASURE_DELAY
#define MEASURE(name, cmd)                                              \
    do                                                                  \
    {                                                                   \
        struct timespec _start1, _start2, _end1, _end2;                 \
        long _time1, _time2;                                            \
        clock_gettime(CLOCK_MONOTONIC, &_start1);                       \
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &_start2);               \
        cmd;                                                            \
        clock_gettime(CLOCK_MONOTONIC, &_end1);                         \
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &_end2);                 \
        _time1 = (_end1.tv_sec - _start1.tv_sec) * E9 +                 \
                 (_end1.tv_nsec - _start1.tv_nsec);                     \
        _time2 = (_end2.tv_sec - _start2.tv_sec) * E9 +                 \
                 (_end2.tv_nsec - _start2.tv_nsec);                     \
        fprintf(stderr, "[%-40s] Wallclock time: %.2lf, Thread time: %.2lf\n", \
                name,                                                   \
                (double)_time1 / E9 * E6,                               \
                (double)_time2 / E9 * E6);                              \
    } while (/* CONSTCOND */ 0);
#else /* !MEASURE_DELAY */
#define MEASURE(name, cmd)                                              \
    do                                                                  \
    {                                                                   \
        cmd;                                                            \
    } while (/* CONSTCOND */ 0);
#endif /* !MEASURE_DELAY */

#if GET_TIME
#define PRINT_CUR_TIME(name)                                                   \
    do {                                                                       \
        struct timespec _ts;                                                   \
        clock_gettime(CLOCK_REALTIME, &_ts);                                   \
        long long _time_us = (long long)_ts.tv_sec * E6 + _ts.tv_nsec / 1000;  \
        fprintf(stderr, "[%-40s] current time (us): %lld \n", name, _time_us % E6); \
    } while (0)
#else /* !GET_TIME */
#define PRINT_CUR_TIME(name) do {} while (0)
#endif /* !GET_TIME */

#ifdef likely
#undef likely
#endif /* likely */
#define likely(x) __builtin_expect(!!(x), 1)

#ifdef unlikely
#undef unlikely
#endif /* unlikely */
#define unlikely(x) __builtin_expect(!!(x), 0)

#if EVALUATION
extern struct timeval cur_tv, prev_tv;
extern uint64_t total_conns;
#endif /* EVALUATION */
/*---------------------------------------------------------------------------*/
