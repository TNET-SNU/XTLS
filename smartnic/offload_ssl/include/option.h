#ifndef __OPTION_H__
#define __OPTION_H__

#include "string.h"

#define UNUSED(x) (void)(x)

#ifndef TRUE
#define TRUE 1
#endif /* TRUE */

#ifndef FALSE
#define FALSE 0
#endif /* FALSE */

#ifdef likely
#undef likely
#endif /* likely */

#ifdef unlikely
#undef unlikely
#endif /* unlikely */

#ifdef dmb
#undef dmb
#endif /* dmb */

/* print msgs (VERBOSE_STAT -> VERBOSE_STAT_0/1) */
#define VERBOSE_INIT                     FALSE
#define VERBOSE_TCP                      FALSE
#define VERBOSE_SSL                      FALSE
#define VERBOSE_STATE                    FALSE
#define VERBOSE_CHUNK                    FALSE
#define VERBOSE_KEY                      FALSE
#define VERBOSE_CERT                     FALSE
#define VERBOSE_SIG                      FALSE
#define VERBOSE_AES                      FALSE
#define VERBOSE_GCM                      FALSE
#define VERBOSE_MAC                      FALSE
#define VERBOSE_DATA                     FALSE
#define VERBOSE_STAT                     FALSE
#define VERBOSE_STAT_0                   FALSE
#define VERBOSE_STAT_1                   FALSE
#define VERBOSE_HOST                     FALSE
#define VERBOSE_DPDK                     FALSE
#define VERBOSE_HWS                      FALSE
#define VERBOSE_RECV                     FALSE
#define VERBOSE_SEND                     FALSE
#define CRYPTO_GETTIME_FLAG              FALSE

/* For debugging */
#define VERBOSE_PER_SEC                  TRUE
#define VERBOSE_RECV_Q_CNT               FALSE
#define VERBOSE_IF_STAT                  TRUE
#define VERBOSE_META_PKT                 FALSE
#define VERBOSE_HWS_RULES                FALSE
#define VERBOSE_RST                      FALSE
#define VERBOSE_FIN                      FALSE
#define VERBOSE_TCP_HS                   FALSE
#define VERBOSE_CONN_LAT                 FALSE
#define VERBOSE_PKA_OP                   FALSE
#define VERBOSE_PENDING_PKA_OP           FALSE
#define VERBOSE_PKA_GET_RESULT           FALSE
#define VERBOSE_RTE_RING_EQ              FALSE
#define VERBOSE_RTE_RING_DQ              FALSE
#define VERBOSE_EFFECTIVE_LOOP           FALSE

/* optimizations */
/* for old SmartTLS: ONLOAD, USE_RTE_HWS */
/* for new SmartTLS: LINUX_TCP_SERVER, ONLOAD, USE_RTE_HWS, CONN_MIG,
   USE_HASHTABLE_FOR_ACTIVE_SESSION */

#define ONLOAD                           1
#define USE_HASHTABLE_FOR_ACTIVE_SESSION 1
#define USE_RTE_HWS                      1
#define ZERO_COPY_RECV                   0 /* No performance gain */
#define LINUX_TCP_SERVER                 1

#define OFFLOAD_AES_GCM                  0
#define RTE_FLOW_SYNC                    0
#define RTE_FLOW_JUMP                    0

#define TEST                             0 // for testing
#define FWD_ONLY_APPDATA                 1 // for testing
#define HKDF_TWICE                       0 // for testing
#define PKA_TWICE                        0 // for testing
#define REMOVE_HWS                       1 // for testing

#define MODIFY_FLAG                      1
#define DEBUG_FLAG                       0
#define DEBUG_TLS_1_3                    0

#if ONLOAD
#define NO_TLS 0
#endif /* ONLOAD */

#define ENCRYPT_META FALSE

#include <pka.h>
#include <pka_utils.h>

#include "pka_helper.h"

/* debug */
/* for Macro functs */
#define MEASURE_DELAY             0
#define GET_TIME                  0
#define E9                        1000000000L
#define E6                        1000000L

/* Macro functs */
#define DEBUG_PRINT(fmt, args...) fprintf(stderr, "" fmt "", ##args)
#if MEASURE_DELAY
#define MEASURE(name, cmd)                                                     \
    do {                                                                       \
        struct timespec _start1, _start2, _end1, _end2;                        \
        long _time1, _time2;                                                   \
        clock_gettime(CLOCK_MONOTONIC, &_start1);                              \
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &_start2);                      \
        cmd;                                                                   \
        clock_gettime(CLOCK_MONOTONIC, &_end1);                                \
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &_end2);                        \
        _time1 = (_end1.tv_sec - _start1.tv_sec) * E9 +                        \
                 (_end1.tv_nsec - _start1.tv_nsec);                            \
        _time2 = (_end2.tv_sec - _start2.tv_sec) * E9 +                        \
                 (_end2.tv_nsec - _start2.tv_nsec);                            \
        fprintf(stderr, "[%-20s] Wallclock time: %.2lf, Thread time: %.2lf\n", \
                name, (double)_time1 / E9 * E6, (double)_time2 / E9 * E6);     \
    } while (/* CONSTCOND */ 0);
#else /* !MEASURE_DELAY */
#define MEASURE(name, cmd)                                                     \
    do {                                                                       \
        cmd;                                                                   \
    } while (/* CONSTCOND */ 0);
#endif /* !MEASURE_DELAY */

#if GET_TIME
#define PRINT_CUR_TIME(name)                                                   \
    do {                                                                       \
        struct timespec _ts;                                                   \
        clock_gettime(CLOCK_REALTIME, &_ts);                                   \
        long long _time_us = (long long)_ts.tv_sec * E6 + _ts.tv_nsec / 1000;  \
        fprintf(stderr, "[%-20s] current time (us): %lld \n", name,            \
                _time_us % E6);                                                \
    } while (0)
#else /* !GET_TIME */
#define PRINT_CUR_TIME(name)                                                   \
    do {                                                                       \
    } while (0)
#endif /* !GET_TIME */

/* #define PKA_RING_CNT 4 */
#define PKA_RING_CNT    10
#define PKA_QUEUE_CNT   32
#define PKA_MAX_OBJS    32

/* note: Maximum queue size should not exceed 8MB (= PKA_QUEUE_MASK_SIZE).
   Also, (1 << 14)*PKA_MAX_OBJS does not work with RSA 4096 bit
   because of memory overflow issue in pka_queue_cmd_dequeue() */
#define CMD_QUEUE_SIZE  (1 << 14) * PKA_MAX_OBJS
#define RSLT_QUEUE_SIZE (1 << 12) * PKA_MAX_OBJS
#define MAX_THREAD_NUM  16
#define MAX_SESSIONS    32768

typedef struct option {
    char *key_file;
    char *key_passwd;
} option_t;

extern option_t option;

#endif /* __OPTION_H__ */
