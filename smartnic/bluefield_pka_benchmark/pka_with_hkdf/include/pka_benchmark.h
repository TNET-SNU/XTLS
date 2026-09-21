#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>

#include <pka.h>
#include <pka_utils.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>

#include "helpers.h"
#include "pka_helper.h"
/*---------------------------------------------------------------------------*/
#define TEST_RSA 0

#define PKA_MAX_RING_CNT 64
#define PKA_MAX_QUEUE_CNT 32
#define PKA_MAX_OBJS 32
#define CMD_QUEUE_SIZE (1 << 14) * PKA_MAX_OBJS
#define RSLT_QUEUE_SIZE (1 << 12) * PKA_MAX_OBJS

#define MAX_THREAD_NUM 16
#define MAX_OUTSTANDING_CMD_NUM 512

#define TRUE                1
#define FALSE               0

#define DBG_MODE            FALSE
#define CHECK_CORRECTNESS   FALSE
#define MULTI_PKA_INSTANCE  FALSE
/* Test Effect of Rand Operand
 * If you want to apply RAND_OPERAND, turn off the CHECK_CORRECTNESS
 * !RAND_OPERAND_0 && !RAND_OPERAND_1: ideal
 * RAND_OPERAND_0 && !RAND_OPERAND_1: pseudo-practical
 * RAND_OPERAND_0 && RAND_OPERAND_1: practical
 */
#define RAND_OPERAND_0      TRUE
#define RAND_OPERAND_1      TRUE
#define PKA_RNG             TRUE

typedef struct {
    size_t ecdsa_done;
    size_t ecdh_done;
} tls13_op_cnt_t;

typedef struct {
    int tid;
    int outstanding_pka_num;
    int outstanding_hkdf_num;
} thread_ctx_t;

enum {
    HANDSHAKE_KEY_DERIVE,
    APP_KEY_DERIVE,
};

enum {
    KEY_PAIR_GEN = 0,
    ECDH_KEY_CALCULATE,
    ECDSA_SIG_GEN,
};
