#pragma once

#include <ctype.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include <pka.h>
#include <pka_utils.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "helpers.h"
#include "pka_helper.h"
/*---------------------------------------------------------------------------*/
#define TEST_RSA                1

#define PKA_MAX_RING_CNT        64
#define PKA_MAX_QUEUE_CNT       32
#define PKA_MAX_OBJS            32
#define CMD_QUEUE_SIZE          (1 << 14) * PKA_MAX_OBJS
#define RSLT_QUEUE_SIZE         (1 << 12) * PKA_MAX_OBJS

#define MAX_THREAD_NUM          16
#define MAX_OUTSTANDING_CMD_NUM 512

#define TRUE                    1
#define FALSE                   0

#define DBG_MODE                FALSE
#define CHECK_CORRECTNESS       FALSE
#define MULTI_PKA_INSTANCE      FALSE
/* Test Effect of Rand Operand
 * If you want to apply RAND_OPERAND, turn off the CHECK_CORRECTNESS
 * !RAND_OPERAND_0 && !RAND_OPERAND_1: ideal
 * RAND_OPERAND_0 && !RAND_OPERAND_1: pseudo-practical
 * RAND_OPERAND_0 && RAND_OPERAND_1: practical
 */
#define RAND_OPERAND_0          TRUE
#define RAND_OPERAND_1          TRUE
#define PKA_RNG                 TRUE

typedef struct {
    size_t ecdsa_done;
    size_t ecdh_done;
} tls13_op_cnt_t;
