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
/* #include <pka_vectors.h> */

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>

#include "helper/pka_helper.h"
/*---------------------------------------------------------------------------*/
#define PKA_MAX_RING_CNT 64
#define PKA_MAX_QUEUE_CNT 32
#define PKA_MAX_OBJS 32
#define CMD_QUEUE_SIZE (1 << 14) * PKA_MAX_OBJS
#define RSLT_QUEUE_SIZE (1 << 12) * PKA_MAX_OBJS

#define MAX_THREAD_NUM 16

#define UNUSED(x) (void)(x)

#define TRUE                1
#define FALSE               0

#define DBG_MODE            FALSE
#define CHECK_CORRECTNESS   FALSE
#define MULTI_PKA_INSTANCE  FALSE
