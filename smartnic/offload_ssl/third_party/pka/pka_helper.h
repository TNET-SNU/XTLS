// SPDX-FileCopyrightText: © 2023 NVIDIA Corporation & affiliates.
// SPDX-License-Identifier: BSD-3-Clause

#ifndef PKA_HELPER_H
#define PKA_HELPER_H

#ifdef  __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

#include <pka.h>
#include <pka_utils.h>

// 64-bit processor
#ifdef BN_ULONG
#define PKA_ULONG   BN_ULONG
#else
#define PKA_ULONG   uint64_t
#endif

#ifdef BN_BYTES
#define PKA_BYTES   BN_BYTES
#else
#define PKA_BYTES   8
#endif

#define PKA_BITS    (PKA_BYTES * 8)

#define PKA_ENGINE_QUEUE_CNT         8
#define PKA_ENGINE_RING_CNT          4
#define PKA_ENGINE_QUEUE_CNT_BF3_MB 16
#define PKA_ENGINE_RING_CNT_BF3_MB   4
#define PKA_ENGINE_QUEUE_CNT_BF3_HB 24
#define PKA_ENGINE_RING_CNT_BF3_HB   4

#define PKA_ENGINE_INSTANCE_NAME    "SSL engine"

#define PKA_MAX_OBJS                 32       // 32  objs
#define PKA_CMD_DESC_MAX_DATA_SIZE  (1 << 14) // 16K bytes.
#define PKA_RSLT_DESC_MAX_DATA_SIZE (1 << 12) //  4K bytes.

// This encapsulates big number information. This structure enables
// compatibility to OpenSSL
typedef struct {
    PKA_ULONG *d;   // Pointer to an array of 'PKA_BITS' bit chunks.
    int top;        // Index of last used d +1.
    int dmax;       // Size of the d array.
    int neg;        // one if the number is negative.
    int flags;
} pka_bignum_t;

// This encapsulates the engine information. As of now, the PKA library
// does not support mult-processes, a single engine is created. This engine
// allows multiple handlers to share the PKA instance.
typedef struct {
    pka_instance_t instance;
    bool           valid;
} pka_engine_info_t;

void copy_operand(pka_operand_t *src, pka_operand_t *dst);

// This converts BIGNUM to pka_operand_t
// You should pass pka_bignum_t* instead of BIGNUM*
pka_operand_t *bignum_to_operand(pka_bignum_t *bignum);

#ifdef  __cplusplus
}
#endif

#endif // PKA_HELPER_H
