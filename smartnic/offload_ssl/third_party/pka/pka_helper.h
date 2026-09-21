// SPDX-FileCopyrightText: © 2023 NVIDIA Corporation & affiliates.
// SPDX-License-Identifier: BSD-3-Clause

#ifndef PKA_HELPER_H
#define PKA_HELPER_H

#ifdef  __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

#include <rte_random.h>

#include <pka.h>
#include <pka_utils.h>
/*---------------------------------------------------------------------------*/
#define UNUSED(x) (void)(x)

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
/*---------------------------------------------------------------------------*/
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
/*---------------------------------------------------------------------------*/
/* helpers */
void byte_swap_copy(uint8_t *dest, uint8_t *src, uint32_t len);

void copy_operand(pka_operand_t *src, pka_operand_t *dst);

/*
 * This function changes string to operand.
 * 
 * @str     The string to convert to operand for RSA
 * @op      The operand which will contain the result
 * @len     The length of string
 * @endian  The endian to be used in conversion
 *          0: Little Endian
 *          1: Big Endian
 */
void
string_to_operand(uint8_t* str, pka_operand_t* op, uint16_t len, int endian);

/*
 * This function changes to operand to string at most max_len.
 *
 * @op      The operand which will be converted to string
 * @str     The pointer which will contain the result
 * @max_len The maximum length of result string
 */
void
operand_to_string(pka_operand_t* op, uint8_t* str, uint16_t max_len);
/*---------------------------------------------------------------------------*/
/* RSA */
// This converts BIGNUM to pka_operand_t
// You should pass pka_bignum_t* instead of BIGNUM*
pka_operand_t *bignum_to_operand_rsa(pka_bignum_t *bignum);
/*---------------------------------------------------------------------------*/
/* ECDHE && ECDSA-related*/
pka_operand_t *make_operand_ecdsa(PKA_ULONG *bn_buf_ptr,
                                         uint32_t   buf_len,
                                         uint32_t   buf_max_len,
                                         uint8_t    big_endian);

pka_operand_t *bignum_to_operand(pka_bignum_t *bignum);

uint32_t operand_bit_len(pka_operand_t *operand);

uint32_t operand_byte_len(pka_operand_t *operand);

pka_operand_t *make_operand(uint8_t  *big_endian_buf_ptr,
                            uint32_t  buf_len,
                            uint8_t   big_endian);

void set_pka_operand(pka_operand_t *operand,
                     uint8_t       *big_endian_buf_ptr,
                     uint32_t       buf_len,
                     uint8_t        big_endian);

pka_operand_t *rand_operand(pka_handle_t  handle,
                            uint32_t      bit_len,
                            bool          make_odd);

ecc_curve_t *make_ecc_curve(uint8_t *big_endian_buf_p_ptr,
                            uint32_t p_len,
                            uint8_t *big_endian_buf_a_ptr,
                            uint32_t a_len,
                            uint8_t *big_endian_buf_b_ptr,
                            uint32_t b_len,
                            uint8_t  big_endian);

ecc_point_t *make_ecc_point(ecc_curve_t *curve,
                            uint8_t     *big_endian_buf_x_ptr,
                            uint32_t     buf_x_len,
                            uint8_t     *big_endian_buf_y_ptr,
                            uint32_t     buf_y_len,
                            uint8_t      big_endian);

ecc_point_t *make_mont_ecc_point(ecc_mont_curve_t *curve,
                                 uint8_t     *big_endian_buf_x_ptr,
                                 uint32_t     buf_x_len,
                                 uint8_t     *big_endian_buf_y_ptr,
                                 uint32_t     buf_y_len,
                                 uint8_t      big_endian);

pka_operand_t *malloc_ecdhe_priv_key(pka_operand_t *max_plus_1);

// pka_operand_t *rand_non_zero_integer(pka_handle_t   handle,
//                                      pka_operand_t *max_plus_1);

void rand_non_zero_integer(pka_handle_t   handle,
                           pka_operand_t *result,
                           pka_operand_t *max_plus_1);

void rand_non_zero_integer_wo_syscall(pka_handle_t   handle,
                                      pka_operand_t *result,
                                      pka_operand_t *max_plus_1);
                                      
void rand_non_zero_integer_w_pka_hwrng_and_clamping(pka_handle_t   handle,
                                                    pka_operand_t *result,
                                                    pka_operand_t *max_plus_1);

void rand_non_zero_integer_w_rte_rand_and_clamping(pka_handle_t   handle,
                                                    pka_operand_t *result,
                                                    pka_operand_t *max_plus_1);
/*---------------------------------------------------------------------------*/                                 
#ifdef  __cplusplus
}
#endif

#endif // PKA_HELPER_H
