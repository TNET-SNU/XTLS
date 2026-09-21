//
//   BSD LICENSE
//
//   Copyright(c) 2016 Mellanox Technologies, Ltd. All rights reserved.
//   All rights reserved.
//
//   Redistribution and use in source and binary forms, with or without
//   modification, are permitted provided that the following conditions
//   are met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in
//       the documentation and/or other materials provided with the
//       distribution.
//     * Neither the name of Mellanox Technologies nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
//   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
//   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
//   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
//   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
//   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
//   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
//   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
//   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

#ifndef PKA_HELPER_H
#define PKA_HELPER_H

#ifdef  __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>

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

#define PKA_ENGINE_QUEUE_CNT        4
#define PKA_ENGINE_RING_CNT         8

#define PKA_ENGINE_INSTANCE_NAME    "SSL engine"

#define PKA_MAX_OBJS                 32       // 32  objs
#define PKA_CMD_DESC_MAX_DATA_SIZE  (1 << 14) // 16K bytes.
#define PKA_RSLT_DESC_MAX_DATA_SIZE (1 << 12) //  4K bytes.

#define MAX_BUF     (260 * 4)  // EIP154 max byte length is actually 258 * 4
#define MAX_ECC_BUF (25  * 4)  // EIP154 max ECC  length is actually  24 * 4

#define LOG(min_verbosity, fmt_and_args...)    \
    ({                                         \
        if (min_verbosity <= verbosity)        \
            PKA_PRINT(PKA_TEST, fmt_and_args); \
    })
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
/* helper functions - operand related */
// This converts BIGNUM to pka_operand_t
// You should pass pka_bignum_t* instead of BIGNUM*
pka_operand_t *bignum_to_operand(pka_bignum_t *bignum);

pka_operand_t *malloc_operand(uint32_t buf_len);

pka_operand_t *make_operand(uint8_t  *big_endian_buf_ptr,
                               uint32_t  buf_len,
                               uint8_t   big_endian);

pka_operand_t *rand_operand(pka_handle_t  handle,
                            uint32_t      bit_len,
                            bool          make_odd);

void set_pka_operand(pka_operand_t *operand,
                     uint8_t       *big_endian_buf_ptr,
                     uint32_t       buf_len,
                     uint8_t        big_endian);

uint32_t operand_bit_len(pka_operand_t *operand);

uint32_t operand_byte_len(pka_operand_t *operand);

void copy_operand(pka_operand_t *original, pka_operand_t *copy);

void print_operand(char *prefix, pka_operand_t *operand, char *suffix);

void free_operand(pka_operand_t *operand);

// pka_results_t* malloc_results(uint32_t result_cnt, uint32_t buf_len);
/*---------------------------------------------------------------------------*/
/* helper functions - ecc/ecdsa related*/
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
/*---------------------------------------------------------------------------*/
/* helper functions - miscellaneous */
pka_operand_t *rand_non_zero_integer(pka_handle_t   handle,
									 pka_operand_t *max_plus_1);

void rand_non_zero_integer_wo_syscall(pka_handle_t   handle,
                                      pka_operand_t *result,
                                      pka_operand_t *max_plus_1);

void rand_non_zero_integer_wo_syscall_32bytes(pka_handle_t   handle,
                                              pka_operand_t *result);

void rand_non_zero_integer_w_pka_hwrng(pka_handle_t   handle,
                                       pka_operand_t *result,
                                       pka_operand_t *max_plus_1);

void rand_non_zero_integer_w_pka_hwrng_and_clamping(pka_handle_t   handle,
                                                    pka_operand_t *result,
                                                    pka_operand_t *max_plus_1);
/*---------------------------------------------------------------------------*/
/* Synchronous PKA implementation */
pka_operand_t *sync_add(pka_handle_t   handle,
                        pka_operand_t *value,
                        pka_operand_t *addend);

pka_operand_t *sync_subtract(pka_handle_t   handle,
                             pka_operand_t *value,
                             pka_operand_t *subtrahend);

pka_operand_t *sync_modulo(pka_handle_t   handle,
                           pka_operand_t *value,
                           pka_operand_t *modulus);

ecc_point_t *sync_ecc_multiply(pka_handle_t   handle,
                               ecc_curve_t   *curve,
                               ecc_point_t   *pointA,
                               pka_operand_t *multiplier);

pka_operand_t *sync_mont_ecdh(pka_handle_t      handle,
                              ecc_mont_curve_t *curve,
                              pka_operand_t    *point,
                              pka_operand_t    *private_key);
/*---------------------------------------------------------------------------*/
/* SW operation APIs */
dsa_signature_t *sw_ecdsa_gen(pka_handle_t   handle,
                              ecc_curve_t   *curve,
                              ecc_point_t   *base_pt,
                              pka_operand_t *base_pt_order,
                              pka_operand_t *private_key,
                              pka_operand_t *hash,
                              pka_operand_t *k);
#ifdef  __cplusplus
}
#endif

#endif // PKA_HELPER_H
