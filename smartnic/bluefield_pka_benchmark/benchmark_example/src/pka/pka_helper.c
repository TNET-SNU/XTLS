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

#include <stdio.h>
#include <string.h>

#include "pka_helper.h"
/*---------------------------------------------------------------------------*/
#define return_if_instance_invalid(inst)                    \
({                                                          \
    if ((inst) == PKA_INSTANCE_INVALID || (inst) ==0)       \
    {                                                       \
        DEBUG(PKA_D_ERROR, "PKA instance is invalid\n");    \
        return 0;                                           \
    }                                                       \
})

#define return_if_handle_invalid(hdl)                       \
({                                                          \
    if ((hdl) == PKA_HANDLE_INVALID || (hdl) == 0)          \
    {                                                       \
        DEBUG(PKA_D_ERROR, "PKA handle is invalid\n");      \
        return 0;                                           \
    }                                                       \
})

#define set_pka_instance(eng, inst) \
    ({ ((pka_engine_info_t *) (eng))->instance = (inst); })

#define reset_pka_instance(inst) \
    ({ (inst) = PKA_INSTANCE_INVALID; })

#define reset_pka_handle(hdl) \
    ({ (hdl) = PKA_HANDLE_INVALID; })

#define handle_is_valid(hdl) \
    ((hdl) != PKA_HANDLE_INVALID && (hdl) != 0)
/*---------------------------------------------------------------------------*/
#define DEBUG_MODE    0xf
#define PKA_D_ERROR   0x1
#define PKA_D_INFO    0x8

#define DEBUG(level, fmt_and_args...)           \
({                                              \
    if (level & DEBUG_MODE)                     \
        PKA_PRINT(PKA_ENGINE, fmt_and_args);    \
})
/*---------------------------------------------------------------------------*/
/* Function Signatures */
pka_operand_t *bignum_to_operand(pka_bignum_t *bignum);

pka_operand_t *malloc_operand(uint32_t buf_len);

void make_operand_buf(pka_operand_t *operand,
					  uint8_t       *big_endian_buf_ptr,
					  uint32_t       buf_len);

pka_operand_t *make_operand(uint8_t  *big_endian_buf_ptr,
                               uint32_t  buf_len,
                               uint8_t   big_endian);

static pka_operand_t *make_operand_rsa(PKA_ULONG *bn_buf_ptr,
                                       uint32_t   buf_len,
                                       uint32_t   buf_max_len,
                                       uint8_t    big_endian);

static void operand_byte_copy(pka_operand_t *operand,
                              uint8_t       *big_endian_buf_ptr,
                              uint32_t       buf_len);

static void init_operand(pka_operand_t *operand,
                         uint8_t       *buf,
                         uint32_t       buf_len,
                         uint8_t        big_endian);

static void init_results_operand(pka_results_t *results,
                                 uint32_t       result_cnt,
                                 uint8_t       *res1_buf,
                                 uint32_t       res1_len,
                                 uint8_t       *res2_buf,
                                 uint32_t       res2_len);

pka_operand_t *rand_operand(pka_handle_t  handle,
                            uint32_t      bit_len,
                            bool          make_odd);

void set_pka_operand(pka_operand_t *operand,
                     uint8_t       *big_endian_buf_ptr,
                     uint32_t       buf_len,
                     uint8_t        big_endian);


void copy_operand(pka_operand_t *original, pka_operand_t *copy);

static pka_operand_t *dup_operand(pka_operand_t *src_operand);

static void set_operand(pka_operand_t *operand, uint32_t integer);

uint32_t operand_bit_len(pka_operand_t *operand);

uint32_t operand_byte_len(pka_operand_t *operand);

void print_operand(char *prefix, pka_operand_t *operand, char *suffix);

void free_operand(pka_operand_t *operand);

static void free_operand_buf(pka_operand_t *operand);

static void free_dsa_signature(dsa_signature_t *signature);

static ecc_point_t *malloc_ecc_point(uint32_t buf_x_len,
                                     uint32_t buf_y_len,
                                     uint8_t  big_endian);

static dsa_signature_t *malloc_dsa_signature(uint32_t r_buf_len,
                                             uint32_t s_buf_len,
                                             uint8_t  big_endian);

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

static void init_ecc_point(ecc_point_t *ecc_pt,
                           uint8_t     *buf_x,
                           uint8_t     *buf_y,
                           uint32_t     buf_len,
                           uint8_t      big_endian);

static void copy_ecc_point(ecc_point_t *original, ecc_point_t *copy);

static void byte_swap_copy(uint8_t *dest, uint8_t *src, uint32_t len);

static uint32_t get_msb_idx(pka_operand_t *operand);

static uint8_t is_zero(pka_operand_t *operand);

static pka_status_t get_rand_bytes(pka_handle_t  handle,
                                   uint8_t      *buf,
                                   uint32_t      buf_len);

static pka_operand_t *results_to_operand(pka_handle_t handle);

pka_operand_t *rand_non_zero_integer(pka_handle_t   handle,
                                     pka_operand_t *max_plus_1);

void rand_non_zero_integer_wo_syscall(pka_handle_t   handle,
                                      pka_operand_t *result,
                                      pka_operand_t *max_plus_1);

static uint32_t count_leading_zeros(pka_operand_t *operand);

static uint32_t get_two_ms_bytes(pka_operand_t *operand);

static uint32_t get_three_ms_bytes(pka_operand_t *operand,
                                   uint32_t       two_ms_bytes);

static pka_cmp_code_t cmp_ms_dividend_to_ms_divisor(pka_operand_t *dividend,
                                                    pka_operand_t *divisor);

static void adjust_actual_len(pka_operand_t *operand);

static void subtract_product(pka_operand_t *dividend,
                             pka_operand_t *divisor,
                             uint32_t       quot_byte,
                             uint32_t       quot_byte_shift);

static void add_quot_byte(pka_operand_t *quotient,
                          uint32_t       quot_byte,
                          uint32_t       quot_byte_shift);

static void bignum_div_mod(pka_operand_t *dividend,
                           pka_operand_t *divisor,
                           pka_operand_t *quotient);

static void divide_with_remainder(pka_operand_t *dividend,
                                  pka_operand_t *divisor,
                                  pka_operand_t *quotient,
                                  pka_operand_t *remainder);

static uint8_t is_one(pka_operand_t *operand);

static uint32_t operand_to_uint32(pka_operand_t *operand);

static uint8_t get_bit(pka_operand_t *operand, uint32_t bit_idx);

static uint32_t bits_in_byte(uint8_t byte);

static void pka_wait_for_results(pka_handle_t handle, pka_results_t *results);

static pka_status_t get_results(pka_handle_t   handle,
                                pka_operand_t *result1,
                                pka_operand_t *result2);

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

static pka_cmp_code_t pki_compare(pka_operand_t *left, pka_operand_t *right);

static pka_result_code_t pki_add(pka_operand_t *value,
                                 pka_operand_t *addend,
                                 pka_operand_t *result);

static pka_result_code_t pki_subtract(pka_operand_t *value,
                                      pka_operand_t *subtrahend,
                                      pka_operand_t *result);

static pka_result_code_t pki_multiply(pka_operand_t *value,
                                      pka_operand_t *multiplier,
                                      pka_operand_t *result);

static pka_result_code_t pki_modulo(pka_operand_t *value,
                                    pka_operand_t *modulus,
                                    pka_operand_t *result_ptr);

static pka_result_code_t pki_mod_add(pka_operand_t *value,
                                     pka_operand_t *addend,
                                     pka_operand_t *modulus,
                                     pka_operand_t *result);

static pka_result_code_t pki_mod_subtract(pka_operand_t *value,
                                          pka_operand_t *subtrahend,
                                          pka_operand_t *modulus,
                                          pka_operand_t *result);

static pka_result_code_t pki_mod_multiply(pka_operand_t *value,
                                          pka_operand_t *multiplier,
                                          pka_operand_t *modulus,
                                          pka_operand_t *result);

static pka_result_code_t ecc_double(ecc_curve_t *curve,
                                    ecc_point_t *pointA,
                                    ecc_point_t *result);

static pka_result_code_t pki_mod_inverse(pka_operand_t *value,
                                         pka_operand_t *modulus,
                                         pka_operand_t *result_ptr);

static pka_result_code_t pki_ecc_add(ecc_curve_t *curve,
                                     ecc_point_t *pointA,
                                     ecc_point_t *pointB,
                                     ecc_point_t *result_pt);

static pka_result_code_t pki_ecc_multiply(ecc_curve_t   *curve,
                                          ecc_point_t   *pointA,
                                          pka_operand_t *multiplier,
                                          ecc_point_t   *result_point);

static pka_result_code_t pki_ecdsa_generate(ecc_curve_t     *curve,
                                            ecc_point_t     *base_pt,
                                            pka_operand_t   *base_pt_order,
                                            pka_operand_t   *private_key,
                                            pka_operand_t   *hash,
                                            pka_operand_t   *k,
                                            dsa_signature_t *signature_result);

static pka_operand_t *sw_add(pka_handle_t   handle,
                             pka_operand_t *value,
                             pka_operand_t *addend);

dsa_signature_t *sw_ecdsa_gen(pka_handle_t   handle,
                              ecc_curve_t   *curve,
                              ecc_point_t   *base_pt,
                              pka_operand_t *base_pt_order,
                              pka_operand_t *private_key,
                              pka_operand_t *hash,
                              pka_operand_t *k);
/*---------------------------------------------------------------------------*/
/* helper functions - operand related */
pka_operand_t *bignum_to_operand(pka_bignum_t *bignum)
{
    uint32_t byte_len, byte_max_len;

    if (bignum)
    {
        byte_len     = bignum->top  * PKA_BYTES;
        byte_max_len = bignum->dmax * PKA_BYTES;

        return make_operand_rsa(bignum->d, byte_len, byte_max_len, 1);
    }

    return NULL;
}

pka_operand_t *malloc_operand(uint32_t buf_len)
{
    pka_operand_t *operand;

    operand             = calloc(1, sizeof(pka_operand_t));
    operand->buf_ptr    = calloc(1, buf_len);
    operand->buf_len    = buf_len;
    operand->actual_len = 0;
    return operand;
}

void make_operand_buf(pka_operand_t *operand,
					  uint8_t       *big_endian_buf_ptr,
					  uint32_t       buf_len)
{
    operand->buf_ptr = malloc(buf_len);
    memset(operand->buf_ptr, 0, buf_len);
    operand->buf_len    = buf_len;
    operand->actual_len = buf_len;
    // Now fill the operand buf.
    operand_byte_copy(operand, big_endian_buf_ptr, buf_len);
}

pka_operand_t *make_operand(uint8_t  *big_endian_buf_ptr,
                            uint32_t  buf_len,
                            uint8_t   big_endian)
{
    pka_operand_t *operand;

    operand = malloc(sizeof(pka_operand_t));
    memset(operand, 0, sizeof(pka_operand_t));
    operand->big_endian = big_endian;
    // Now init the operand buf.
    make_operand_buf(operand, big_endian_buf_ptr, buf_len);
    return operand;
}

static pka_operand_t *make_operand_rsa(PKA_ULONG *bn_buf_ptr,
                                       uint32_t   buf_len,
                                       uint32_t   buf_max_len,
                                       uint8_t    big_endian)
{
    pka_operand_t *operand;

    if (!bn_buf_ptr || (buf_max_len == 0))
        return NULL;

    operand = malloc(sizeof(pka_operand_t));
    memset(operand, 0, sizeof(pka_operand_t));
    operand->big_endian = big_endian;

    // Now init the operand buffer
    operand->buf_ptr    = malloc(buf_max_len);
    operand->buf_len    = buf_max_len;
    memset(operand->buf_ptr, 0, buf_max_len);

    // Now fill the operand buf.
    operand_byte_copy(operand, (uint8_t *) bn_buf_ptr, buf_len);

    return operand;
}

static void operand_byte_copy(pka_operand_t *operand,
                              uint8_t       *big_endian_buf_ptr,
                              uint32_t       buf_len)
{
    PKA_ASSERT(buf_len <= operand->buf_len);

    if (operand->big_endian)
    {
        memcpy(operand->buf_ptr, big_endian_buf_ptr, buf_len);
    }
    else // little-endian
    {
        // Now fill the operand buf, but backwards.
        byte_swap_copy(operand->buf_ptr, big_endian_buf_ptr, buf_len);
    }

    operand->actual_len = buf_len;
}

static void init_operand(pka_operand_t *operand,
                         uint8_t       *buf,
                         uint32_t       buf_len,
                         uint8_t        big_endian)
{
    memset(operand, 0, sizeof(pka_operand_t));
    memset(buf,     0, buf_len);
    operand->buf_ptr    = buf;
    operand->buf_len    = buf_len;
    operand->actual_len = 0;
    operand->big_endian = big_endian;
}

// pka_results_t* malloc_results(uint32_t result_cnt, uint32_t buf_len)
// {
//     pka_results_t  * results;
//     pka_operand_t  * result_ptr;
//     uint8_t         result_idx, i;

//     PKA_ASSERT(result_cnt <= MAX_RESULT_CNT);

//     results = malloc(sizeof(pka_results_t));

//     if (results == NULL) {
//         fprintf(stderr, "Error: malloc for results failed\n");
//         return NULL;
//     }

//     memset(results, 0, sizeof(pka_results_t));

//     for (result_idx = 0; result_idx < result_cnt; result_idx++) {
//         result_ptr = &results->results[result_idx];
//         if ((result_ptr->buf_ptr = malloc(buf_len)) == NULL) {
//             fprintf(stderr, "Error: malloc for buf_ptr failed\n");
//             for (i = 0; i < result_idx; i++)
//                 free(results->results[i].buf_ptr);
//             return NULL;
//         }
//         memset(result_ptr->buf_ptr, 0, buf_len);
//         result_ptr->buf_len = buf_len;
//         result_ptr->actual_len = 0;
//     }

//     results->result_cnt = result_cnt;

//     return results;
// }

static void init_results_operand(pka_results_t *results,
                                 uint32_t       result_cnt,
                                 uint8_t       *res1_buf,
                                 uint32_t       res1_len,
                                 uint8_t       *res2_buf,
                                 uint32_t       res2_len)
{
    pka_operand_t *result_ptr;

    PKA_ASSERT(result_cnt <= MAX_RESULT_CNT);
    results->result_cnt = result_cnt;

    switch (result_cnt) {
    case 2:
        PKA_ASSERT(res2_buf   != NULL);
        result_ptr             = &results->results[1];
        result_ptr->buf_ptr    = res2_buf;
        memset(result_ptr->buf_ptr, 0, res2_len);
        result_ptr->buf_len    = res2_len;
        result_ptr->actual_len = 0;
        // fall-through
    case 1:
        PKA_ASSERT(res1_buf   != NULL);
        result_ptr             = &results->results[0];
        result_ptr->buf_ptr    = res1_buf;
        memset(result_ptr->buf_ptr, 0, res1_len);
        result_ptr->buf_len    = res1_len;
        result_ptr->actual_len = 0;
    default:
        return;
    }
}

pka_operand_t *rand_operand(pka_handle_t  handle,
                            uint32_t      bit_len,
                            bool          make_odd)
{
    pka_operand_t *result;
    uint32_t       byte_len, msb_idx, lsb_idx, num_msb_bits;
    uint8_t        msb_byte;

    byte_len           = (bit_len + 7) / 8;
    result             = malloc_operand(byte_len);
    result->actual_len = byte_len;
    result->big_endian = pka_get_rings_byte_order(handle);

    get_rand_bytes(handle, &result->buf_ptr[0], byte_len);

    // Get the index of the most significant and least significant bytes.
    if (result->big_endian)
    {
        result->big_endian = 1;
        msb_idx            = 0;
        lsb_idx            = byte_len - 1;
    }
    else
    {
        result->big_endian = 0;
        msb_idx            = byte_len - 1;
        lsb_idx            = 0;
    }

    // Make sure the msb byte is non-zero and in fact is of the correct
    // bit len.
    msb_byte     = result->buf_ptr[msb_idx];
    num_msb_bits = bit_len - (8 * (byte_len - 1));
    PKA_ASSERT((1 <= num_msb_bits) && (num_msb_bits <= 8));

    msb_byte |=   1 << (num_msb_bits - 1);
    msb_byte &= ((1 << num_msb_bits) - 1);

    result->buf_ptr[msb_idx] = msb_byte;
    if (make_odd)
        result->buf_ptr[lsb_idx] |= 0x01;

    PKA_ASSERT(operand_bit_len(result) == bit_len);
    return result;
}

void set_pka_operand(pka_operand_t *operand,
                     uint8_t       *big_endian_buf_ptr,
                     uint32_t       buf_len,
                     uint8_t        big_endian)
{
    operand->big_endian = big_endian;
    operand->buf_len    = buf_len;
    operand->actual_len = buf_len;
    operand->buf_ptr    = malloc(buf_len);
    memset(operand->buf_ptr, 0, buf_len);

    operand->buf_len    = buf_len;
    operand->actual_len = buf_len;

    // Now fill the operand buf.
    if (big_endian)
        memcpy(operand->buf_ptr, big_endian_buf_ptr, buf_len);
    else
        byte_swap_copy(operand->buf_ptr, big_endian_buf_ptr, buf_len);
}


void copy_operand(pka_operand_t *original, pka_operand_t *copy)
{
    uint8_t *copy_buf_ptr;

    copy_buf_ptr = copy->buf_ptr;
    memcpy(copy, original, sizeof(pka_operand_t));

    copy->buf_ptr = copy_buf_ptr;
    memcpy(copy->buf_ptr, original->buf_ptr, original->actual_len);
}

static pka_operand_t *dup_operand(pka_operand_t *src_operand)
{
    pka_operand_t *new_operand;
    uint32_t       leading_zeros, len;
    uint8_t       *src_buf_ptr;

    if (src_operand == NULL)
    {
        PKA_ERROR(PKA_TESTS,  "dup_operand called with src_operand == NULL\n");
        return NULL;
    }

    leading_zeros = count_leading_zeros(src_operand);
    len           = src_operand->actual_len - leading_zeros;
    src_buf_ptr   = src_operand->buf_ptr;
    if (src_operand->big_endian)
        src_buf_ptr += leading_zeros;

    new_operand             = malloc_operand(len);
    new_operand->actual_len = len;
    new_operand->big_endian = src_operand->big_endian;
    memcpy(new_operand->buf_ptr, src_buf_ptr, len);
    return new_operand;
}

// Operand must be Initialized first (e.g. by calling init_operand).
static void set_operand(pka_operand_t *operand, uint32_t integer)
{
    uint32_t  lsb_idx, idx;
    uint8_t  *buf_ptr;

    if (integer == 0)
        operand->actual_len = 0;
    else if (integer < 0x100)
        operand->actual_len = 1;
    else if (integer < 0x10000)
        operand->actual_len = 2;
    else if (integer < 0x1000000)
        operand->actual_len = 3;
    else
        operand->actual_len = 4;

    lsb_idx = (operand->big_endian) ? (operand->actual_len - 1) : 0;
    buf_ptr = &operand->buf_ptr[lsb_idx];

    // Work from the least significant end to the most significant end.
    for (idx = 0;  idx < operand->actual_len;  idx++)
    {
        *buf_ptr = integer & 0xFF;
        integer  = integer >> 8;
        if (operand->big_endian)
            buf_ptr--;
        else
            buf_ptr++;
    }
}

uint32_t operand_bit_len(pka_operand_t *operand)
{
    uint32_t byte_len;
    uint8_t *byte_ptr;

    byte_len = operand->actual_len;
    if (byte_len == 0)
        return 0;

    if (operand->big_endian)
    {
        // Move forwards over all zero bytes.
        byte_ptr = &operand->buf_ptr[0];
        if (byte_ptr[0] != 0)
            return (8 * (byte_len - 1)) + bits_in_byte(byte_ptr[0]);

        while ((byte_ptr[0] == 0) && (1 <= byte_len))
        {
            byte_ptr++;
            byte_len--;
        }
    }
    else // little-endian
    {
        // First find the most significant byte based upon the actual_len,
        // and then move backwards over all zero bytes.
        byte_ptr = &operand->buf_ptr[byte_len - 1];
        if (byte_ptr[0] != 0)
            return (8 * (byte_len - 1)) + bits_in_byte(byte_ptr[0]);

        while ((byte_ptr[0] == 0) && (1 <= byte_len))
        {
            byte_ptr--;
            byte_len--;
        }
    }

    if (byte_len == 0)
        return 0;
    else
        return (8 * (byte_len - 1)) + bits_in_byte(byte_ptr[0]);
}

uint32_t operand_byte_len(pka_operand_t *operand)
{
    uint32_t byte_len;
    uint8_t *byte_ptr;

    byte_len = operand->actual_len;
    if (byte_len == 0)
        return 0;

    if (operand->big_endian)
    {
        byte_ptr = &operand->buf_ptr[0];
        if (byte_ptr[0] != 0)
            return byte_len;

        // Move forwards over all zero bytes.
        while ((1 <= byte_len) && (byte_ptr[0] == 0))
        {
            byte_ptr++;
            byte_len--;
        }
    }
    else // little-endian
    {
        // First find the most significant byte based upon the actual_len, and
        // then move backwards over all zero bytes.
        byte_ptr = &operand->buf_ptr[byte_len - 1];
        if (byte_ptr[0] != 0)
            return byte_len;

        while ((1 <= byte_len) && (byte_ptr[0] == 0))
        {
            byte_ptr--;
            byte_len--;
        }
    }

    return byte_len;
}

void print_operand(char *prefix, pka_operand_t *operand, char *suffix)
{
    uint32_t byte_len, byte_cnt, byte_idx;
    uint8_t *byte_ptr;

    if (prefix != NULL)
        printf("%s", prefix);

    byte_len = operand_byte_len(operand);
    printf("0x");
    if ((byte_len == 0) || ((byte_len == 1) && (operand->buf_ptr[0] == 0)))
        printf("0");
    else
    {
        byte_idx = (operand->big_endian) ? 0 : byte_len - 1;
        byte_ptr = &operand->buf_ptr[byte_idx];
        for (byte_cnt = 0; byte_cnt < byte_len; byte_cnt++)
            printf("%02X", (operand->big_endian) ?
                    *byte_ptr++ : *byte_ptr--);
    }

    if (suffix != NULL)
        printf("%s", suffix);
}

void free_operand(pka_operand_t *operand)
{
    uint8_t *buf_ptr;

    if (operand == NULL)
        return;

    buf_ptr = operand->buf_ptr;

    if (buf_ptr != NULL)
        free(buf_ptr);

    free(operand);
}

static void free_operand_buf(pka_operand_t *operand)
{
    uint8_t *buf_ptr;

    buf_ptr = operand->buf_ptr;
    if (buf_ptr == NULL)
        PKA_ERROR(PKA_TESTS,  "free_operand_buf called with NULL buf_ptr\n");
    else
        free(buf_ptr);

    operand->buf_ptr      = NULL;
    operand->buf_len      = 0;
    operand->actual_len   = 0;
}

static void free_dsa_signature(dsa_signature_t *signature)
{
    if (signature == NULL)
    {
        PKA_ERROR(PKA_TESTS,  "free_dsa_signature called with NULL operand\n");
        return;
    }

    free_operand_buf(&signature->r);
    free_operand_buf(&signature->s);
    free(signature);
}
/*---------------------------------------------------------------------------*/
/* helper functions - ecc/ecdsa related*/
static ecc_point_t *malloc_ecc_point(uint32_t buf_x_len,
                                     uint32_t buf_y_len,
                                     uint8_t  big_endian)
{
    ecc_point_t   *ecc_point;
    uint8_t       *buf_x, *buf_y;

    ecc_point = malloc(sizeof(ecc_point_t));
    memset(ecc_point, 0, sizeof(ecc_point_t));

    buf_x = malloc(buf_x_len);
    buf_y = malloc(buf_y_len);

    init_operand(&ecc_point->x, buf_x, buf_x_len, big_endian);
    init_operand(&ecc_point->y, buf_y, buf_y_len, big_endian);

    return ecc_point;
}

static dsa_signature_t *malloc_dsa_signature(uint32_t r_buf_len,
                                             uint32_t s_buf_len,
                                             uint8_t  big_endian)
{
    dsa_signature_t *signature;
    uint8_t         *buf_r, *buf_s;

    signature = malloc(sizeof(dsa_signature_t));
    buf_r = malloc(r_buf_len);
    buf_s = malloc(s_buf_len);
    init_operand(&signature->r, buf_r, r_buf_len, big_endian);
    init_operand(&signature->s, buf_s, s_buf_len, big_endian);

    return signature;
}

ecc_curve_t *make_ecc_curve(uint8_t *big_endian_buf_p_ptr,
                            uint32_t p_len,
                            uint8_t *big_endian_buf_a_ptr,
                            uint32_t a_len,
                            uint8_t *big_endian_buf_b_ptr,
                            uint32_t b_len,
                            uint8_t  big_endian)
{
    ecc_curve_t *curve;

    curve = malloc(sizeof(ecc_curve_t));
    memset(curve, 0, sizeof(ecc_curve_t));

    curve->p.big_endian = big_endian;
    curve->a.big_endian = big_endian;
    curve->b.big_endian = big_endian;

    make_operand_buf(&curve->p, big_endian_buf_p_ptr, p_len);
    make_operand_buf(&curve->a, big_endian_buf_a_ptr, a_len);
    make_operand_buf(&curve->b, big_endian_buf_b_ptr, b_len);

    return curve;
}

ecc_point_t *make_ecc_point(ecc_curve_t *curve,
                            uint8_t     *big_endian_buf_x_ptr,
                            uint32_t     buf_x_len,
                            uint8_t     *big_endian_buf_y_ptr,
                            uint32_t     buf_y_len,
                            uint8_t      big_endian)
{
    ecc_point_t *ecc_point;

    ecc_point = malloc(sizeof(ecc_point_t));
    memset(ecc_point, 0, sizeof(ecc_point_t));

    ecc_point->x.big_endian = big_endian;
    ecc_point->y.big_endian = big_endian;

    make_operand_buf(&ecc_point->x, big_endian_buf_x_ptr, buf_x_len);
    make_operand_buf(&ecc_point->y, big_endian_buf_y_ptr, buf_y_len);

    if (curve == NULL)
		{
			PKA_ERROR(PKA_TESTS,  "point not on curve\n\n");
		}

    /* if (curve != NULL) */
	/* 	{ */
	/* 		if (is_point_on_curve(curve, ecc_point) != 1) */
	/* 			PKA_ERROR(PKA_TESTS,  "point not on curve\n\n"); */
	/* 	} */

    return ecc_point;
}

ecc_point_t *make_mont_ecc_point(ecc_mont_curve_t *curve,
                                 uint8_t     *big_endian_buf_x_ptr,
                                 uint32_t     buf_x_len,
                                 uint8_t     *big_endian_buf_y_ptr,
                                 uint32_t     buf_y_len,
                                 uint8_t      big_endian)
{
    UNUSED(curve);
    ecc_point_t *ecc_point;

    ecc_point = malloc(sizeof(ecc_point_t));
    memset(ecc_point, 0, sizeof(ecc_point_t));

    ecc_point->x.big_endian = big_endian;
    ecc_point->y.big_endian = big_endian;

    make_operand_buf(&ecc_point->x, big_endian_buf_x_ptr, buf_x_len);
    make_operand_buf(&ecc_point->y, big_endian_buf_y_ptr, buf_y_len);

    return ecc_point;
}

static void init_ecc_point(ecc_point_t *ecc_pt,
                           uint8_t     *buf_x,
                           uint8_t     *buf_y,
                           uint32_t     buf_len,
                           uint8_t      big_endian)
{
    init_operand(&ecc_pt->x, buf_x, buf_len, big_endian);
    init_operand(&ecc_pt->y, buf_y, buf_len, big_endian);
}

static void copy_ecc_point(ecc_point_t *original, ecc_point_t *copy)
{
    copy_operand(&original->x, &copy->x);
    copy_operand(&original->y, &copy->y);
}
/*---------------------------------------------------------------------------*/
/* helper functions - miscellaneous */
static void byte_swap_copy(uint8_t *dest, uint8_t *src, uint32_t len)
{
    uint32_t idx;

    for (idx = 0; idx < len; idx++)
        dest[idx] = src[(len - 1) - idx];
}

static uint32_t get_msb_idx(pka_operand_t *operand)
{
    uint32_t byte_len, msb_idx;
    uint8_t *byte_ptr;

    if (operand->big_endian)
		{
			byte_ptr = &operand->buf_ptr[0];
			if (byte_ptr[0] != 0)
				return 0;

			// Move forwards over all zero bytes.
			byte_len = operand->actual_len;
			msb_idx  = 0;
			while ((byte_ptr[0] == 0) && (1 <= byte_len))
				{
					msb_idx++;
					byte_ptr++;
					byte_len--;
				}

			return msb_idx;
		}
    else  // little-endian.
		{
			// First find the most significant byte based upon the actual_len,
			// and then move backwards over all zero bytes, in order to skip
			// leading zeros and find the real msb index.
			byte_len = operand->actual_len;
			byte_ptr = &operand->buf_ptr[byte_len - 1];
			if (byte_ptr[0] != 0)
				return byte_len - 1;

			msb_idx = byte_len - 1;
			while ((byte_ptr[0] == 0) && (1 <= byte_len))
				{
					msb_idx--;
					byte_ptr--;
					byte_len--;
				}
		}

    return msb_idx;
}

static uint8_t is_zero(pka_operand_t *operand)
{
    uint32_t len;

    len = operand_byte_len(operand);
    if (len == 0)
        return 1;
    else if (len == 1)
        return operand->buf_ptr[0] == 0;
    else
        return 0;
}

static pka_status_t get_rand_bytes(pka_handle_t  handle,
                                   uint8_t      *buf,
                                   uint32_t      buf_len)
{
    UNUSED(handle);
    int fd;

    if ((fd = open("/dev/hwrng", O_RDONLY | O_NONBLOCK)) != -1)
    {
        if (read(fd, buf, buf_len) < 0)
            return FAILURE;
        close(fd);
        return SUCCESS;
    }
    else
    {
        if (errno == EACCES)
        {
            PKA_ERROR(PKA_TESTS,
                "unpriviliged user, access denied for /dev/hwrng\n");
        }
        else
        {
            PKA_ERROR(PKA_TESTS,  "failed to open /dev/hwrng\n");
        }
        exit(1);
    }

    return FAILURE;
}

static pka_operand_t *results_to_operand(pka_handle_t handle)
{
    pka_results_t  results;
    pka_operand_t *result_ptr;
    uint32_t       result_len;
    uint8_t        res1[MAX_BYTE_LEN];

    memset(&results, 0, sizeof(pka_results_t));
    init_results_operand(&results, 1, res1, MAX_BYTE_LEN, NULL, 0);

    pka_wait_for_results(handle, &results);
    if (results.status != RC_NO_ERROR)
    {
        PKA_ERROR(PKA_TESTS, "pka_get_result status=0x%x\n", results.status);
        return NULL;
    }

    result_len = results.results[0].actual_len;
    result_ptr = malloc_operand(result_len);
    copy_operand(&results.results[0], result_ptr);
    return result_ptr;
}

// Return a big number between 1 .. max_plus_1 - 1.
pka_operand_t *rand_non_zero_integer(pka_handle_t   handle,
                                     pka_operand_t *max_plus_1)
{
    pka_operand_t *result;
    uint32_t       byte_len, msb_idx, max_plus_msb, result_msb;

    byte_len           = operand_byte_len(max_plus_1);
    result             = malloc_operand(byte_len);
    result->big_endian = pka_get_rings_byte_order(handle);
    result->actual_len = byte_len;

    do
		{
			get_rand_bytes(handle, &result->buf_ptr[0], byte_len);
		} while (is_zero(result));
        
    if (pki_compare(result, max_plus_1) == RC_LEFT_IS_SMALLER)
        return result;

    // Need to reduce the most significant byte of the result to be less than
    // the most significant byte of max_plus_1.  First get msb of max_plus_1.
    msb_idx      = get_msb_idx(max_plus_1);
    max_plus_msb = max_plus_1->buf_ptr[msb_idx];
    PKA_ASSERT(max_plus_msb != 0);

    // Next find msb of the result and adjust it.
    msb_idx                  = get_msb_idx(result);
    result_msb               = result->buf_ptr[msb_idx];
    result->buf_ptr[msb_idx] = result_msb % max_plus_msb;
    return result;
}

// Return a big number between 1 .. max_plus_1 - 1.
void rand_non_zero_integer_wo_syscall(pka_handle_t   handle,
                                      pka_operand_t *result,
                                      pka_operand_t *max_plus_1)
{
    result->big_endian = pka_get_rings_byte_order(handle);
    result->actual_len = operand_byte_len(max_plus_1);

    do
		{
            uint8_t *p = result->buf_ptr;
            for (size_t i = 0; i < result->actual_len; i++) {
                p[i] = rand() & 0xFF;
            }
        } while (is_zero(result) || pki_compare(result, max_plus_1) != RC_LEFT_IS_SMALLER);
        
    return;
}

// Return a big number between 1 .. max_plus_1 - 1.
void rand_non_zero_integer_w_pka_hwrng(pka_handle_t   handle,
                                       pka_operand_t *result,
                                       pka_operand_t *max_plus_1)
{
    result->big_endian = pka_get_rings_byte_order(handle);
    result->actual_len = operand_byte_len(max_plus_1);

    do
		{
            pka_get_rand_bytes(handle, 
                               result->buf_ptr, 
                               result->actual_len);
        } while (is_zero(result) || pki_compare(result, max_plus_1) != RC_LEFT_IS_SMALLER);
        
    return;
}

// Return a big number between 1 .. max_plus_1 - 1.
void rand_non_zero_integer_w_pka_hwrng_and_clamping(pka_handle_t   handle,
                                                    pka_operand_t *result,
                                                    pka_operand_t *max_plus_1)
{
    result->big_endian = pka_get_rings_byte_order(handle);
    result->actual_len = operand_byte_len(max_plus_1);

    pka_get_rand_bytes(handle, 
                        result->buf_ptr, 
                        result->actual_len);

    result->buf_ptr[0] &= 248;
    result->buf_ptr[31] &= 127;
    result->buf_ptr[31] |= 64;

    pki_compare(result, max_plus_1);

    return;
}

void rand_non_zero_integer_wo_syscall_32bytes(pka_handle_t   handle,
                                              pka_operand_t *result)
{
    result->big_endian = pka_get_rings_byte_order(handle);
    result->actual_len = 32;

    do {
        uint8_t *p = result->buf_ptr;

        for (size_t i = 0; i < 32; i++) {
            p[i] = rand() & 0xFF;
        }

    } while (is_zero(result));
}

static uint32_t count_leading_zeros(pka_operand_t *operand)
{
    uint32_t byte_len, leading_zeros;
    uint8_t  ms_byte;

    byte_len = operand->actual_len;
    if (is_zero(operand))
        return byte_len - 1;
    else if (byte_len == 0)
        byte_len = operand->buf_len;

    for (leading_zeros = 0; leading_zeros <= byte_len; leading_zeros++)
    {
        if (operand->big_endian)
            ms_byte = operand->buf_ptr[leading_zeros];
        else
            ms_byte = operand->buf_ptr[(byte_len - 1) - leading_zeros];

        if (ms_byte != 0)
            return leading_zeros;
    }

    PKA_ASSERT(false);
    return byte_len - 1;
}

static uint32_t get_two_ms_bytes(pka_operand_t *operand)
{
    uint32_t result, byte_len, msb_idx, next_idx;

    byte_len = operand_byte_len(operand);
    msb_idx  = get_msb_idx(operand);

    PKA_ASSERT(byte_len != 0);
    result = operand->buf_ptr[msb_idx] << 8;
    if (byte_len <= 1)
        return result;

    next_idx = msb_idx - 1;
    result += operand->buf_ptr[next_idx];
    return result;
}

static uint32_t get_three_ms_bytes(pka_operand_t *operand,
                                   uint32_t       two_ms_bytes)
{
  uint32_t result, byte_len, msb_idx, next_idx;

    byte_len = operand_byte_len(operand);
    result   = two_ms_bytes << 8;
    if (byte_len < 3)
        return result;

    msb_idx = get_msb_idx(operand);
    next_idx = msb_idx - 2;

    result += operand->buf_ptr[next_idx];
    return result;
}

static pka_cmp_code_t cmp_ms_dividend_to_ms_divisor(pka_operand_t *dividend,
                                                    pka_operand_t *divisor)
{
    uint32_t divisor_byte_len, divisor_msb_idx, dividend_msb_idx, byte_cnt;
    uint8_t *divisor_ptr, *dividend_ptr, divisor_byte, dividend_byte;

    divisor_byte_len = operand_byte_len(divisor);
    divisor_msb_idx  = get_msb_idx(divisor);
    dividend_msb_idx = get_msb_idx(dividend);

    divisor_ptr  = &divisor->buf_ptr[divisor_msb_idx];
    dividend_ptr = &dividend->buf_ptr[dividend_msb_idx];

    // Compare the most significant "divisor_byte_len" bytes of the dividend
    // to the divisor, starting at the most significant bytes.
    for (byte_cnt = 0; byte_cnt < divisor_byte_len; byte_cnt++)
    {
        divisor_byte  = *divisor_ptr;
        dividend_byte = *dividend_ptr;
        if (dividend_byte < divisor_byte)
            return RC_LEFT_IS_SMALLER;
        else if (dividend_byte > divisor_byte)
            return RC_RIGHT_IS_SMALLER;

        divisor_ptr--;
        dividend_ptr--;
    }

    return RC_COMPARE_EQUAL;
}

// The following function removes all leading zeros from the operand by
// decrementing the actual length field.
static void adjust_actual_len(pka_operand_t *operand)
{
    uint32_t byte_len, leading_zeros;

    if (is_zero(operand))
    {
        operand->actual_len = 1;
        return;
    }

    leading_zeros = count_leading_zeros(operand);
    if (leading_zeros == 0)
        return;

    byte_len = operand->actual_len;
    if (MAX_BUF < byte_len)
        abort();
    else if (byte_len == 0)
        byte_len = operand->buf_len;

    operand->actual_len = byte_len - leading_zeros;
    if (operand->big_endian)
        operand->buf_ptr += leading_zeros;
}

static void subtract_product(pka_operand_t *dividend,
                             pka_operand_t *divisor,
                             uint32_t       quot_byte,
                             uint32_t       quot_byte_shift)
{
    uint32_t divisor_byte_len, dividend_byte_len, carry, borrow;
    uint32_t divisor_byte, dividend_byte, product, prod_byte, result_byte;
    uint32_t byte_cnt;
    uint8_t *divisor_byte_ptr, *dividend_byte_ptr;

    divisor_byte_len  = divisor->actual_len;
    dividend_byte_len = dividend->actual_len;
    if ((dividend_byte_len == divisor_byte_len) && (quot_byte == 1))
    {
        // Optimize the case where dividend == divisor.
        if (pki_compare(dividend, divisor) == RC_COMPARE_EQUAL)
        {
            memset(dividend->buf_ptr, 0, dividend->actual_len);
            dividend->actual_len = 1;
            return;
        }
    }

    divisor_byte_ptr  = &divisor->buf_ptr[0];
    dividend_byte_ptr = &dividend->buf_ptr[quot_byte_shift];

    // Now multiply divisor by quot_byte and subtract it from dividend.
    // This code proceeds from least significant byte to most significant
    // byte.
    carry  = 0;
    borrow = 0;
    for (byte_cnt = 0; byte_cnt < divisor_byte_len; byte_cnt++)
    {
        divisor_byte  = *divisor_byte_ptr;
        dividend_byte = *dividend_byte_ptr;

        // Note that since quot_byte, divisor_byte and carry in are all <= 255,
        // this implies that product <= 0xFF00, so carry out <= 255.
        product   = (quot_byte * divisor_byte) + carry;
        prod_byte = (product & 0xFF) + borrow;
        carry     = product >> 8;
        if (prod_byte <= dividend_byte)
        {
            result_byte = dividend_byte - prod_byte;
            borrow      = 0;
        }
        else
        {
            result_byte = (256 + dividend_byte) - prod_byte;
            borrow      = 1;
        }

        *dividend_byte_ptr = result_byte;
        divisor_byte_ptr++;
        dividend_byte_ptr++;
    }

    if ((carry != 0) || (borrow != 0))
    {
        dividend_byte = *dividend_byte_ptr;
        prod_byte     = carry + borrow;
        PKA_ASSERT(prod_byte <= dividend_byte);
        *dividend_byte_ptr = dividend_byte - prod_byte;
    }

    // trim result of leading zeros to have the correct length.
    adjust_actual_len(dividend);
}

static void add_quot_byte(pka_operand_t *quotient,
                          uint32_t       quot_byte,
                          uint32_t       quot_byte_shift)
{
    uint32_t idx, old_quot_byte, new_quot_byte;

    PKA_ASSERT(quot_byte_shift < quotient->actual_len);
    idx = quot_byte_shift;

    // Add carry into subsequently more significant bytes?
    old_quot_byte = quotient->buf_ptr[idx];
    new_quot_byte = old_quot_byte + quot_byte;
    PKA_ASSERT(new_quot_byte <= 255);
    quotient->buf_ptr[idx] = new_quot_byte;
}

static void bignum_div_mod(pka_operand_t *dividend,
                           pka_operand_t *divisor,
                           pka_operand_t *quotient)
{
    pka_cmp_code_t cmp;
    uint32_t divisor_len, ms_divisor, ms_dividend, quot_byte_shift, quot_byte;

    PKA_ASSERT(dividend->actual_len <= (operand_byte_len(dividend) + 4));
    divisor_len = operand_byte_len(divisor);
    ms_divisor  = get_two_ms_bytes(divisor);
    PKA_ASSERT((0x100 <= ms_divisor) && (ms_divisor <= 0xFFFF));

    while (pki_compare(dividend, divisor) != RC_LEFT_IS_SMALLER)
    {
        // Note that quot_byte_idx MUST be >= 0, as a consequence of the test
        // above showing that divisor <= dividend.
        ms_dividend     = get_two_ms_bytes(dividend);
        quot_byte_shift = operand_byte_len(dividend) - divisor_len;
        if (ms_dividend == ms_divisor)
            // Compare the "divisor_len" most significant bytes of dividend
            // to the divisor.
            cmp = cmp_ms_dividend_to_ms_divisor(dividend, divisor);
        else if (ms_dividend < ms_divisor)
            cmp = RC_LEFT_IS_SMALLER;
        else
            cmp = RC_RIGHT_IS_SMALLER;

        if (cmp == RC_LEFT_IS_SMALLER)
        {
            quot_byte_shift--;
            ms_dividend = get_three_ms_bytes(dividend, ms_dividend);
            quot_byte   = ms_dividend / (ms_divisor + 1);
        }
        else if ((cmp == RC_COMPARE_EQUAL) || (ms_dividend == ms_divisor))
            quot_byte = 1;
        else  // cmp == RC_RIGHT_IS_SMALLER, which implies ms_divisor < 0xFFFF.
            quot_byte = ms_dividend / (ms_divisor + 1);

        // quot_byte here is guaranteed to be <= the "real" quotient byte,
        // and probably not more than 1 less than the "real" quotient byte.
        PKA_ASSERT((1 <= quot_byte) && (quot_byte <= 255));
        subtract_product(dividend, divisor, quot_byte, quot_byte_shift);

        add_quot_byte(quotient, quot_byte, quot_byte_shift);
    }
}

static void divide_with_remainder(pka_operand_t *dividend,
                                  pka_operand_t *divisor,
                                  pka_operand_t *quotient,
                                  pka_operand_t *remainder)
{
    pka_operand_t  remain, quot;
    pka_cmp_code_t comparison;
    uint32_t       quot_buf_len, dividend_byte_len, divisor_byte_len;
    uint32_t       dividend_uint32, divisor_uint32;
    uint8_t        remain_buf[MAX_BUF], quot_buf[MAX_BUF];
    uint8_t        big_endian;

    PKA_ASSERT(dividend->big_endian == divisor->big_endian);
    big_endian = dividend->big_endian;

    comparison = pki_compare(dividend, divisor);
    if (comparison == RC_LEFT_IS_SMALLER)
    {
        if (quotient != NULL)
            set_operand(quotient, 0);

        if (remainder != NULL)
            copy_operand(dividend, remainder);

        return;
    }
    else if (comparison == RC_COMPARE_EQUAL)
    {
        if (quotient != NULL)
            set_operand(quotient,  1);

        if (remainder != NULL)
            set_operand(remainder, 0);

        return;
    }
    else if (is_one(divisor))
    {
        if (quotient != NULL)
            copy_operand(dividend, quotient);

        if (remainder != NULL)
            set_operand(remainder, 0);

        return;
    }

    dividend_byte_len = operand_byte_len(dividend);
    divisor_byte_len  = operand_byte_len(divisor);
    if ((dividend_byte_len < 4) && (divisor_byte_len < 4))
    {
        dividend_uint32 = operand_to_uint32(dividend);
        divisor_uint32  = operand_to_uint32(divisor);
        if (quotient != NULL)
            set_operand(quotient,  dividend_uint32 / divisor_uint32);

        if (remainder != NULL)
            set_operand(remainder, dividend_uint32 % divisor_uint32);

        return;
    }

    quot_buf_len = (operand_byte_len(dividend) + 1) -
                    operand_byte_len(divisor);
    init_operand(&remain,  remain_buf, dividend_byte_len, big_endian);
    init_operand(&quot,    quot_buf,   quot_buf_len,      big_endian);
    copy_operand(dividend, &remain);
    set_operand(&quot,     0);
    quot.actual_len = quot_buf_len;  // Needed ??

    bignum_div_mod(&remain, divisor, &quot);

    if (quotient != NULL)
        copy_operand(&quot,   quotient);

    if (remainder != NULL)
        copy_operand(&remain, remainder);
}

static uint8_t is_one(pka_operand_t *operand)
{
    if (operand_byte_len(operand) != 1)
        return 0;

    return operand->buf_ptr[0] == 1;
}

static uint32_t operand_to_uint32(pka_operand_t *operand)
{
    uint32_t operand_len, msb_idx, value, idx;
    uint8_t *buf_ptr;

    operand_len = operand_byte_len(operand);
    if (4 < operand_len)
        return 0;  // This should never happen!

    msb_idx = get_msb_idx(operand);
    buf_ptr = &operand->buf_ptr[msb_idx];
    value   = 0;

    // Work from the most significant end to the least significant end.
    for (idx = 0; idx < operand_len; idx++)
    {
        value = (value << 8) | buf_ptr[0];
        if (operand->big_endian)
            buf_ptr++;
        else
            buf_ptr--;
    }

    return value;
}

static uint8_t get_bit(pka_operand_t *operand, uint32_t bit_idx)
{
    uint32_t byte_idx, bit_in_byte_idx;
    uint8_t  byte, bit;

    // PKA_ASSERT((bit_idx / 8) <= (operand->actual_len - 1));
    bit_in_byte_idx = bit_idx & 7;
    byte_idx = bit_idx / 8;

    byte = operand->buf_ptr[byte_idx];
    bit  = (byte >> bit_in_byte_idx) & 0x1;
    return bit;
}

static uint32_t bits_in_byte(uint8_t byte)
{
    int32_t bit_num;

    if (byte == 0)
        return 0;

    // Assumes byte != 0;
    for (bit_num = 7; bit_num >= 0; bit_num--)
        if ((byte & (1 << bit_num)) != 0)
            return bit_num + 1;

    // Should never reach here
    return 0;
}
/*---------------------------------------------------------------------------*/
/* Synchronous PKA implementation */
static void pka_wait_for_results(pka_handle_t handle, pka_results_t *results)
{
    // *TBD*
    // This is weak! We should define a timer here, so that we don't
    // get stuck indefinitely when the test fails to retrieve a result.
    while (true)
    {
        if (!pka_get_result(handle, results))
            break;

        // Wait for a short while (~50 cycles) between attempts to get
        // the result
        pka_wait();
    }
}

static pka_status_t get_results(pka_handle_t   handle,
                                pka_operand_t *result1,
                                pka_operand_t *result2)
{
    pka_results_t  results;
    uint32_t       result1_len, result2_len;
    uint8_t        res1[MAX_BYTE_LEN], res2[MAX_BYTE_LEN];

    memset(&results, 0, sizeof(pka_results_t));
    memset(&res1[0], 0, sizeof(res1));
    memset(&res2[0], 0, sizeof(res2));
    init_results_operand(&results, 2, res1, MAX_BYTE_LEN, res2, MAX_BYTE_LEN);

    pka_wait_for_results(handle, &results);
    if (results.status != RC_NO_ERROR)
    {
        PKA_ERROR(PKA_TESTS,  "get_results status=0x%x\n", results.status);
        return 0;
    }

    if ((2 <= results.results[0].big_endian) || (2 <= results.results[1].big_endian))
        PKA_ERROR(PKA_TESTS, "Bad big_endians=0x%x 0x%x opcode=0x%x\n",
                  results.results[0].big_endian, results.results[1].big_endian,
                  results.opcode);

    if (results.result_cnt != 2)
        PKA_ERROR(PKA_TESTS,  "get_results result_cnt != 2\n");

    if (results.results[0].big_endian != results.results[1].big_endian)
        PKA_ERROR(PKA_TESTS,  "get_results mixed endianness\n");

    if (result1->buf_ptr != NULL)
        free(result1->buf_ptr);

    if (result2->buf_ptr != NULL)
        free(result2->buf_ptr);

    memset(result1, 0, sizeof(pka_operand_t));
    result1_len         = results.results[0].actual_len;
    result1->actual_len = result1_len;
    result1->buf_len    = result1_len;
    result1->buf_ptr    = malloc(result1_len);
    result1->big_endian = results.results[0].big_endian;
    memcpy(result1->buf_ptr, results.results[0].buf_ptr, result1_len);

    memset(result2, 0, sizeof(pka_operand_t));
    result2_len         = results.results[1].actual_len;
    result2->actual_len = result2_len;
    result2->buf_len    = result2_len;
    result2->buf_ptr    = malloc(result2_len);
    result2->big_endian = results.results[1].big_endian;
    memcpy(result2->buf_ptr, results.results[1].buf_ptr, result2_len);

    return SUCCESS;
}

pka_operand_t *sync_add(pka_handle_t   handle,
                        pka_operand_t *value,
                        pka_operand_t *addend)
{
    pka_operand_t *hw_result;
    uint32_t       sum_len;

    // See if the size of the result is too large for the HW, and if so use
    // the sw algorithm.
    sum_len = MAX(value->actual_len, addend->actual_len) + 1;
    if (MAX_BYTE_LEN <= sum_len)
        return sw_add(handle, value, addend);

    if (SUCCESS != pka_add(handle, NULL, value, addend))
    {
        PKA_ERROR(PKA_TESTS,  "sync_add failed\n");
        return NULL;
    }

    hw_result = results_to_operand(handle);

    return hw_result;
}

pka_operand_t *sync_subtract(pka_handle_t   handle,
                             pka_operand_t *value,
                             pka_operand_t *subtrahend)
{
    if (SUCCESS != pka_subtract(handle, NULL, value, subtrahend))
    {
        PKA_ERROR(PKA_TESTS,  "sync_subtract failed\n");
        return NULL;
    }

    return results_to_operand(handle);
}

pka_operand_t *sync_modulo(pka_handle_t   handle,
                           pka_operand_t *value,
                           pka_operand_t *modulus)
{
    if (pki_compare(value, modulus) == RC_LEFT_IS_SMALLER)
        return dup_operand(value);

    if (SUCCESS != pka_modulo(handle, NULL, value, modulus))
    {
        PKA_ERROR(PKA_TESTS,  "sync_modulo failed\n");
        print_operand("  value  =", value,   "\n");
        print_operand("  modulus=", modulus, "\n");
        return NULL;
    }

    return results_to_operand(handle);
}

ecc_point_t *sync_ecc_multiply(pka_handle_t   handle,
                               ecc_curve_t   *curve,
                               ecc_point_t   *pointA,
                               pka_operand_t *multiplier)
{
    ecc_point_t *result_pt;
    uint32_t     buf_len;
    uint8_t      big_endian;

    UNUSED(buf_len);

    if (SUCCESS != pka_ecc_pt_mult(handle, NULL, curve, pointA, multiplier))
    {
        PKA_ERROR(PKA_TESTS,  "sync_ecc_multiply failed\n");
        return NULL;
    }

    buf_len    = curve->p.actual_len;
    big_endian = pka_get_rings_byte_order(handle);
    result_pt  = malloc_ecc_point(curve->p.actual_len,
                                  curve->p.actual_len,
                                  big_endian);
    if (SUCCESS != get_results(handle, &result_pt->x, &result_pt->y))
        return NULL;

    return result_pt;
}

pka_operand_t *sync_mont_ecdh(pka_handle_t      handle,
                            ecc_mont_curve_t *curve,
                            pka_operand_t    *point,
                            pka_operand_t    *private_key)
{
    if (SUCCESS != pka_mont_ecdh_mult(handle, NULL, curve, point,
                                      private_key))
    {
        PKA_ERROR(PKA_TESTS, "sync_ecc_mont_multiply failed\n");
        return NULL;
    }

    return results_to_operand(handle);
}
/*---------------------------------------------------------------------------*/
/* SW operation APIs */
static pka_cmp_code_t pki_compare(pka_operand_t *left, pka_operand_t *right)
{
    uint32_t left_len, right_len, idx;
    uint8_t *left_buf_ptr, *right_buf_ptr;

    if (is_zero(left))
		{
			if (is_zero(right))
				return RC_COMPARE_EQUAL;
			else
				return RC_LEFT_IS_SMALLER;
		}
    else if (is_zero(right))
        return RC_RIGHT_IS_SMALLER;

    left_len      = left->actual_len;
    right_len     = right->actual_len;
    left_buf_ptr  = left->buf_ptr;
    right_buf_ptr = right->buf_ptr;

    // Start the comparison at the most significant end which is at the
    // highest idx.  But first we need to skip any leading zeros!
    left_buf_ptr = &left_buf_ptr[left_len - 1];
    while ((left_buf_ptr[0] == 0) && (2 <= left_len))
		{
			left_buf_ptr--;
			left_len--;
		}

    right_buf_ptr = &right_buf_ptr[right_len - 1];
    while ((right_buf_ptr[0] == 0) && (2 <= right_len))
		{
			right_buf_ptr--;
			right_len--;
		}

    if (left_len < right_len)
        return RC_LEFT_IS_SMALLER;
    else if (right_len < left_len)
        return RC_RIGHT_IS_SMALLER;

    for (idx = 1; idx <= left_len; idx++)
		{
			if (left_buf_ptr[0] < right_buf_ptr[0])
				return  RC_LEFT_IS_SMALLER;
			else if (left_buf_ptr[0] > right_buf_ptr[0])
				return RC_RIGHT_IS_SMALLER;

			left_buf_ptr--;
			right_buf_ptr--;
		}

    return RC_COMPARE_EQUAL;
}

static pka_result_code_t pki_add(pka_operand_t *value,
                                 pka_operand_t *addend,
                                 pka_operand_t *result)
{
    uint32_t value_byte_len, addend_byte_len, result_byte_len;
    uint32_t value_byte, addend_byte, sum_byte, carry, idx, final_len;
    uint8_t *value_buf_ptr, *addend_buf_ptr, *result_buf_ptr;

    value_byte_len  = value->actual_len;
    value_buf_ptr   = value->buf_ptr;
    addend_byte_len = addend->actual_len;
    addend_buf_ptr  = addend->buf_ptr;
    result_byte_len = MAX(value_byte_len, addend_byte_len) + 1;
    result_buf_ptr  = result->buf_ptr;

    carry = 0;
    for (idx = 0; idx < result_byte_len - 1; idx++)
    {
        value_byte  = (idx < value_byte_len)  ? value_buf_ptr[idx]  : 0;
        addend_byte = (idx < addend_byte_len) ? addend_buf_ptr[idx] : 0;
        sum_byte    = value_byte + addend_byte + carry;
        carry       = sum_byte >> 8;
        result_buf_ptr[idx] = (uint8_t) (sum_byte & 0xFF);
    }

    result_buf_ptr[result_byte_len - 1] = carry;

    // Now determine result's actual_len by going backwards (i.e. from MSB
    // to LSB).
    for (idx = result_byte_len - 1; idx != 0; idx--)
        if (result_buf_ptr[idx] != 0)
            break;

    final_len = idx + 1;

    result->actual_len = final_len;
    return RC_NO_ERROR;
}

static pka_result_code_t pki_subtract(pka_operand_t *value,
                                     pka_operand_t *subtrahend,
                                     pka_operand_t *result)
{
    uint32_t minuend_byte_len, subtrahend_byte_len, result_byte_len;
    uint32_t borrow, minuend_byte, subtrahend_byte, result_byte;
    uint32_t byte_cnt;
    uint8_t *minuend_ptr, *subtrahend_ptr, *result_ptr;

    if (pki_compare(value, subtrahend) == RC_LEFT_IS_SMALLER)
        return RC_CALCULATION_ERR;

    minuend_byte_len    = value->actual_len;
    subtrahend_byte_len = subtrahend->actual_len;
    result_byte_len     = minuend_byte_len;
    result->actual_len  = result_byte_len;

    minuend_ptr    = &value->buf_ptr[0];
    subtrahend_ptr = &subtrahend->buf_ptr[0];
    result_ptr     = &result->buf_ptr[0];

    // Subtract subtrahend from minued by proceeding from the least significant
    // bytes to the most significant bytes.
    borrow = 0;
    for (byte_cnt = 0; byte_cnt < minuend_byte_len; byte_cnt++)
    {
        minuend_byte = *minuend_ptr;
        if (byte_cnt < subtrahend_byte_len)
            subtrahend_byte = (*subtrahend_ptr) + borrow;
        else
            subtrahend_byte = borrow;

        if (subtrahend_byte <= minuend_byte)
        {
            result_byte = minuend_byte - subtrahend_byte;
            borrow    = 0;
        }
        else
        {
            result_byte = (256 + minuend_byte) - subtrahend_byte;
            borrow    = 1;
        }

        *result_ptr = result_byte;
        minuend_ptr++;
        subtrahend_ptr++;
        result_ptr++;
    }

    adjust_actual_len(result);
    return RC_NO_ERROR;
}

static pka_result_code_t pki_multiply(pka_operand_t *value,
                                      pka_operand_t *multiplier,
                                      pka_operand_t *result)
{
    uint32_t val_byte_len, mul_byte_len, result_byte_len;
    uint32_t val_idx, mul_idx, result_idx;
    uint32_t value_byte, mul_byte, result_byte, carry;
    uint8_t *val_buf_ptr, *mul_buf_ptr, *result_buf_ptr;

    val_byte_len       = value->actual_len;
    val_buf_ptr        = value->buf_ptr;
    mul_byte_len       = multiplier->actual_len;
    mul_buf_ptr        = multiplier->buf_ptr;
    result_byte_len    = val_byte_len + mul_byte_len;
    result->actual_len = result_byte_len;
    result_buf_ptr     = result->buf_ptr;

    if ((MAX_BUF < val_byte_len) || (MAX_BUF < mul_byte_len) ||
        (MAX_BUF < result_byte_len))
        abort();

    memset(result_buf_ptr, 0, result_byte_len);
    for (val_idx = 0; val_idx < val_byte_len; val_idx++)
    {
        value_byte = val_buf_ptr[val_idx];
        carry      = 0;

        for (mul_idx = 0; mul_idx < mul_byte_len; mul_idx++)
        {
            mul_byte    = mul_buf_ptr[mul_idx];
            result_idx  = val_idx + mul_idx;
            if (MAX_BUF < result_idx)
                abort();

            result_byte = result_buf_ptr[result_idx];
            result_byte = result_byte + (value_byte * mul_byte) + carry;
            carry       = result_byte >> 8;

            result_buf_ptr[result_idx] = (uint8_t) (result_byte & 0xFF);
        }

        result_idx = val_idx + mul_byte_len;
        result_buf_ptr[result_idx] = carry;
        if (MAX_BUF < result_idx)
            abort();
    }

    adjust_actual_len(result);
    return RC_NO_ERROR;
}

static pka_result_code_t pki_modulo(pka_operand_t *value,
                                    pka_operand_t *modulus,
                                    pka_operand_t *result_ptr)
{
    pka_operand_t quotient;
    uint8_t       quot_buf[MAX_BUF];

    PKA_ASSERT(value->big_endian == modulus->big_endian);

    init_operand(&quotient, quot_buf, MAX_BUF, value->big_endian);
    divide_with_remainder(value, modulus, &quotient, result_ptr);
    return RC_NO_ERROR;
}

static pka_result_code_t pki_mod_add(pka_operand_t *value,
                                     pka_operand_t *addend,
                                     pka_operand_t *modulus,
                                     pka_operand_t *result)
{
    pka_operand_t     sum;
    pka_result_code_t rc;
    uint8_t           bufA[MAX_BUF];

    PKA_ASSERT(value->big_endian  == modulus->big_endian);
    PKA_ASSERT(addend->big_endian == modulus->big_endian);

    init_operand(&sum, bufA, MAX_BUF, value->big_endian);

    rc = pki_add(value, addend, &sum);
    adjust_actual_len(&sum);
    if (pki_compare(&sum, modulus) == RC_LEFT_IS_SMALLER)
    {
        result->actual_len = sum.actual_len;
        memcpy(result->buf_ptr, sum.buf_ptr, result->actual_len);
        return RC_NO_ERROR;
    }

    rc = pki_subtract(&sum, modulus, result);
    adjust_actual_len(result);
    return rc;
}

static pka_result_code_t pki_mod_subtract(pka_operand_t *value,
                                          pka_operand_t *subtrahend,
                                          pka_operand_t *modulus,
                                          pka_operand_t *result)
{
    pka_operand_t     reversed_diff;
    pka_result_code_t rc;
    pka_cmp_code_t    comparison;
    uint8_t           bufA[MAX_BUF];

    PKA_ASSERT(value->big_endian       == modulus->big_endian);
    PKA_ASSERT(subtrahend->big_endian  == modulus->big_endian);

    init_operand(&reversed_diff, bufA, MAX_BUF, value->big_endian);

    comparison = pki_compare(value, subtrahend);
    if (comparison == RC_COMPARE_EQUAL)
      return RC_INVALID_ARGUMENT;
    else if (comparison == RC_RIGHT_IS_SMALLER)
        return pki_subtract(value, subtrahend, result);

    // result is -diff mod modulus which is the same as modulus - diff;
    rc = pki_subtract(subtrahend, value, &reversed_diff);
    rc = pki_subtract(modulus, &reversed_diff, result);

    UNUSED(rc);

    return RC_NO_ERROR;
}

static pka_result_code_t pki_mod_multiply(pka_operand_t *value,
                                          pka_operand_t *multiplier,
                                          pka_operand_t *modulus,
                                          pka_operand_t *result)
{
    pka_operand_t product;
    pka_result_code_t rc;
    uint8_t       bufA[MAX_BUF];

    PKA_ASSERT(value->big_endian      == modulus->big_endian);
    PKA_ASSERT(multiplier->big_endian == modulus->big_endian);

    init_operand(&product, bufA, MAX_BUF, value->big_endian);

    rc = pki_multiply(value, multiplier, &product);
    if (rc != RC_NO_ERROR)
        return rc;

    rc = pki_modulo(&product, modulus, result);
    return rc;
}

static pka_result_code_t ecc_double(ecc_curve_t *curve,
                                    ecc_point_t *pointA,
                                    ecc_point_t *result)
{
    pka_operand_t x_squared, temp2, temp3, dbl_y, dbl_y_inv, slope;
    pka_operand_t plus_a, s_squared, dbl_x, ac_xdiff, product;
    uint8_t       bufA[MAX_ECC_BUF], bufB[MAX_ECC_BUF], bufC[MAX_ECC_BUF];
    uint8_t       bufD[MAX_ECC_BUF], bufE[MAX_ECC_BUF], bufF[MAX_ECC_BUF];
    uint8_t       bufG[MAX_ECC_BUF], bufH[MAX_ECC_BUF], bufI[MAX_ECC_BUF];
    uint8_t       bufJ[MAX_ECC_BUF], bufK[MAX_ECC_BUF];
    uint8_t       big_endian;
    pka_result_code_t rc;

    PKA_ASSERT(curve->p.big_endian == curve->a.big_endian);
    PKA_ASSERT(curve->p.big_endian == curve->b.big_endian);
    PKA_ASSERT(curve->p.big_endian == pointA->x.big_endian);
    PKA_ASSERT(curve->p.big_endian == pointA->y.big_endian);
    big_endian = curve->p.big_endian;

    init_operand(&x_squared, bufA, MAX_ECC_BUF, big_endian);
    init_operand(&temp2,     bufB, MAX_ECC_BUF, big_endian);
    init_operand(&temp3,     bufC, MAX_ECC_BUF, big_endian);
    init_operand(&plus_a,    bufD, MAX_ECC_BUF, big_endian);
    init_operand(&dbl_y,     bufE, MAX_ECC_BUF, big_endian);
    init_operand(&dbl_y_inv, bufF, MAX_ECC_BUF, big_endian);
    init_operand(&slope,     bufG, MAX_ECC_BUF, big_endian);
    init_operand(&s_squared, bufH, MAX_ECC_BUF, big_endian);
    init_operand(&dbl_x,     bufI, MAX_ECC_BUF, big_endian);
    init_operand(&ac_xdiff,  bufJ, MAX_ECC_BUF, big_endian);
    init_operand(&product,   bufK, MAX_ECC_BUF, big_endian);

    // ECC point doubling is accomplished using the following formulas:
    // x_squared     = (pointA->x * pointA->x)    mod p;
    // x_sqrd_times3 = (3 * x_squared)            mod p;
    // numer         = (x_sqrd_times3 + curve->a) mod p;
    // dbl_x         = (pointA->x + pointA->x)    mod p;
    // dbl_y         = (pointA->y + pointA->y)    mod p;
    // slope         = (numer / dbl_y)            mod p;
    // s_squared     = (slope * slope)            mod p;
    // result->x     = (s_squared - dbl_x)        mod p;
    // diff          = (pointA->x - result->x)    mod p;
    // product       = (slope * diff)             mod p;
    // result->y     = (product - pointA->y)      mod p;
    rc = pki_mod_multiply(&pointA->x, &pointA->x, &curve->p, &x_squared);
    rc = pki_mod_add(&x_squared,      &x_squared, &curve->p, &temp2);
    rc = pki_mod_add(&temp2,          &x_squared, &curve->p, &temp3);
    rc = pki_mod_add(&temp3,          &curve->a,  &curve->p, &plus_a);
    rc = pki_mod_add(&pointA->y,      &pointA->y, &curve->p, &dbl_y);
    rc = pki_mod_inverse(&dbl_y,              &curve->p, &dbl_y_inv);
    rc = pki_mod_multiply(&plus_a,    &dbl_y_inv, &curve->p, &slope);
    rc = pki_mod_multiply(&slope,     &slope,     &curve->p, &s_squared);
    rc = pki_mod_add(&pointA->x,      &pointA->x, &curve->p, &dbl_x);
    rc = pki_mod_subtract(&s_squared, &dbl_x,     &curve->p, &result->x);
    rc = pki_mod_subtract(&pointA->x, &result->x, &curve->p, &ac_xdiff);
    rc = pki_mod_multiply(&slope,     &ac_xdiff,  &curve->p, &product);
    rc = pki_mod_subtract(&product,   &pointA->y, &curve->p, &result->y);
    
    UNUSED(rc);
    
    return RC_NO_ERROR;
}

static pka_result_code_t pki_mod_inverse(pka_operand_t *value,
                                         pka_operand_t *modulus,
                                         pka_operand_t *result_ptr)
{
    pka_operand_t a, b, quot, abs_x, last_abs_x, temp_abs_x;
    pka_operand_t abs_prod, temp, remain;
    int32_t       x_sign, last_x_sign, temp_x_sign;
    uint8_t       bufA[MAX_BUF], bufB[MAX_BUF], bufC[MAX_BUF], bufD[MAX_BUF];
    uint8_t       bufE[MAX_BUF], bufF[MAX_BUF], bufG[MAX_BUF], bufH[MAX_BUF];
    uint8_t       bufI[MAX_BUF];
    pka_result_code_t rc;
    pka_cmp_code_t    comparison;

    PKA_ASSERT(value->big_endian == modulus->big_endian);

    init_operand(&a,          bufA, MAX_BUF, value->big_endian);
    init_operand(&b,          bufB, MAX_BUF, value->big_endian);
    init_operand(&quot,       bufC, MAX_BUF, value->big_endian);
    init_operand(&abs_x,      bufD, MAX_BUF, value->big_endian);
    init_operand(&last_abs_x, bufE, MAX_BUF, value->big_endian);
    init_operand(&temp_abs_x, bufF, MAX_BUF, value->big_endian);
    init_operand(&abs_prod,   bufG, MAX_BUF, value->big_endian);
    init_operand(&temp,       bufH, MAX_BUF, value->big_endian);
    init_operand(&remain,     bufI, MAX_BUF, value->big_endian);

    comparison = pki_compare(value, modulus);
    if (comparison != RC_LEFT_IS_SMALLER)
        rc = pki_modulo(value, modulus, &a);
    else
        copy_operand(value, &a);

    copy_operand(modulus, &b);
    if (is_zero(&a) || is_zero(&b))
    {
        PKA_ERROR(PKA_TESTS,  "pki_mod_inverse called with zero operands\n");
        return RC_NO_MODULAR_INVERSE;
    }

    // Find x such that a*x - q*b = 1 using the extended euclidean algorithm.
    set_operand(&last_abs_x, 1);
    set_operand(&abs_x,      0);
    last_x_sign = 1;
    x_sign      = 0;

    while (! is_zero(&b))
    {
        divide_with_remainder(&a, &b, &quot, &remain);
        copy_operand(&b,      &a);           // a = b;
        copy_operand(&remain, &b);           // b = remainder;
        copy_operand(&abs_x,  &temp_abs_x);  // temp_abs_x = abs_x;
        temp_x_sign = x_sign;

        // Calculate the next x as "x = last_x - quot * x".  The complications
        // arise, since the bignum arithmetic does not support negative values
        // and we are also careful to prevent multiplication or addition by 0.
        if ((x_sign == 0) || is_zero(&quot))
        {
            copy_operand(&last_abs_x, &abs_x);
            x_sign = last_x_sign;
        }
        else
        {
            rc = pki_multiply(&quot, &abs_x, &abs_prod);
            if (last_x_sign == 0)
            {
                copy_operand(&abs_prod, &abs_x);
                x_sign = -1 * x_sign;
            }
            else if (x_sign != last_x_sign)
            {
                rc     = pki_add(&last_abs_x, &abs_prod, &abs_x);
                x_sign = last_x_sign;
            }
            else
            {
                comparison = pki_compare(&abs_prod, &last_abs_x);
                if (comparison == RC_COMPARE_EQUAL)
                {
                    set_operand(&abs_x, 0);
                    x_sign = 0;
                }
                else if (comparison == RC_LEFT_IS_SMALLER)
                {
                    rc = pki_subtract(&last_abs_x, &abs_prod, &abs_x);
                    // x_sign doesn't change in this case.
                }
                else
                {
                    rc     = pki_subtract(&abs_prod, &last_abs_x, &abs_x);
                    x_sign = -1 * x_sign;
                }
            }
        }

        copy_operand(&temp_abs_x, &last_abs_x);  // last_abs_x  = temp_abs_x;
        last_x_sign = temp_x_sign;
    }

    if (last_x_sign == -1)
        rc = pki_subtract(modulus, &last_abs_x, result_ptr);
    else
        copy_operand(&last_abs_x, result_ptr);

    // Check that inverse is in fact correct:
    rc = pki_mod_multiply(value, result_ptr, modulus, &abs_prod);

    UNUSED(rc);

    if (is_one(&abs_prod))
        return RC_NO_ERROR;
    else
        return RC_NO_MODULAR_INVERSE;
}

static pka_result_code_t pki_ecc_add(ecc_curve_t *curve,
                                     ecc_point_t *pointA,
                                     ecc_point_t *pointB,
                                     ecc_point_t *result_pt)
{
    pka_operand_t ab_xdiff, ab_ydiff, ab_xdiff_inv, slope, s_squared;
    pka_operand_t ab_xsum, ac_xdiff, product;
    uint8_t       bufA[MAX_ECC_BUF], bufB[MAX_ECC_BUF], bufC[MAX_ECC_BUF];
    uint8_t       bufD[MAX_ECC_BUF], bufE[MAX_ECC_BUF], bufF[MAX_ECC_BUF];
    uint8_t       bufG[MAX_ECC_BUF], bufH[MAX_ECC_BUF];
    uint8_t       big_endian;
    pka_result_code_t rc;

    PKA_ASSERT(curve->p.big_endian == curve->a.big_endian);
    PKA_ASSERT(curve->p.big_endian == curve->b.big_endian);
    PKA_ASSERT(curve->p.big_endian == pointA->x.big_endian);
    PKA_ASSERT(curve->p.big_endian == pointA->y.big_endian);
    PKA_ASSERT(curve->p.big_endian == pointB->x.big_endian);
    PKA_ASSERT(curve->p.big_endian == pointB->y.big_endian);
    big_endian = curve->p.big_endian;

    init_operand(&ab_xdiff,      bufA, MAX_ECC_BUF, big_endian);
    init_operand(&ab_ydiff,      bufB, MAX_ECC_BUF, big_endian);
    init_operand(&ab_xdiff_inv,  bufC, MAX_ECC_BUF, big_endian);
    init_operand(&slope,         bufD, MAX_ECC_BUF, big_endian);
    init_operand(&s_squared,     bufE, MAX_ECC_BUF, big_endian);
    init_operand(&ab_xsum,       bufF, MAX_ECC_BUF, big_endian);
    init_operand(&ac_xdiff,      bufG, MAX_ECC_BUF, big_endian);
    init_operand(&product,       bufH, MAX_ECC_BUF, big_endian);

    rc = pki_mod_subtract(&pointA->x, &pointB->x, &curve->p, &ab_xdiff);
    rc = pki_mod_subtract(&pointA->y, &pointB->y, &curve->p, &ab_ydiff);

    if (is_zero(&ab_xdiff) && is_zero(&ab_ydiff))
        return ecc_double(curve, pointA, result_pt);
    else if (is_zero(&ab_xdiff) || is_zero(&ab_ydiff))
        return RC_INTERMEDIATE_PAI;  // *TBD* is this right??

    // ECC point addition is accomplished using the following formulas:
    // ydiff     = (pointA->y - pointB->y) mod p;
    // xdiff     = (pointA->x - pointB->x) mod p;
    // xsum      = (pointA->x + pointB->x) mod p;
    // slope     = (ydiff / xdiff)         mod p;
    // s_squared = (slope * slope)         mod p;
    // result->x = (s_squared - xsum)      mod p;
    // diff      = (pointA->x, result->x)  mod p;
    // product   = (slope * diff)          mod p;
    // result->y = (product - pointA->y)   mod p;
    rc = pki_mod_inverse(&ab_xdiff,              &curve->p, &ab_xdiff_inv);
    rc = pki_mod_multiply(&ab_ydiff,  &ab_xdiff_inv, &curve->p, &slope);
    rc = pki_mod_multiply(&slope,     &slope,        &curve->p, &s_squared);
    rc = pki_mod_add(&pointA->x,      &pointB->x,    &curve->p, &ab_xsum);
    rc = pki_mod_subtract(&s_squared, &ab_xsum,      &curve->p, &result_pt->x);
    rc = pki_mod_subtract(&pointA->x, &result_pt->x, &curve->p, &ac_xdiff);
    rc = pki_mod_multiply(&slope,     &ac_xdiff,     &curve->p, &product);
    rc = pki_mod_subtract(&product,   &pointA->y,    &curve->p, &result_pt->y);

    UNUSED(rc);

    adjust_actual_len(&result_pt->x);
    adjust_actual_len(&result_pt->y);
    return RC_NO_ERROR;
}

static pka_result_code_t pki_ecc_multiply(ecc_curve_t   *curve,
                                          ecc_point_t   *pointA,
                                          pka_operand_t *multiplier,
                                          ecc_point_t   *result_point)
{
    ecc_point_t   result_pt, new_result_pt, base_pt, new_base_pt;
    uint32_t      mult_bit_len, mult_bit_idx;
    uint8_t       result_is_0;
    uint8_t       bufA[MAX_ECC_BUF], bufB[MAX_ECC_BUF], bufC[MAX_ECC_BUF];
    uint8_t       bufD[MAX_ECC_BUF], bufE[MAX_ECC_BUF], bufF[MAX_ECC_BUF];
    uint8_t       bufG[MAX_ECC_BUF], bufH[MAX_ECC_BUF];
    uint8_t       big_endian;
    pka_result_code_t rc;

    PKA_ASSERT(curve->p.big_endian == curve->a.big_endian);
    PKA_ASSERT(curve->p.big_endian == curve->b.big_endian);
    PKA_ASSERT(curve->p.big_endian == pointA->x.big_endian);
    PKA_ASSERT(curve->p.big_endian == pointA->y.big_endian);
    PKA_ASSERT(curve->p.big_endian == multiplier->big_endian);
    big_endian = curve->p.big_endian;

    init_ecc_point(&result_pt,     bufA, bufB, MAX_ECC_BUF, big_endian);
    init_ecc_point(&new_result_pt, bufC, bufD, MAX_ECC_BUF, big_endian);
    init_ecc_point(&base_pt,       bufE, bufF, MAX_ECC_BUF, big_endian);
    init_ecc_point(&new_base_pt,   bufG, bufH, MAX_ECC_BUF, big_endian);

    // Copy pointA into base_pt and get multiplier bit length.
    copy_ecc_point(pointA, &base_pt);
    mult_bit_len = operand_bit_len(multiplier);
    if (mult_bit_len < 2)
    {
        PKA_ERROR(PKA_TESTS,  "mult_bit_len=%u\n", mult_bit_len);
        return RC_OPERAND_VALUE_ERR;
    }
    // Initialize result to be 0.
    result_is_0 = 1;

    for (mult_bit_idx = 0; mult_bit_idx < mult_bit_len; mult_bit_idx++)
    {
        if (get_bit(multiplier, mult_bit_idx) != 0)
        {
            // Add base_pt to result.  Special case for the first addition,
            // where result is zero.
            if (result_is_0)
            {
                copy_ecc_point(&base_pt, &result_pt);
                result_is_0 = 0;
            }
            else
            {
                rc = pki_ecc_add(curve, &result_pt, &base_pt, &new_result_pt);
                copy_ecc_point(&new_result_pt, &result_pt);
            }
        }

        // Double the base_pt.
        rc = ecc_double(curve, &base_pt, &new_base_pt);
        copy_ecc_point(&new_base_pt, &base_pt);
    }

    UNUSED(rc);

    copy_ecc_point(&result_pt, result_point);
    adjust_actual_len(&result_point->x);
    adjust_actual_len(&result_point->y);
    return RC_NO_ERROR;
}

static pka_result_code_t pki_ecdsa_generate(ecc_curve_t     *curve,
                                            ecc_point_t     *base_pt,
                                            pka_operand_t   *base_pt_order,
                                            pka_operand_t   *private_key,
                                            pka_operand_t   *hash,
                                            pka_operand_t   *k,
                                            dsa_signature_t *signature_result)
{
    pka_operand_t k_inv, product, sum, r, s;
    ecc_point_t   kG;
    uint8_t       bufA[MAX_ECC_BUF], bufB[MAX_ECC_BUF], bufC[MAX_ECC_BUF];
    uint8_t       bufD[MAX_ECC_BUF], bufE[MAX_ECC_BUF], bufF[MAX_ECC_BUF];
    uint8_t       bufG[MAX_ECC_BUF];
    uint8_t       big_endian;
    pka_result_code_t rc;

    PKA_ASSERT(curve->p.big_endian == curve->a.big_endian);
    PKA_ASSERT(curve->p.big_endian == curve->b.big_endian);
    PKA_ASSERT(curve->p.big_endian == base_pt->x.big_endian);
    PKA_ASSERT(curve->p.big_endian == base_pt->y.big_endian);
    PKA_ASSERT(curve->p.big_endian == base_pt_order->big_endian);
    PKA_ASSERT(curve->p.big_endian == private_key->big_endian);
    PKA_ASSERT(hash->big_endian    == private_key->big_endian);
    PKA_ASSERT(k->big_endian       == hash->big_endian);
    big_endian = curve->p.big_endian;

    init_operand(&k_inv,   bufA, MAX_ECC_BUF, big_endian);
    init_operand(&product, bufB, MAX_ECC_BUF, big_endian);
    init_operand(&sum,     bufC, MAX_ECC_BUF, big_endian);
    init_operand(&r,       bufD, MAX_ECC_BUF, big_endian);
    init_operand(&s,       bufE, MAX_ECC_BUF, big_endian);
    init_ecc_point(&kG,    bufF, bufG, MAX_ECC_BUF, big_endian);

    // kG = k * base_pt;             // This is an "ECC" point multiplication.
    // r  = kG.x mod base_pt_order;
    // s  = (k_inv * (hash + private_key * r) mod base_pt_order;
    rc = pki_mod_inverse (k,       base_pt_order, &k_inv);
    rc = pki_ecc_multiply(curve,   base_pt, k,    &kG);
    rc = pki_modulo      (&kG.x,   base_pt_order, &r);

    rc = pki_mod_multiply(private_key, &r,       base_pt_order, &product);
    rc = pki_mod_add     (hash,        &product, base_pt_order, &sum);
    rc = pki_mod_multiply(&k_inv,      &sum,     base_pt_order, &s);

    UNUSED(rc);

    copy_operand(&r, &signature_result->r);
    copy_operand(&s, &signature_result->s);
    adjust_actual_len(&signature_result->r);
    adjust_actual_len(&signature_result->s);
    return RC_NO_ERROR;
}

static pka_operand_t *sw_add(pka_handle_t   handle,
                             pka_operand_t *value,
                             pka_operand_t *addend)
{
    pka_result_code_t  rc;
    pka_operand_t     *result;
    uint32_t           value_byte_len, addend_byte_len, result_byte_len;
    uint8_t            big_endian;

    big_endian = pka_get_rings_byte_order(handle);
    if ((value->big_endian != big_endian) ||
            (addend->big_endian != big_endian))
    {
        PKA_ERROR(PKA_TESTS,  "sw_add endian mismatch.\n");
        return NULL;
    }

    value_byte_len     = value->actual_len;
    addend_byte_len    = addend->actual_len;
    result_byte_len    = MAX(value_byte_len, addend_byte_len) + 1;
    result             = malloc_operand(result_byte_len);
    result->big_endian = big_endian;

    rc = pki_add(value, addend, result);
    if (rc == RC_NO_ERROR)
        return result;

    PKA_ERROR(PKA_TESTS,  "sw_add failed rc=%d\n", rc);
    free_operand(result);
    return NULL;
}

dsa_signature_t *sw_ecdsa_gen(pka_handle_t   handle,
                              ecc_curve_t   *curve,
                              ecc_point_t   *base_pt,
                              pka_operand_t *base_pt_order,
                              pka_operand_t *private_key,
                              pka_operand_t *hash,
                              pka_operand_t *k)
{
    dsa_signature_t   *signature;
    pka_result_code_t  rc;
    uint8_t            big_endian;

    big_endian = pka_get_rings_byte_order(handle);
    signature  = malloc_dsa_signature(MAX_ECC_BUF, MAX_ECC_BUF, big_endian);

    rc = pki_ecdsa_generate(curve, base_pt, base_pt_order,
                                private_key, hash, k, signature);
    if (rc == RC_NO_ERROR)
        return signature;

    PKA_ERROR(PKA_TESTS,  "sw_ecdsa_gen failed rc=%d\n", rc);
    free_dsa_signature(signature);
    return NULL;
}
