#include <stdio.h>
#include <string.h>

#include "pka_helper.h"

static void operand_byte_copy(pka_operand_t *operand,
                              uint8_t       *buf_ptr,
                              uint32_t       buf_len)
{
    PKA_ASSERT(operand != NULL);
    PKA_ASSERT(buf_ptr != NULL);
    PKA_ASSERT(buf_len <= operand->buf_len);
    operand->actual_len = buf_len;

    // BIG ASSUMPTION: OpenSSL treats all series of bytes (unsigned char
    //                 arrays) depending on the underlying architecture.
    //                 Since we are running in Little endian, no need to
    //                 swap bytes while copying buffers.
    memcpy(operand->buf_ptr, buf_ptr, buf_len);
}

static pka_operand_t *make_operand(PKA_ULONG *bn_buf_ptr,
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

pka_operand_t *bignum_to_operand(pka_bignum_t *bignum)
{
    uint32_t byte_len, byte_max_len;

    if (bignum)
    {
        byte_len     = bignum->top  * PKA_BYTES;
        byte_max_len = bignum->dmax * PKA_BYTES;

        return make_operand(bignum->d, byte_len, byte_max_len, 0);
    }

    return NULL;
}
