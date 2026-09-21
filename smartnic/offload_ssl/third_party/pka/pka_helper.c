#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "pka_helper.h"

extern uint32_t C255_base_pt_order_byte_len;
/*---------------------------------------------------------------------------*/
/* helpers */
void byte_swap_copy(uint8_t *dest, uint8_t *src, uint32_t len)
{
    uint32_t idx;

    for (idx = 0; idx < len; idx++)
        dest[idx] = src[(len - 1) - idx];
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

void copy_operand(pka_operand_t *original, pka_operand_t *copy)
{
    uint8_t *copy_buf_ptr;

    copy_buf_ptr = copy->buf_ptr;
    memcpy(copy, original, sizeof(pka_operand_t));

    copy->buf_ptr = copy_buf_ptr;
    memcpy(copy->buf_ptr, original->buf_ptr, original->actual_len);
}

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
string_to_operand(uint8_t* str, pka_operand_t* op, uint16_t len, int endian)
{
    uint8_t* big_num_ptr;
    int i;

#if VERBOSE_KEY
    unsigned z = 0;
    fprintf(stderr, "\nPKA request data:\n\n");
    {
        for (z = 0; z < len; z++)
            fprintf(stderr, "%02X%c", *((uint8_t *)(str) + z),
                ((z + 1) % 16) ? ' ' : '\n');
    }
#endif /* VERBOSE_KEY */

    assert(op != NULL);
    assert(op->buf_ptr != NULL);

    memset(op->buf_ptr, 0, op->buf_len);

    op->actual_len = len;
    op->is_encrypted = 0;
    op->big_endian = endian;

    if (endian)
        big_num_ptr = &op->buf_ptr[0];
    else
        big_num_ptr = &op->buf_ptr[len - 1];

    for (i = 0; i < len; i++) {
        if (endian)
            *big_num_ptr++ = str[i];
        else
            *big_num_ptr-- = str[i];
    }
}

/*
 * This function changes to operand to string at most max_len.
 *
 * @op      The operand which will be converted to string
 * @str     The pointer which will contain the result
 * @max_len The maximum length of result string
 */
void
operand_to_string(pka_operand_t* op, uint8_t* str, uint16_t max_len)
{
    uint32_t len = MIN(max_len, op->actual_len);
    uint32_t i;
    uint8_t* byte_ptr;

#if VERBOSE_KEY
    unsigned z = 0;
    fprintf(stderr, "\nPKA return data:\n\n");
    {
        for (z = 0; z < len; z++)
            fprintf(stderr, "%02X%c", *((uint8_t *)(op->buf_ptr) + z),
                ((z + 1) % 16) ? ' ' : '\n');
    }
#endif /* VERBOSE_KEY */

    //memset(str, 0, max_len);

    if (op->big_endian) {
        byte_ptr = &op->buf_ptr[0];
        for (i = 0; i < len; i++) {
            str[i] = *byte_ptr++;
        }
    } else {
        byte_ptr = &op->buf_ptr[len - 1];
        for (i = 0; i < len; i++) {
            str[i] = *byte_ptr--;
        }
    }
}
/*---------------------------------------------------------------------------*/
/* RSA */
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

pka_operand_t *bignum_to_operand_rsa(pka_bignum_t *bignum)
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
/*---------------------------------------------------------------------------*/
/* ECDSA-ECDHE*/
pka_operand_t *make_operand_ecdsa(PKA_ULONG *bn_buf_ptr,
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
    operand->buf_len    = buf_len;
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

        return make_operand_ecdsa(bignum->d, byte_len, byte_max_len, 1);
    }

    return NULL;
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

static pka_operand_t *malloc_operand(uint32_t buf_len)
{
    pka_operand_t *operand;

    operand             = calloc(1, sizeof(pka_operand_t));
    operand->buf_ptr    = calloc(1, buf_len);
    operand->buf_len    = buf_len;
    operand->actual_len = 0;
    return operand;
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

static void make_operand_buf(pka_operand_t *operand,
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

// Return a big number between 1 .. max_plus_1 - 1.
void rand_non_zero_integer(pka_handle_t   handle,
                               pka_operand_t *result,
                               pka_operand_t *max_plus_1)
{
    uint32_t       byte_len, msb_idx, max_plus_msb, result_msb;

    byte_len           = operand_byte_len(max_plus_1);
    result->big_endian = pka_get_rings_byte_order(handle);
    result->actual_len = byte_len;

    do
		{
			get_rand_bytes(handle, &result->buf_ptr[0], byte_len);
		} while (is_zero(result));
        
    if (pki_compare(result, max_plus_1) == RC_LEFT_IS_SMALLER)
        return;

    // Need to reduce the most significant byte of the result to be less than
    // the most significant byte of max_plus_1.  First get msb of max_plus_1.
    msb_idx      = get_msb_idx(max_plus_1);
    max_plus_msb = max_plus_1->buf_ptr[msb_idx];
    PKA_ASSERT(max_plus_msb != 0);

    // Next find msb of the result and adjust it.
    msb_idx                  = get_msb_idx(result);
    result_msb               = result->buf_ptr[msb_idx];
    result->buf_ptr[msb_idx] = result_msb % max_plus_msb;

    return;
}

// Return a big number between 1 .. max_plus_1 - 1.
void rand_non_zero_integer_wo_syscall(pka_handle_t   handle,
                                      pka_operand_t *result,
                                      pka_operand_t *max_plus_1)
{
    result->big_endian = pka_get_rings_byte_order(handle);
    result->actual_len = C255_base_pt_order_byte_len;

    do
		{
            uint64_t *ptr = (uint64_t *)result->buf_ptr;
            ptr[0] = rte_rand(); /* TODO: change rng func as cryptographically secure one */
            ptr[1] = rte_rand();
            ptr[2] = rte_rand();
            ptr[3] = rte_rand();
        } while (is_zero(result) || pki_compare(result, max_plus_1) != RC_LEFT_IS_SMALLER);
        
    return;
}

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

    return;
}

void rand_non_zero_integer_w_rte_rand_and_clamping(pka_handle_t   handle,
                                                    pka_operand_t *result,
                                                    pka_operand_t *max_plus_1)
{
    result->big_endian = pka_get_rings_byte_order(handle);
    result->actual_len = C255_base_pt_order_byte_len;

    uint64_t *ptr = (uint64_t *)result->buf_ptr;
    ptr[0] = rte_rand(); /* TODO: change rng func as cryptographically secure one */
    ptr[1] = rte_rand();
    ptr[2] = rte_rand();
    ptr[3] = rte_rand();

    result->buf_ptr[0] &= 248;
    result->buf_ptr[31] &= 127;
    result->buf_ptr[31] |= 64;
      
    return;
}
