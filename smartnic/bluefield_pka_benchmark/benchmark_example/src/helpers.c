#include <openssl/aes.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "helpers.h"

#if !TEST_RSA
#include <openssl/kdf.h>
#endif /* !TEST_RSA */

/*---------------------------------------------------------------------------------------*/
// eclipse function parameter for ECC
// All of the following constants are in big-endian format.
extern uint8_t P256_p_buf[32];
extern uint8_t P256_a_buf[32];
extern uint8_t P256_b_buf[32];

extern uint8_t P256_xg_buf[32];
extern uint8_t P256_yg_buf[32];
extern uint8_t P256_n_buf[32];

// 2^255 - 19 in big-endian
extern uint8_t X25519_curve_p_buf[32];
extern uint8_t X25519_curve_A_buf[3];
extern uint8_t Curve255_bp_u_buf[1];
extern uint8_t Curve255_bp_v_buf[32];
extern uint8_t Curve255_bp_order_buf[32];

extern uint8_t HEX_CHARS[16];
extern uint8_t FROM_HEX[256];

/* RSA specific variables
 *
 * p, q: two prime numbers to make a key pair
 * dmp1, dmpq1, iqmp: values for CRT, conducted from p, q
 * n: modulus
 * e: exponent(public key)
 * d: exponent(private key)                                 */
extern EVP_PKEY *rsa_private_key;
extern pka_operand_t *p, *q, *d_p, *d_q, *qinv;
extern pka_operand_t *rsa_encrypt_key, *rsa_decrypt_key, *rsa_modulus,
    *rsa_ciphertext;

/* EC specific variables
 *
 * a, b, p: parameter of elliptic curve
 * ec_private_key: a big prime number k, less than P
 * x, y: public_key K = (x, y) = k*G, where G is well-known starting point on
 * the graph P256_base_pt: G note: multiply and add operation in ECC are totally
 * different with regular ones */
extern ecc_curve_t *P256_curve;
extern ecc_point_t *P256_base_pt;
extern pka_operand_t *P256_base_pt_order;

extern ecc_mont_curve_t *X25519_curve;
extern ecc_point_t *C255_base_pt;
extern pka_operand_t *C255_base_pt_order;
extern uint32_t C255_base_pt_order_byte_len;

extern pka_operand_t **ec_priv_key;
extern ecc_point_t **ec_pub_key_ep;
extern pka_operand_t **ec_pub_key_po;

extern pka_operand_t **remote_ec_priv_key;
extern ecc_point_t **remote_ec_pub_key_ep;
extern pka_operand_t **remote_ec_pub_key_po;

extern pka_operand_t **ec_priv_key_x25519_0;
extern pka_operand_t **ec_priv_key_x25519_1;
extern pka_operand_t **ec_pub_key_x25519;

extern pka_operand_t **remote_ec_priv_key_x25519;
extern pka_operand_t **remote_ec_pub_key_x25519;

extern ecc_point_t **remote_shared_secret_ep;
extern pka_operand_t **remote_shared_secret_po;
extern dsa_signature_t **answer;

extern pka_operand_t **k;
extern pka_operand_t **hash;

/* other global variables */
extern int thread_num;
extern struct timespec start_ts;
extern int is_tls13_benchmark;
extern size_t cmd_cnt[MAX_THREAD_NUM];
extern tls13_op_cnt_t tls13_op_cnt[MAX_THREAD_NUM];
extern size_t tls13_sess_cnt[MAX_THREAD_NUM];

// static uint8_t TWO_BUFFER[1]  = { 0x02 };
static uint8_t ONE_BUFFER[1] = {0x01};
// static uint8_t ZERO_BUFFER[1] = { 0x00 };

// static pka_operand_t TWO =
// {
//     .buf_len    = 1,
//     .actual_len = 1,
//     .buf_ptr    = &TWO_BUFFER[0],
// 	.big_endian = 0
// };

static pka_operand_t ONE = {
    .buf_len = 1, .actual_len = 1, .buf_ptr = &ONE_BUFFER[0], .big_endian = 0};

// static pka_operand_t ZERO =
// {
//     .buf_len    = 1,
//     .actual_len = 1,
//     .buf_ptr    = &ZERO_BUFFER[0],
// 	.big_endian = 0
// };
/*---------------------------------------------------------------------------------------*/
void
usage()
{
    printf("usage: ./pka_benchmark -m [mode] -t [thread_num] -r [ring_num] -o "
           "[outstanding_cmd_num] -n [command_num_per_thread]\n");
    printf("mode\n 0: RSA_DECRYPTION\n 1: P256\n 2: X25519\n 3: "
           "ECDSA_SIG_GEN\n 4: TLS13\n 5: RAND\n");
}

void
print_hex(pka_operand_t *value)
{
    printf("0x");
    for (uint32_t i = 0; i < value->actual_len; i++) {
        printf("%02X", value->buf_ptr[i]);
    }
    printf("\n");
}

int
from_hex_string(char *hex_string, pka_operand_t *value)
{
    uint32_t string_len, hexDigitCnt, char_idx, byte_len, hexDigitState;
    uint32_t hex_value, hex_value1 = 0;
    uint8_t *big_num_ptr, ch, big_endian, byte_value;

    // Skip the initial 0x, if present
    string_len = strlen(hex_string);
    if ((3 <= string_len) && (hex_string[0] == '0') && (hex_string[1] == 'x')) {
        hex_string += 2;
        string_len -= 2;
    }

    /* fprintf(stderr, "from_hex_string: debug 0\n"); */

    // Next count the number of hexadecimal characters in the string (i.e.
    // ignoring things like spaces and underscores).
    hexDigitCnt = 0;

    for (char_idx = 0; char_idx < string_len; char_idx++) {
        ch = hex_string[char_idx];
        if (isxdigit(ch))
            hexDigitCnt++;
        else if ((!isspace(ch)) && (ch != '_')) {
            return -1;
        }
    }

    byte_len = (hexDigitCnt + 1) / 2;
    if (value->buf_ptr == NULL) {
        value->buf_ptr = malloc(byte_len);
        value->buf_len = byte_len;
    } else if (value->buf_len < byte_len) {
        return -1;
    }

    value->actual_len = byte_len;
    value->is_encrypted = 0;
    big_endian = value->big_endian;
    if (big_endian)
        big_num_ptr = &value->buf_ptr[0];
    else
        big_num_ptr = &value->buf_ptr[byte_len - 1];

    hexDigitState = 0;
    hex_value1 = 0;
    if ((hexDigitCnt & 0x1) != 0)
        hexDigitState = 1;

    for (char_idx = 0; char_idx < string_len; char_idx++) {
        ch = hex_string[char_idx];
        if (isxdigit(ch)) {
            hex_value = FROM_HEX[ch];
            if (hexDigitState == 0) {
                hex_value1 = hex_value;
                hexDigitState = 1;
            } else {
                byte_value = (hex_value1 << 4) | hex_value;
                hexDigitState = 0;
                if (big_endian)
                    *big_num_ptr++ = byte_value;
                else
                    *big_num_ptr-- = byte_value;
            }
        }
    }

    return 0;
}

int
to_hex_string(pka_operand_t *value, char *string_buf, uint32_t buf_len)
{
    uint32_t byte_len, byte_cnt, byte_value;
    uint8_t *byte_ptr;
    char *char_ptr;

    byte_len = value->actual_len;
    if (buf_len <= byte_len)
        return -1;

    memset(string_buf, 0, buf_len);

    if (value->big_endian) {
        byte_ptr = &value->buf_ptr[0];
        char_ptr = &string_buf[0];
        for (byte_cnt = 0; byte_cnt < byte_len; byte_cnt++) {
            byte_value = *byte_ptr++;
            *char_ptr++ = HEX_CHARS[byte_value >> 4];
            *char_ptr++ = HEX_CHARS[byte_value & 0x0F];
        }
    } else {
        byte_ptr = &value->buf_ptr[byte_len - 1];
        char_ptr = &string_buf[0];
        for (byte_cnt = 0; byte_cnt < byte_len; byte_cnt++) {
            byte_value = *byte_ptr--;
            *char_ptr++ = HEX_CHARS[byte_value >> 4];
            *char_ptr++ = HEX_CHARS[byte_value & 0x0F];
        }
    }

    return 0;
}

int
bn2binpad(const BIGNUM *bn, unsigned char *out, int out_len)
{
    int bn_len = BN_num_bytes(bn);

    if (bn_len > out_len)
        return -1;

    // forward zero padding
    memset(out, 0, out_len - bn_len);

    // copy values (big-endian)
    BN_bn2bin(bn, out + (out_len - bn_len));

    return out_len;
}

int
Get_RSA_key_pair(char *pem_filename)
{
#if TEST_RSA
    FILE *fp_pem;
    RSA *rsa;

    if ((fp_pem = fopen(pem_filename, "r")) == NULL) {
        perror("fopen");
        exit(0);
    }

    rsa_private_key = PEM_read_PrivateKey(fp_pem, NULL, NULL, NULL);

    if (rsa_private_key == NULL || rsa_private_key->pkey.rsa == NULL) {
        perror("PEM_READ");
        exit(0);
    }

    fclose(fp_pem);

    rsa = rsa_private_key->pkey.rsa;

    if (rsa->p && rsa->q && rsa->dmp1 && rsa->dmq1 && rsa->iqmp) {
#if DBG_MODE
        printf("p: ");
        BN_print(out, rsa->p);
        printf("\nq: ");
        BN_print(out, rsa->q);
        printf("\ndmp1: ");
        BN_print(out, rsa->dmp1);
        printf("\ndmq1: ");
        BN_print(out, rsa->dmq1);
        printf("\niqmp: ");
        BN_print(out, rsa->iqmp);
        printf("\n");
#endif /* DBG_MODE */
        p = bignum_to_operand((pka_bignum_t *)rsa->p);
        q = bignum_to_operand((pka_bignum_t *)rsa->q);
        d_p = bignum_to_operand((pka_bignum_t *)rsa->dmp1);
        d_q = bignum_to_operand((pka_bignum_t *)rsa->dmq1);
        qinv = bignum_to_operand((pka_bignum_t *)rsa->iqmp);
    }
    if (rsa->d) {
#if DBG_MODE
        printf("\nd: ");
        BN_print(out, rsa->d);
        printf("\nn: ");
        BN_print(out, rsa->n);
        printf("\ne: ");
        BN_print(out, rsa->e);
        printf("\n");
#endif /* DBG_MODE */
        rsa_encrypt_key = bignum_to_operand((pka_bignum_t *)rsa->e);
        rsa_decrypt_key = bignum_to_operand((pka_bignum_t *)rsa->d);
        rsa_modulus = bignum_to_operand((pka_bignum_t *)rsa->n);
    }

#if DBG_MODE
    print_operand("rsa_encrypt_key = ", rsa_encrypt_key, "\n");
    print_operand("rsa_decrypt_key = ", rsa_decrypt_key, "\n");
    print_operand("rsa_modulus = ", rsa_modulus, "\n");
#endif /* DBG_MODE */
#else  /* !TEST_RSA */
    UNUSED(pem_filename);
#endif /* TEST_RSA */

    return SUCCESS;
}

int
Get_P256_key_pair(pka_handle_t handle, int big_endian)
{
    /* make room for ec_priv_key and ec_pub_key */
    ec_priv_key = calloc(MAX_OUTSTANDING_CMD_NUM, sizeof(pka_operand_t *));
    ec_pub_key_ep = calloc(MAX_OUTSTANDING_CMD_NUM, sizeof(ecc_point_t *));
    remote_ec_priv_key =
        calloc(MAX_OUTSTANDING_CMD_NUM, sizeof(pka_operand_t *));
    remote_ec_pub_key_ep =
        calloc(MAX_OUTSTANDING_CMD_NUM, sizeof(ecc_point_t *));
    remote_shared_secret_ep =
        calloc(MAX_OUTSTANDING_CMD_NUM, sizeof(ecc_point_t *));

    /* allocate ecc point and curve */
    P256_curve = make_ecc_curve(P256_p_buf, sizeof(P256_p_buf), P256_a_buf,
                                sizeof(P256_a_buf), P256_b_buf,
                                sizeof(P256_b_buf), big_endian);

#if DBG_MODE
    print_operand("curve.p = ", &P256_curve->p, "\n");
    print_operand("curve.a = ", &P256_curve->a, "\n");
    print_operand("curve.b = ", &P256_curve->b, "\n");
    fprintf(stderr, "curve.p's endian: %s\n",
            P256_curve->p.big_endian ? "big-endian" : "little-endian");
#endif /* DBG_MODE */

    if (P256_curve == NULL)
        return -1;

    if (!P256_curve->p.buf_ptr || !P256_curve->a.buf_ptr ||
        !P256_curve->b.buf_ptr)
        return -1;

    P256_base_pt = make_ecc_point(P256_curve, P256_xg_buf, sizeof(P256_xg_buf),
                                  P256_yg_buf, sizeof(P256_yg_buf), big_endian);

#if DBG_MODE
    print_operand("base_pt.x = ", &P256_base_pt->x, "\n");
    print_operand("base_pt.y = ", &P256_base_pt->y, "\n");
#endif /* DBG_MODE */

    if (P256_base_pt == NULL)
        return -1;

    P256_base_pt_order =
        make_operand(P256_n_buf, sizeof(P256_n_buf), big_endian);

#if DBG_MODE
    print_operand("P256_base_pt_order = ", P256_base_pt_order, "\n");
#endif /* DBG_MODE */

    if (P256_base_pt_order == NULL)
        return -1;

    /* generate EC key pair */
    for (int i = 0; i < MAX_OUTSTANDING_CMD_NUM; i++) {
        ec_priv_key[i] = rand_non_zero_integer(handle, P256_base_pt_order);
        ec_pub_key_ep[i] =
            sync_ecc_multiply(handle, P256_curve, P256_base_pt, ec_priv_key[i]);
        remote_ec_priv_key[i] =
            rand_non_zero_integer(handle, P256_base_pt_order);
        remote_ec_pub_key_ep[i] = sync_ecc_multiply(
            handle, P256_curve, P256_base_pt, remote_ec_priv_key[i]);

        if (!ec_priv_key[i]->buf_ptr || !ec_pub_key_ep[i]->x.buf_ptr ||
            !ec_pub_key_ep[i]->y.buf_ptr) {
            fprintf(stderr, "EC Key Pair Generation Failed!\n");
            return -1;
        }

        if (!remote_ec_priv_key[i]->buf_ptr ||
            !remote_ec_pub_key_ep[i]->x.buf_ptr ||
            !remote_ec_pub_key_ep[i]->y.buf_ptr) {
            fprintf(stderr, "Remote EC Key Pair Generation Failed!\n");
            return -1;
        }
    }

    fprintf(stderr, "ECC Key Pair Generated.\n");

    /* generate answers */
    for (int i = 0; i < MAX_OUTSTANDING_CMD_NUM; i++) {
        remote_shared_secret_ep[i] = sync_ecc_multiply(
            handle, P256_curve, ec_pub_key_ep[i], remote_ec_priv_key[i]);
    }

    fprintf(stderr, "Answers Generated.\n");

    fprintf(stderr, "Now test will be started...\n");

    return SUCCESS;
}

int
Get_X25519_key_pair(pka_handle_t handle, int big_endian)
{
    /* make room for ec_priv_key and ec_pub_key */
    ec_priv_key_x25519_0 =
        calloc(MAX_OUTSTANDING_CMD_NUM, sizeof(pka_operand_t *));
    ec_priv_key_x25519_1 =
        calloc(MAX_OUTSTANDING_CMD_NUM, sizeof(pka_operand_t *));
    ec_pub_key_x25519 =
        calloc(MAX_OUTSTANDING_CMD_NUM, sizeof(pka_operand_t *));
    remote_ec_priv_key_x25519 =
        calloc(MAX_OUTSTANDING_CMD_NUM, sizeof(pka_operand_t *));
    remote_ec_pub_key_x25519 =
        calloc(MAX_OUTSTANDING_CMD_NUM, sizeof(pka_operand_t *));
    remote_shared_secret_po =
        calloc(MAX_OUTSTANDING_CMD_NUM, sizeof(pka_operand_t *));

    /* allocate ecc point and curve */
    X25519_curve = calloc(1, sizeof(ecc_mont_curve_t));
    set_pka_operand(&X25519_curve->p, X25519_curve_p_buf,
                    sizeof(X25519_curve_p_buf), big_endian);
    set_pka_operand(&X25519_curve->A, X25519_curve_A_buf,
                    sizeof(X25519_curve_A_buf), big_endian);
    X25519_curve->type = PKA_CURVE_25519;

#if DBG_MODE
    print_operand("X25519_curve.p = ", &X25519_curve->p, "\n");
    print_operand("X25519_curve.A = ", &X25519_curve->A, "\n");
    fprintf(stderr, "X25519_curve.p's endian: %s\n",
            X25519_curve->p.big_endian ? "big-endian" : "little-endian");
#endif /* DBG_MODE */

    if (X25519_curve == NULL)
        return -1;

    if (!X25519_curve->p.buf_ptr || !X25519_curve->A.buf_ptr)
        return -1;

    C255_base_pt = make_mont_ecc_point(
        X25519_curve, Curve255_bp_u_buf, sizeof(Curve255_bp_u_buf),
        Curve255_bp_v_buf, sizeof(Curve255_bp_v_buf), big_endian);

#if DBG_MODE
    print_operand("C255_base_pt.x = ", &C255_base_pt->x, "\n");
    print_operand("C255_base_pt.y = ", &C255_base_pt->y, "\n");
#endif /* DBG_MODE */

    if (C255_base_pt == NULL)
        return -1;

    C255_base_pt_order = make_operand(
        Curve255_bp_order_buf, sizeof(Curve255_bp_order_buf), big_endian);

    C255_base_pt_order_byte_len = operand_byte_len(C255_base_pt_order);

#if DBG_MODE
    print_operand("C255_base_pt_order = ", C255_base_pt_order, "\n");
#endif /* DBG_MODE */

    if (C255_base_pt_order == NULL)
        return -1;

    /* generate EC key pair */
    for (int i = 0; i < MAX_OUTSTANDING_CMD_NUM; i++) {
        ec_priv_key_x25519_0[i] =
            rand_non_zero_integer(handle, C255_base_pt_order);
        ec_priv_key_x25519_1[i] =
            rand_non_zero_integer(handle, C255_base_pt_order);

        ec_pub_key_x25519[i] = sync_mont_ecdh(
            handle, X25519_curve, &C255_base_pt->x, ec_priv_key_x25519_0[i]);
        remote_ec_priv_key_x25519[i] =
            rand_non_zero_integer(handle, C255_base_pt_order);
        remote_ec_pub_key_x25519[i] =
            sync_mont_ecdh(handle, X25519_curve, &C255_base_pt->x,
                           remote_ec_priv_key_x25519[i]);

        if (!ec_priv_key_x25519_0[i]->buf_ptr ||
            !ec_pub_key_x25519[i]->buf_ptr) {
            fprintf(stderr, "EC Key Pair Generation Failed!\n");
            return -1;
        }

        if (!remote_ec_priv_key_x25519[i]->buf_ptr ||
            !remote_ec_pub_key_x25519[i]->buf_ptr) {
            fprintf(stderr, "Remote EC Key Pair Generation Failed!\n");
            return -1;
        }
    }

    fprintf(stderr, "X25519 Key Pair Generated.\n");

    /* generate answers */
    for (int i = 0; i < MAX_OUTSTANDING_CMD_NUM; i++) {
        remote_shared_secret_po[i] =
            sync_mont_ecdh(handle, X25519_curve, ec_pub_key_x25519[i],
                           remote_ec_priv_key_x25519[i]);
    }

    fprintf(stderr, "Answers Generated.\n");

    fprintf(stderr, "Now test will be started...\n");

    return SUCCESS;
}

int
Get_ECDSA_key_pair(pka_handle_t handle, int big_endian)
{
    pka_operand_t *c, *n_minus_1, *temp;
    uint32_t n, hash_len;

    /* make room for ec_priv_key and ec_pub_key */
    ec_priv_key = calloc(MAX_OUTSTANDING_CMD_NUM, sizeof(pka_operand_t *));
    ec_pub_key_ep = calloc(MAX_OUTSTANDING_CMD_NUM, sizeof(ecc_point_t *));
    answer = calloc(MAX_OUTSTANDING_CMD_NUM, sizeof(dsa_signature_t *));
    k = calloc(MAX_OUTSTANDING_CMD_NUM, sizeof(pka_operand_t *));
    hash = calloc(MAX_OUTSTANDING_CMD_NUM, sizeof(pka_operand_t *));

    /* allocate ecc point and curve */
    P256_curve = make_ecc_curve(P256_p_buf, sizeof(P256_p_buf), P256_a_buf,
                                sizeof(P256_a_buf), P256_b_buf,
                                sizeof(P256_b_buf), big_endian);

#if DBG_MODE
    print_operand("curve.p = ", &P256_curve->p, "\n");
    print_operand("curve.a = ", &P256_curve->a, "\n");
    print_operand("curve.b = ", &P256_curve->b, "\n");
    fprintf(stderr, "curve.p's endian: %s\n",
            P256_curve->p.big_endian ? "big-endian" : "little-endian");
#endif /* DBG_MODE */

    if (P256_curve == NULL)
        return -1;

    if (!P256_curve->p.buf_ptr || !P256_curve->a.buf_ptr ||
        !P256_curve->b.buf_ptr)
        return -1;

    P256_base_pt = make_ecc_point(P256_curve, P256_xg_buf, sizeof(P256_xg_buf),
                                  P256_yg_buf, sizeof(P256_yg_buf), big_endian);

#if DBG_MODE
    print_operand("base_pt.x = ", &P256_base_pt->x, "\n");
    print_operand("base_pt.y = ", &P256_base_pt->y, "\n");
#endif /* DBG_MODE */

    if (P256_base_pt == NULL)
        return -1;

    P256_base_pt_order =
        make_operand(P256_n_buf, sizeof(P256_n_buf), big_endian);

#if DBG_MODE
    print_operand("base_pt_order = ", P256_base_pt_order, "\n");
#endif /* DBG_MODE */

    if (P256_base_pt_order == NULL)
        return -1;

    fprintf(stderr, "Now ECDSA Keys and Signatures will be generated...\n");

    for (int i = 0; i < MAX_OUTSTANDING_CMD_NUM; i++) {
        /* generate EC key pair */
        ec_priv_key[i] = rand_non_zero_integer(handle, P256_base_pt_order);
        ec_pub_key_ep[i] =
            sync_ecc_multiply(handle, P256_curve, P256_base_pt, ec_priv_key[i]);

        if (!ec_priv_key[i]->buf_ptr || !ec_pub_key_ep[i]->x.buf_ptr ||
            !ec_pub_key_ep[i]->y.buf_ptr) {
            fprintf(stderr, "EC Key Pair Generation Failed!\n");
            return -1;
        }

        /* generate answers */
        n = operand_bit_len(P256_base_pt_order);
        c = rand_operand(handle, n + 64, false);
        n_minus_1 = sync_subtract(handle, P256_base_pt_order, &ONE);
        temp = sync_modulo(handle, c, n_minus_1);
        k[i] = sync_add(handle, temp, &ONE);

        hash_len = n - 16; // *TBD*
        hash[i] = rand_operand(handle, hash_len, false);
        big_endian = pka_get_rings_byte_order(handle);

        answer[i] =
            sw_ecdsa_gen(handle, P256_curve, P256_base_pt, P256_base_pt_order,
                         ec_priv_key[i], hash[i], k[i]);

        if (i % 50 == 0)
            fprintf(stderr, "%d ECDSA Signatures are generated.\n", i);

#if DBG_MODE
        if (answer[i]->r.actual_len == 31)
            fprintf(stderr, "r's len is 31\n");
        if (answer[i]->s.actual_len == 31)
            fprintf(stderr, "s's len is 31\n");
#endif /* DBG_MODE */
    }

    fprintf(stderr, "ECDSA Keys and Signatures are generated.\n");

    fprintf(stderr, "Now test will be started...\n");

    return SUCCESS;
}

#if !TEST_RSA
static EVP_KDF_CTX *
hkdf_ctx_new(const char *algorithm)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, algorithm, NULL);
    if (kdf == NULL)
        return NULL;

    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    return ctx;
}

int
hkdf_extract(unsigned char *out, size_t out_len, const unsigned char *salt,
             size_t salt_len, const unsigned char *key, size_t key_len,
             const EVP_MD *md)
{
    int ret = 0;
    EVP_KDF_CTX *kctx = hkdf_ctx_new(OSSL_KDF_NAME_HKDF);
    if (kctx == NULL)
        return 0;

    OSSL_PARAM params[5], *p = params;

    int mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
    *p++ = OSSL_PARAM_construct_int("mode", &mode);

    *p++ = OSSL_PARAM_construct_utf8_string("digest",
                                            (char *)EVP_MD_get0_name(md), 0);
    *p++ = OSSL_PARAM_construct_octet_string("salt", (void *)salt, salt_len);
    *p++ = OSSL_PARAM_construct_octet_string("key", (void *)key, key_len);

    *p = OSSL_PARAM_construct_end();

    if (EVP_KDF_CTX_set_params(kctx, params) <= 0)
        goto end;

    if (EVP_KDF_derive(kctx, out, out_len, NULL) <= 0)
        goto end;

    ret = 1;

end:
    EVP_KDF_CTX_free(kctx);

    return ret;
}

int
hkdf_expand_label(unsigned char *out, size_t out_len, const unsigned char *key,
                  size_t key_len, const unsigned char *label, size_t label_len,
                  const unsigned char *ctx, size_t ctx_len, const EVP_MD *md)
{
    int ret = 0;
    EVP_KDF_CTX *kctx = hkdf_ctx_new(OSSL_KDF_NAME_TLS1_3_KDF);
    if (kctx == NULL)
        return 0;

    OSSL_PARAM params[7], *p = params;
    char label_prefix[] = "tls13 ";

    int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
    *p++ = OSSL_PARAM_construct_int("mode", &mode);

    *p++ = OSSL_PARAM_construct_utf8_string("digest",
                                            (char *)EVP_MD_get0_name(md), 0);
    *p++ = OSSL_PARAM_construct_octet_string("key", (void *)key, key_len);
    *p++ = OSSL_PARAM_construct_octet_string(
        "prefix", (unsigned char *)label_prefix, sizeof(label_prefix) - 1);
    *p++ = OSSL_PARAM_construct_octet_string("label", (unsigned char *)label,
                                             label_len);
    *p++ = OSSL_PARAM_construct_octet_string("data", (unsigned char *)ctx,
                                             ctx_len);
    *p = OSSL_PARAM_construct_end();

    if (EVP_KDF_CTX_set_params(kctx, params) <= 0)
        goto end;

    if (EVP_KDF_derive(kctx, out, out_len, NULL) <= 0)
        goto end;

    ret = 1;

end:
    EVP_KDF_CTX_free(kctx);

    return ret;
}
#endif /* !TEST_RSA */

pka_results_t *
malloc_results(uint32_t result_cnt, uint32_t buf_len)
{
    pka_results_t *results;
    pka_operand_t *result_ptr;
    uint8_t result_idx;

    PKA_ASSERT(result_cnt <= MAX_RESULT_CNT);

    results = calloc(1, sizeof(pka_results_t));

    for (result_idx = 0; result_idx < result_cnt; result_idx++) {
        result_ptr = &results->results[result_idx];
        result_ptr->buf_ptr = malloc(buf_len);
        memset(result_ptr->buf_ptr, 0, buf_len);
        result_ptr->buf_len = buf_len;
        result_ptr->actual_len = 0;
    }

    results->result_cnt = result_cnt;

    return results;
}

//*TBR*
void
free_results_buf(pka_results_t *results)
{
    pka_operand_t *result_ptr;
    uint8_t result_idx;

    for (result_idx = 0; result_idx < results->result_cnt; result_idx++) {
        result_ptr = &results->results[result_idx];
        free(result_ptr->buf_ptr);
        result_ptr->buf_ptr = NULL;
        result_ptr->buf_len = 0;
        result_ptr->actual_len = 0;
    }
}

//*TBR*
void
free_results(pka_results_t *results)
{
    if (results == NULL) {
        PKA_ERROR(PKA_TESTS, "free_results called with NULL operand\n");
        return;
    }

    free_results_buf(results);
    free(results);
}

void
PrintStatistics(uint64_t interval)
{
    int i;
    static size_t prev_cmd_cnt[MAX_THREAD_NUM];
    static size_t total_cmd = 0;
    static size_t prev_sess_cnt[MAX_THREAD_NUM];
    static size_t total_sess = 0;

    struct timespec now_ts;
    double elapsed_sec;

    size_t total_diff = 0;
    size_t diff;

    if (start_ts.tv_sec == 0 && start_ts.tv_nsec == 0) {
        clock_gettime(CLOCK_MONOTONIC, &start_ts);
    }

    clock_gettime(CLOCK_MONOTONIC, &now_ts);

    elapsed_sec = (now_ts.tv_nsec - start_ts.tv_nsec) / 1e9 +
                  (now_ts.tv_sec - start_ts.tv_sec);
    printf("\n----------------------------------\n");

    if (!is_tls13_benchmark) {
        for (i = 0; i < thread_num; i++) {
            /* printf("[THREAD %d]: %lu\n", i + cpu_set_base, cmd_cnt[i] *
             * 1000000 / interval); */
            diff = cmd_cnt[i] - prev_cmd_cnt[i];
            printf("[THREAD %d]: %lu\n", i, diff * 1000000000 / interval);
            total_diff += diff;
            prev_cmd_cnt[i] = cmd_cnt[i];
        }

        total_cmd += total_diff;

        printf("[TOTAL]: %lu\n", total_diff * 1000000000 / interval);

        if (elapsed_sec > 0) {
            double avg_tps = total_cmd / elapsed_sec;

            printf(
                "[AVG TOTAL]:  %.2f ops/sec (%.2f Kops/sec, %.2f Mops/sec)\n",
                avg_tps, avg_tps / 1e3, avg_tps / 1e6);
        }
    } else {
        for (i = 0; i < MAX_THREAD_NUM; i++) {
            tls13_sess_cnt[i] =
                tls13_op_cnt[i].ecdsa_done < (tls13_op_cnt[i].ecdh_done / 2)
                    ? tls13_op_cnt[i].ecdsa_done
                    : (tls13_op_cnt[i].ecdh_done / 2);
        }

        for (i = 0; i < MAX_THREAD_NUM; i++) {
            if (tls13_sess_cnt[i] == 0)
                continue;
            /* printf("[THREAD %d]: %lu\n", i + cpu_set_base, cmd_cnt[i] *
             * 1000000 / interval); */
            diff = tls13_sess_cnt[i] - prev_sess_cnt[i];
            printf("[THREAD %d]: %lu\n", i, diff * 1000000000 / interval);
            total_diff += diff;
            prev_sess_cnt[i] = tls13_sess_cnt[i];
        }

        total_sess += total_diff;

        printf("[TOTAL]: %lu\n", total_diff * 1000000000 / interval);

        if (elapsed_sec > 0) {
            double avg_tps = total_sess / elapsed_sec;

            printf("[AVG TOTAL]:  %.2f sess/sec (%.2f Ksess/sec, %.2f "
                   "Msess/sec)\n",
                   avg_tps, avg_tps / 1e3, avg_tps / 1e6);
        }
    }
}
