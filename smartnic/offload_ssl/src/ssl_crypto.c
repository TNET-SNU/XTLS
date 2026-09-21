#include "ssl_crypto.h"

#include <assert.h>
#include <openssl/aes.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "ssloff.h"

#define MAX_PHASH_INPUT (MAX_HASH_SIZE * 3)
#define MAX_CPUS        16

typedef struct ecc_info ecc_info_t;
typedef struct ssl_session ssl_session_t;

extern pka_handle_t pka_handle;
extern EVP_MD *sha1;
extern EVP_MD *sha256;
extern EVP_MD *sha384;
extern ecc_info_t *ecc_info[MAX_CPUS];
/*--------------------------- FUNCTION PROTOTYPE ----------------------------*/
static int
encrypt_aes_gcm(EVP_CIPHER_CTX *ctx, unsigned char *plaintext,
                int plaintext_len, unsigned char *key, unsigned char *iv,
                unsigned short iv_len, unsigned char *aad,
                unsigned short aad_len, unsigned char *tag,
                unsigned char *ciphertext);

static int
decrypt_aes_gcm(EVP_CIPHER_CTX *ctx, unsigned char *ciphertext,
                int ciphertext_len, unsigned char *key, unsigned char *iv,
                unsigned short iv_len, unsigned char *aad,
                unsigned short aad_len, unsigned char *tag,
                unsigned char *plaintext);
/*----------------------------- FUNCTION PTR TAB ----------------------------*/
typedef int (*aes_gcm_func_t)(EVP_CIPHER_CTX *ctx, unsigned char *plaintext,
                              int plaintext_len, unsigned char *key,
                              unsigned char *iv, unsigned short iv_len,
                              unsigned char *aad, unsigned short aad_len,
                              unsigned char *tag, unsigned char *ciphertext);

static const aes_gcm_func_t aes_gcm_table[2] = {[ENCRYPT] = encrypt_aes_gcm,
                                                [DECRYPT] = decrypt_aes_gcm};
/*---------------------------------------------------------------------------*/
static int
P_HASH(const EVP_MD *hash, const int secret_len, const uint8_t *secret,
       const int seed_len, const uint8_t *seed, const int out_len, uint8_t *out)
{
    int out_len_actual = 0;
    uint8_t buf[MAX_PHASH_INPUT];
    uint8_t *hmac_out = buf;
    int hmac_out_len = 0;

    HMAC(hash, secret, secret_len, seed, seed_len, hmac_out,
         (unsigned int *)&hmac_out_len);
    assert(MAX_HASH_SIZE > hmac_out_len && hmac_out_len > 0);

    memcpy(hmac_out + hmac_out_len, seed, seed_len);

    HMAC(hash, secret, secret_len, hmac_out, hmac_out_len + seed_len,
         out + out_len_actual, (unsigned int *)&hmac_out_len);
    assert(MAX_HASH_SIZE > hmac_out_len && hmac_out_len > 0);

    out_len_actual += hmac_out_len;

    while (out_len_actual < out_len) {
        HMAC(hash, secret, secret_len, hmac_out, hmac_out_len, hmac_out,
             (unsigned int *)&hmac_out_len);
        assert(MAX_HASH_SIZE > hmac_out_len && hmac_out_len > 0);

        HMAC(hash, secret, secret_len, hmac_out, hmac_out_len + seed_len,
             out + out_len_actual, (unsigned int *)&hmac_out_len);
        assert(MAX_HASH_SIZE > hmac_out_len && hmac_out_len > 0);
        out_len_actual += hmac_out_len;
    }

    return out_len_actual;
}
#undef MAX_PHASH_INPUT

#define MAX_PRF_INPUT 16384
int
PRF(const EVP_MD *(*hash_func)(void), const int secret_len,
    const uint8_t *secret, const int label_len, const uint8_t *label,
    const int seed_len, const uint8_t *seed, const int out_len, uint8_t *out)
{
    uint8_t buf[MAX_PRF_INPUT];
    uint8_t *p_sha256 = buf;
    int real_seed_len = label_len + seed_len;
    uint8_t *real_seed = p_sha256 + out_len + 20;

    assert(out_len + 20 + real_seed_len < MAX_PRF_INPUT);

    memcpy(real_seed, label, label_len);
    memcpy(real_seed + label_len, seed, seed_len);

    P_HASH(hash_func(), secret_len, secret, real_seed_len, real_seed, out_len,
           p_sha256);

    memcpy(out, p_sha256, out_len);

    return out_len;
}
#undef MAX_PRF_INPUT

static void
handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

static int
encrypt_aes_gcm(EVP_CIPHER_CTX *ctx, unsigned char *plaintext,
                int plaintext_len, unsigned char *key, unsigned char *iv,
                unsigned short iv_len, unsigned char *aad,
                unsigned short aad_len, unsigned char *tag,
                unsigned char *ciphertext)
{
#if VERBOSE_AES
    fprintf(stderr, "\nTLS_AES_GCM %d: ENCRYPT\n", op->opcode.s.bit);
    fprintf(stderr, "Encrypted len: %d\n", ret);
#endif /* VERBOSE_AES */

    int len;
    int ciphertext_len;

#if CRYPTO_GETTIME_FLAG
    struct timespec tv_start, tv_end;
    int64_t elapsed_time;
    clock_gettime(CLOCK_MONOTONIC, &tv_start);
#endif /* CRYPTO_GETTIME_FLAG */

    /* Initialise the encryption operation. */
    /* #if MODIFY_FLAG */
    /*     if (!(ctx = EVP_CIPHER_CTX_new())) */
    /*         handleErrors(); */
    /* #endif */

    if (unlikely(
            EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) != 1)
        handleErrors();

    if (unlikely(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len,
                                     NULL) != 1))
        handleErrors();

    if (unlikely(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1))
        handleErrors();

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if (unlikely(EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (unlikely(EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext,
                                   plaintext_len) != 1))
        handleErrors();

    ciphertext_len = len;

#if CRYPTO_GETTIME_FLAG
    clock_gettime(CLOCK_MONOTONIC, &tv_end);
    elapsed_time = (tv_end.tv_nsec - tv_start.tv_nsec) +
                   (tv_end.tv_sec - tv_start.tv_sec) * 100000000;
    if (elapsed_time > 1000)
        fprintf(stderr,
                "[encrypt aes gcm] EVP_EncryptUpdate (plaintext) takes %ld "
                "nano sec\n",
                (tv_end.tv_nsec - tv_start.tv_nsec) +
                    (tv_end.tv_sec - tv_start.tv_sec) * 100000000);
#endif /* CRYPTO_GETTIME_FLAG */

    if (unlikely(EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1))
        handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if (unlikely(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1))
        handleErrors();

#if VERBOSE_GCM
    int z;
    fprintf(stderr, "\n\n[encrypt aes gcm] iv_len: 0x%x, iv (nonce): \n",
            iv_len);
    for (z = 0; z < iv_len; z++)
        fprintf(stderr, "%02X%c", iv[z], ((z + 1) % 16) ? ' ' : '\n');
    fprintf(stderr, "\nkey: \n");
    for (z = 0; z < 32; z++)
        fprintf(stderr, "%02X%c", key[z], ((z + 1) % 16) ? ' ' : '\n');
    fprintf(stderr, "\naad_len: 0x%x, aad: \n", aad_len);
    for (z = 0; z < aad_len; z++)
        fprintf(stderr, "%02X%c", aad[z], ((z + 1) % 16) ? ' ' : '\n');
    fprintf(stderr, "\n[encrypt aes gcm] plaintext_len: 0x%x, plaintext: \n",
            plaintext_len);
    for (z = 0; z < plaintext_len; z++)
        fprintf(stderr, "%02X%c", plaintext[z], ((z + 1) % 16) ? ' ' : '\n');
    fprintf(stderr, "\nciphertext_len: 0x%x, ciphertext: \n", ciphertext_len);
    for (z = 0; z < plaintext_len; z++)
        fprintf(stderr, "%02X%c", ciphertext[z], ((z + 1) % 16) ? ' ' : '\n');
    fprintf(stderr, "\ntag: \n");
    for (z = 0; z < 16; z++)
        fprintf(stderr, "%02X%c", tag[z], ((z + 1) % 16) ? ' ' : '\n');
    fprintf(stderr, "\n");
#endif /* VERBOSE_GCM */

    /* #if MODIFY_FLAG */
    /*     EVP_CIPHER_CTX_free(ctx); */
    /* #endif */

    return ciphertext_len;
}

static int
decrypt_aes_gcm(EVP_CIPHER_CTX *ctx, unsigned char *ciphertext,
                int ciphertext_len, unsigned char *key, unsigned char *iv,
                unsigned short iv_len, unsigned char *aad,
                unsigned short aad_len, unsigned char *tag,
                unsigned char *plaintext)
{
#if VERBOSE_AES
    fprintf(stderr, "\nTLS_AES_GCM %d: DECRYPT\n", op->opcode.s.bit);
    fprintf(stderr, "decrypted len: %d\n", ret);
#endif /* VERBOSE_AES */

    /* EVP_CIPHER_CTX *ctx; */
    int len;
    int plaintext_len;
    int ret;

#if VERBOSE_GCM
    int z;
    fprintf(stderr, "\n[decrypt aes gcm] iv_len: 0x%x, iv (nonce): \n", iv_len);
    for (z = 0; z < iv_len; z++)
        fprintf(stderr, "%02X%c", iv[z], ((z + 1) % 16) ? ' ' : '\n');
    fprintf(stderr, "\nkey: \n");
    for (z = 0; z < 32; z++)
        fprintf(stderr, "%02X%c", key[z], ((z + 1) % 16) ? ' ' : '\n');
    fprintf(stderr, "\naad_len: 0x%x, aad: \n", aad_len);
    for (z = 0; z < aad_len; z++)
        fprintf(stderr, "%02X%c", aad[z], ((z + 1) % 16) ? ' ' : '\n');
    fprintf(stderr, "\nciphertext_len: 0x%x, ciphertext: \n", ciphertext_len);
    for (z = 0; z < ciphertext_len; z++)
        fprintf(stderr, "%02X%c", ciphertext[z], ((z + 1) % 16) ? ' ' : '\n');
    fprintf(stderr, "\ntag: \n");
    for (z = 0; z < GCM_TAG_SIZE; z++)
        fprintf(stderr, "%02X%c", tag[z], ((z + 1) % 16) ? ' ' : '\n');
    fprintf(stderr, "\n");
#endif /* VERBOSE_GCM */

    /* Initialise the decryption operation. */
    /* #if MODIFY_FLAG */
    /*     if (!(ctx = EVP_CIPHER_CTX_new())) */
    /*         handleErrors(); */
    /* #endif */

    if (unlikely(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)))
        handleErrors();

    if (unlikely(
            !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)))
        handleErrors();

    if (unlikely(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)))
        handleErrors();

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    len = 0;

    if (unlikely(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (unlikely(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext,
                                    ciphertext_len)))
        handleErrors();
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (unlikely(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)))
        handleErrors();

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

#if VERBOSE_GCM
    fprintf(stderr, "plaintext_len: 0x%x, plaintext: \n", plaintext_len);
    for (z = 0; z < plaintext_len; z++)
        fprintf(stderr, "%02X%c", plaintext[z], ((z + 1) % 16) ? ' ' : '\n');
    fprintf(stderr, "\nanother nplaintext_len: 0x%x, plaintext: \n",
            plaintext_len);
    for (z = 0; z < plaintext_len; z++)
        fprintf(stderr, "%02X%c", plaintext[z + len],
                ((z + 1) % 16) ? ' ' : '\n');
    fprintf(stderr, "\n");
#endif /* VERBOSE_GCM */

    /* #if MODIFY_FLAG */
    /*     EVP_CIPHER_CTX_free(ctx); */
    /* #endif */

    if (ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}

int
execute_ecdhe_key_generation(ssl_crypto_op_t *op)
{
    if (unlikely(!op))
        return -1;

    ssl_session_t *sess = (ssl_session_t *)(op->sess);

#if DEBUG_TLS_1_3
    fprintf(stderr, "\n[generate ecdhe key pair] Generating ECDHE key pair\n");
#endif /* DEBUG_TLS_1_3 */

    rand_non_zero_integer_w_pka_hwrng_and_clamping(
        pka_handle, sess->ecdhe_priv_key, ecc_info[0]->C255_base_pt_order);

    if (unlikely(pka_mont_ecdh_mult(pka_handle, (void *)op,
                                    ecc_info[0]->X25519_curve,
                                    &ecc_info[0]->C255_base_pt->x,
                                    sess->ecdhe_priv_key) < 0)) {
        fprintf(stderr, "\nPKA ECDHE KEY GENERATION ERROR\n");
        assert(0);
    }

    return 0;
}

int
execute_ecdhe_shared_secret_calculation(ssl_crypto_op_t *op)
{
    if (unlikely(!op))
        return -1;

    if (unlikely(pka_mont_ecdh_mult(pka_handle, (void *)op,
                                    ecc_info[0]->X25519_curve, op->pka_in,
                                    op->pka_in_1) < 0)) {
        fprintf(stderr, "\nPKA ECDHE SHARED SECRET CALCULATION ERROR\n");
        assert(0);
    }

#if DEBUG_TLS_1_3
    fprintf(stderr, "[execute_ecdhe_shared_secret_calculation] "
                    "Submit ECDHE shared secret calculation request\n");
#endif /* DEBUG_TLS_1_3 */

    return 0;
}

int
execute_ecdsa_signature(ssl_crypto_op_t *op)
{
    if (unlikely(!op))
        return -1;

    if (unlikely(pka_ecdsa_signature_generate(
                     pka_handle, (void *)op, ecc_info[0]->P256_curve,
                     ecc_info[0]->P256_base_pt, ecc_info[0]->P256_base_pt_order,
                     op->pka_in, op->pka_in_1, op->pka_in_2) < 0)) {
        fprintf(stderr, "\nPKA ECDSA SIGNATURE ERROR\n");
        assert(0);
    }

#if DEBUG_TLS_1_3
    fprintf(stderr,
            "[execute_ecdsa_signature] Submit ECDSA signature request\n");
#endif /* DEBUG_TLS_1_3 */

    return 0;
}

int
execute_aes_crypto(EVP_CIPHER_CTX *ctx, ssl_crypto_op_t *op)
{
    int ret;

    if (unlikely(!op))
        return -1;

    switch (op->opcode.s.function) {
    case TLS_AES_GCM: {
        unsigned char *tag_ptr = (op->opcode.s.op == ENCRYPT)
                                     ? (op->out + op->in_len)
                                     : (op->in + op->in_len);

        ret = aes_gcm_table[op->opcode.s.op](ctx, op->in, op->in_len, op->key,
                                             op->iv, op->iv_len, op->aad,
                                             op->aad_len, tag_ptr, op->out);
        break;
    }

    default:
        assert(0);
    }

    if (unlikely(ret <= 0)) {
        fprintf(stderr, "AES %s %s error\n",
                (op->opcode.s.op == ENCRYPT) ? "encryption" : "decryption",
                (op->opcode.s.function == TLS_AES_CBC) ? "CBC" : "GCM");
        fprintf(stderr, "handshake msgs len: %d\n",
                ((record_t *)(op->data))->sess->handshake_msgs_len);
        return -1;
    }

    return 0;
}

int
execute_mac_crypto(ssl_crypto_op_t *op)
{
    assert(op != NULL);
    assert(op->opcode.s.function == TLS_HMAC_SHA1);

    unsigned len;

    HMAC(sha1, op->key, op->key_len, op->in, op->in_len, op->out, &len);

    assert(len == op->out_len);

    return 0;
}

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
hkdf_extract(HMAC_CTX *hctx, unsigned char *out, size_t out_len,
             const unsigned char *salt, size_t salt_len,
             const unsigned char *key, size_t key_len, const EVP_MD *md)
{
    unsigned int len = 0;

    if (HMAC_Init_ex(hctx, salt, salt_len, md, NULL) <= 0)
        return 0;

    if (HMAC_Update(hctx, key, key_len) <= 0)
        return 0;

    if (HMAC_Final(hctx, out, &len) <= 0)
        return 0;

    HMAC_CTX_reset(hctx);

    return 1;
}

static int
hkdf_expand_internal(HMAC_CTX *hctx, unsigned char *out, size_t out_len,
                     const unsigned char *prk, size_t prk_len,
                     const unsigned char *info, size_t info_len,
                     const EVP_MD *md)
{
    size_t hash_len = EVP_MD_get_size(md);
    size_t n = (out_len + hash_len - 1) / hash_len;
    unsigned char T[EVP_MAX_MD_SIZE];
    size_t T_len = 0;
    size_t done = 0;

    if (n > 255)
        return 0;

    for (uint8_t i = 1; i <= n; i++) {
        if (i == 1) {
            if (HMAC_Init_ex(hctx, prk, prk_len, md, NULL) <= 0)
                return 0;
        } else {
            if (HMAC_Init_ex(hctx, NULL, 0, NULL, NULL) <= 0)
                return 0;
        }
        if (T_len > 0)
            if (HMAC_Update(hctx, T, T_len) <= 0)
                return 0;
        if (HMAC_Update(hctx, info, info_len) <= 0)
            return 0;
        if (HMAC_Update(hctx, &i, 1) <= 0)
            return 0;
        unsigned int outlen = 0;
        if (HMAC_Final(hctx, T, &outlen) <= 0)
            return 0;
        T_len = outlen;

        size_t copy = (done + T_len > out_len) ? (out_len - done) : T_len;
        memcpy(out + done, T, copy);
        done += copy;
    }

    return 1;
}

int
hkdf_expand_label(HMAC_CTX *hctx, unsigned char *out, size_t out_len,
                  const unsigned char *key, size_t key_len,
                  const unsigned char *label, size_t label_len,
                  const unsigned char *ctx, size_t ctx_len, const EVP_MD *md)
{
    // HkdfLabel 구성: uint16 length || "tls13 " + label || ctx
    unsigned char info[2 + 1 + 6 + 255 + 1 + 255];
    size_t pos = 0;
    info[pos++] = (out_len >> 8) & 0xff;
    info[pos++] = out_len & 0xff;
    info[pos++] = 6 + label_len; // total label length
    memcpy(info + pos, "tls13 ", 6);
    pos += 6;
    memcpy(info + pos, label, label_len);
    pos += label_len;
    info[pos++] = ctx_len;

    if (ctx_len) {
        memcpy(info + pos, ctx, ctx_len);
        pos += ctx_len;
    }

    return hkdf_expand_internal(hctx, out, out_len, key, key_len, info, pos,
                                md);
}
