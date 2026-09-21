#include <assert.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "ssl_crypto.h"

#define MAX_PHASH_INPUT (MAX_HASH_SIZE * 3)

/*--------------------------- FUNCTION PROTOTYPE ----------------------------*/
static int
encrypt_aes_cbc(EVP_CIPHER_CTX *ctx, 
                unsigned char *ciphertext, int ciphertext_len, 
                unsigned char *key,
                unsigned char *iv, 
                unsigned char *plaintext);

static int
decrypt_aes_cbc(EVP_CIPHER_CTX *ctx, 
                unsigned char *ciphertext, int ciphertext_len, 
                unsigned char *key,
                unsigned char *iv, 
                unsigned char *plaintext);

static int
encrypt_aes_gcm(EVP_CIPHER_CTX *ctx, 
                unsigned char *plaintext, int plaintext_len, 
                unsigned char *key,
                unsigned char *iv, unsigned short iv_len, 
                unsigned char *aad, unsigned short aad_len,
                unsigned char *tag, 
                unsigned char *ciphertext);

static int
decrypt_aes_gcm(EVP_CIPHER_CTX *ctx, 
                unsigned char *ciphertext, int ciphertext_len, 
                unsigned char *key,
                unsigned char *iv, unsigned short iv_len, 
                unsigned char *aad, unsigned short aad_len,
                unsigned char *tag, 
                unsigned char *plaintext);
/*----------------------------- FUNCTION PTR TAB ----------------------------*/
typedef int 
(*aes_cbc_func_t)(EVP_CIPHER_CTX *ctx, 
                  unsigned char *ciphertext, int ciphertext_len, 
                  unsigned char *key,
                  unsigned char *iv,
                  unsigned char *plaintext);

typedef int 
(*aes_gcm_func_t)(EVP_CIPHER_CTX *ctx, 
                  unsigned char *plaintext, int plaintext_len, 
                  unsigned char *key,
                  unsigned char *iv, unsigned short iv_len, 
                  unsigned char *aad, unsigned short aad_len,
                  unsigned char *tag, 
                  unsigned char *ciphertext);

static const 
aes_cbc_func_t aes_cbc_table[2] = {
    [ENCRYPT] = encrypt_aes_cbc,
    [DECRYPT] = decrypt_aes_cbc
};

static const 
aes_gcm_func_t aes_gcm_table[2] = {
    [ENCRYPT] = encrypt_aes_gcm,
    [DECRYPT] = decrypt_aes_gcm
};
/*---------------------------------------------------------------------------*/

static int
P_HASH(const EVP_MD* hash, const int secret_len, const uint8_t *secret,
       const int seed_len, const uint8_t *seed,
       const int out_len,  uint8_t *out)
{
    int out_len_actual = 0;
    uint8_t buf[MAX_PHASH_INPUT];
    uint8_t *hmac_out = buf;
    int hmac_out_len = 0;

    HMAC(hash, secret, secret_len,
         seed, seed_len,
         hmac_out, (unsigned int *)&hmac_out_len);
    assert(MAX_HASH_SIZE > hmac_out_len && hmac_out_len > 0);

    memcpy(hmac_out + hmac_out_len, seed, seed_len);

    HMAC(hash, secret, secret_len,
         hmac_out, hmac_out_len + seed_len,
         out + out_len_actual, (unsigned int *)&hmac_out_len);
    assert(MAX_HASH_SIZE > hmac_out_len && hmac_out_len > 0);

    out_len_actual += hmac_out_len;

    while (out_len_actual < out_len) {
        HMAC(hash, secret, secret_len,
             hmac_out, hmac_out_len,
             hmac_out, (unsigned int *)&hmac_out_len);
        assert(MAX_HASH_SIZE > hmac_out_len && hmac_out_len > 0);

        HMAC(hash, secret, secret_len,
             hmac_out, hmac_out_len + seed_len,
             out + out_len_actual, (unsigned int *)&hmac_out_len);
        assert(MAX_HASH_SIZE > hmac_out_len && hmac_out_len > 0);
        out_len_actual += hmac_out_len;
    }

    return out_len_actual;
}
#undef MAX_PHASH_INPUT

#define MAX_PRF_INPUT 16384
int
PRF(const EVP_MD* (*hash_func)(void), const int secret_len, const uint8_t *secret,
    const int label_len,  const uint8_t *label,
    const int seed_len,   const uint8_t *seed,
    const int out_len,    uint8_t *out)
{
    uint8_t buf[MAX_PRF_INPUT];
    uint8_t *p_sha256 = buf;
    int real_seed_len = label_len + seed_len;
    uint8_t *real_seed = p_sha256 + out_len + 20;

    assert(out_len + 20 + real_seed_len < MAX_PRF_INPUT);

    memcpy(real_seed, label, label_len);
    memcpy(real_seed + label_len, seed, seed_len);

    P_HASH(hash_func(), secret_len, secret,
           real_seed_len, real_seed,
           out_len, p_sha256);

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

static int /* TODO: plain text ,-> cipher text */
encrypt_aes_cbc(EVP_CIPHER_CTX *ctx, 
                unsigned char *ciphertext, int ciphertext_len, 
                unsigned char *key,
                unsigned char *iv, 
                unsigned char *plaintext)
{
#if VERBOSE_AES
			fprintf(stderr, "\nTLS_AES_CBC %d: ENCRYPT\n",
					op->opcode.s.bit);
			fprintf(stderr, "Encrypted len: %d\n", ret);
#endif /* VERBOSE_AES */

    /* EVP_CIPHER_CTX *ctx; */

    int len;

    /* /\* Create and initialise the context *\/ */
    /* if (unlikely(!(ctx = EVP_CIPHER_CTX_new()))) */
    /*     handleErrors(); */

    /* Initialise the decryption operation */
    if (unlikely(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) != 1)
        handleErrors();

    len = EVP_Cipher(ctx, plaintext, ciphertext, ciphertext_len);

    /* /\* Clean up *\/ */
    /* EVP_CIPHER_CTX_free(ctx); */

    return len;
}

static int
decrypt_aes_cbc(EVP_CIPHER_CTX *ctx, 
                unsigned char *ciphertext, int ciphertext_len, 
                unsigned char *key,
                unsigned char *iv, 
                unsigned char *plaintext)
{
#if VERBOSE_AES
			fprintf(stderr, "\nTLS_AES_CBC %d: DECRYPT\n",
					op->opcode.s.bit);
			fprintf(stderr, "decrypted len: %d\n", ret);
#endif /* VERBOSE_AES */

    /* EVP_CIPHER_CTX *ctx; */

    int len;

    /* /\* Create and initialise the context *\/ */
    /* if (unlikely(!(ctx = EVP_CIPHER_CTX_new()))) */
    /*     handleErrors(); */

    /* Initialise the decryption operation */
    if (unlikely(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) != 1)
        handleErrors();

    len = EVP_Cipher(ctx, plaintext, ciphertext, ciphertext_len);

    /* /\* Clean up *\/ */
    /* EVP_CIPHER_CTX_free(ctx); */

    return len;
}

static int
encrypt_aes_gcm(EVP_CIPHER_CTX *ctx, 
                unsigned char *plaintext, int plaintext_len, 
                unsigned char *key,
                unsigned char *iv, unsigned short iv_len, 
                unsigned char *aad, unsigned short aad_len,
                unsigned char *tag, unsigned char *ciphertext)
{
#if VERBOSE_AES
            fprintf(stderr, "\nTLS_AES_GCM %d: ENCRYPT\n",
                    op->opcode.s.bit);
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

    if (unlikely(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) != 1)
        handleErrors();

    if (unlikely(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) != 1))
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
    if (unlikely(EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1))
        handleErrors();

    ciphertext_len = len;

#if CRYPTO_GETTIME_FLAG
    clock_gettime(CLOCK_MONOTONIC, &tv_end);
    elapsed_time = (tv_end.tv_nsec - tv_start.tv_nsec) + (tv_end.tv_sec - tv_start.tv_sec)*100000000;
    if (elapsed_time > 1000)
        fprintf(stderr, "[encrypt aes gcm] EVP_EncryptUpdate (plaintext) takes %ld nano sec\n",
				(tv_end.tv_nsec - tv_start.tv_nsec) + (tv_end.tv_sec - tv_start.tv_sec)*100000000);
#endif /* CRYPTO_GETTIME_FLAG */

    if (unlikely(EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1))
        handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if (unlikely(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1))
        handleErrors();

#if VERBOSE_GCM
    int z;
    fprintf(stderr, "\n\n[encrypt aes gcm] iv_len: 0x%x, iv (nonce): \n", iv_len);
    for (z = 0; z < iv_len; z++)
        fprintf(stderr, "%02X%c", iv[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\nkey: \n");
    for (z = 0; z < 32; z++)
        fprintf(stderr, "%02X%c", key[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\naad_len: 0x%x, aad: \n", aad_len);
    for (z = 0; z < aad_len; z++)
        fprintf(stderr, "%02X%c", aad[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\n[encrypt aes gcm] plaintext_len: 0x%x, plaintext: \n", plaintext_len);
    for (z = 0; z < plaintext_len; z++)
        fprintf(stderr, "%02X%c", plaintext[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\nciphertext_len: 0x%x, ciphertext: \n", ciphertext_len);
    for (z = 0; z < plaintext_len; z++)
        fprintf(stderr, "%02X%c", ciphertext[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\ntag: \n");
    for (z = 0; z < 16; z++)
        fprintf(stderr, "%02X%c", tag[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\n");
#endif /* VERBOSE_GCM */

/* #if MODIFY_FLAG */
/*     EVP_CIPHER_CTX_free(ctx); */
/* #endif */

    return ciphertext_len;
}

static int
decrypt_aes_gcm(EVP_CIPHER_CTX *ctx, 
                unsigned char *ciphertext, int ciphertext_len, 
                unsigned char *key,
                unsigned char *iv, unsigned short iv_len, 
                unsigned char *aad, unsigned short aad_len,
                unsigned char *tag, unsigned char *plaintext)
{
#if VERBOSE_AES
            fprintf(stderr, "\nTLS_AES_GCM %d: DECRYPT\n",
                    op->opcode.s.bit);
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
        fprintf(stderr, "%02X%c", iv[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\nkey: \n");
    for (z = 0; z < 32; z++)
        fprintf(stderr, "%02X%c", key[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\naad_len: 0x%x, aad: \n", aad_len);
    for (z = 0; z < aad_len; z++)
        fprintf(stderr, "%02X%c", aad[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\nciphertext_len: 0x%x, ciphertext: \n", ciphertext_len);
    for (z = 0; z < ciphertext_len; z++)
        fprintf(stderr, "%02X%c", ciphertext[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\ntag: \n");
    for (z = 0; z < GCM_TAG_SIZE; z++)
        fprintf(stderr, "%02X%c", tag[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\n");
#endif /* VERBOSE_GCM */

    /* Initialise the decryption operation. */
/* #if MODIFY_FLAG */
/*     if (!(ctx = EVP_CIPHER_CTX_new())) */
/*         handleErrors(); */
/* #endif */

    if (unlikely(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)))
        handleErrors();

    if (unlikely(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)))
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
    if (unlikely(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)))
        handleErrors();
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (unlikely(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)))
        handleErrors();

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

#if VERBOSE_GCM
    fprintf(stderr, "plaintext_len: 0x%x, plaintext: \n", plaintext_len);
    for (z = 0; z < plaintext_len; z++)
        fprintf(stderr, "%02X%c", plaintext[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\nanother nplaintext_len: 0x%x, plaintext: \n", plaintext_len);
    for (z = 0; z < plaintext_len; z++)
        fprintf(stderr, "%02X%c", plaintext[z+len],
                ((z + 1) % 16)? ' ' : '\n');
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
execute_rsa_crypto(ssl_crypto_op_t* op) 
{
	if (unlikely(!op))
		return -1;

    assert(op->opcode.s.function == TLS_RSA);

    if (likely(op->opcode.s.op == PRIVATE_DECRYPT)) {
#if VERBOSE_KEY
		fprintf(stderr, "\nTLS_RSA: PRIVATE_DECRYPT\n");
#endif /* VERBOSE_KEY */

		pka_t* pka = (pka_t *)op->key;
		ssl_session_t *sess =
			(ssl_session_t *)((record_t *)op->data)->sess;
		assert(pka != NULL);

        if (unlikely(pka_modular_exp_crt(pka_handle,
										 (void *)op, op->pka_in,
										 pka->p,
										 pka->q,
										 pka->d_p,
										 pka->d_q,
										 pka->qinv) < 0)) {
			fprintf(stderr, "\nPKA RSA DECRYPTION ERROR\n");
			assert(0);
		}

#if VERBOSE_SSL
		fprintf(stderr, "Crypto Request at handle %d\n", sess->coreid);
#endif /* VERBOSE_SSL */

    } else
		assert(0);

    return 0;
}

int
execute_aes_crypto(EVP_CIPHER_CTX *ctx, ssl_crypto_op_t* op) 
{
    int ret;

	if (unlikely(!op))
		return -1;

    switch (op->opcode.s.function) {
        case TLS_AES_CBC: {
            ret = aes_cbc_table[op->opcode.s.op](ctx, 
                                                 op->in,
                                                 op->in_len,
                                                 op->key,
                                                 op->iv,
                                                 op->out);
            break;
        }
        case TLS_AES_GCM: {
            unsigned char *tag_ptr 
                = (op->opcode.s.op == ENCRYPT) ? /* ? */
                  (op->out + op->in_len) : (op->in + op->in_len);

            ret = aes_gcm_table[op->opcode.s.op](ctx,
                                                 op->in,
                                                 op->in_len,
                                                 op->key,
                                                 op->iv,
                                                 op->iv_len,
                                                 op->aad,
                                                 op->aad_len,
                                                 tag_ptr,
                                                 op->out);
            break;
        }

        default:
            assert(0);
    }

    if (unlikely(ret <= 0)) {
        fprintf(stderr, "AES %s %s error\n",
                (op->opcode.s.op == ENCRYPT) ? "encryption" : "decryption",
                (op->opcode.s.function == TLS_AES_CBC) ? "CBC" : "GCM");
        fprintf(stderr, "handshake msgs len: %d\n", ((record_t *)(op->data))->sess->handshake_msgs_len);
        fprintf(stderr, "client ip: 0x%08x, client port: %u, handshake state: %u\n",
                htonl(((record_t *)(op->data))->sess->parent->client_ip),
                htons(((record_t *)(op->data))->sess->parent->client_port),
                ((record_t *)(op->data))->sess->handshake_state);
        fprintf(stderr, "record type: %u, handshake type: %u\n",
                ((record_t *)(op->data))->data[0],
                ((record_t *)(op->data))->data[5]);
        return -1;
    }

	return 0;
}

int
execute_mac_crypto(ssl_crypto_op_t* op) 
{
    assert(op != NULL);
    assert(op->opcode.s.function == TLS_HMAC_SHA1);

	unsigned len;

	HMAC(EVP_sha1(),
		 op->key,
		 op->key_len,
		 op->in,
		 op->in_len,
		 op->out,
		 &len);

	assert(len == op->out_len);

    return 0;
}
