#ifndef __SSL_CRYPTO_H__
#define __SSL_CRYPTO_H__

#include "cert.h"
#include "option.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rsa.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
/*---------------------------------------------------------------------------*/
typedef enum tls_crypto_function {
    TLS_RSA = 0,
    TLS_AES_CBC = 1,
    TLS_AES_GCM = 2,
    TLS_HMAC_SHA1 = 3,
    TLS_MONT_ECDH = 4,
    TLS_ECDSA = 5,
} tls_crypto_function_t;

typedef enum tls_crypto_op {
    ENCRYPT = 0,
    DECRYPT = 1,
    PUBLIC_ENCRYPT = 2,
    PUBLIC_DECRYPT = 3,
    PRIVATE_ENCRYPT = 4,
    PRIVATE_DECRYPT = 5,
    HASH = 6,
    KEY_GENERATION = 7,
    SHARED_SECRET = 8,
    SIGNATURE = 9,
} tls_crypto_op_t;

typedef enum tls13_key_exchange {
    TLS_1_3_ECDSA_ECDHE = 2,
    KEY_GEN = 0,
    SHARED_SECRET_CALC = 1,
    ECDSA_SIGNATURE = 2,
} tls13_key_exchange_t;
/*---------------------------------------------------------------------------*/
#define GCM_TAG_SIZE                        16
#define MAX_HASH_SIZE                       256
#define MAX_PRE_SIG_SIZE                    384
/*---------------------------------------------------------------------------*/
#define TLS_OPCODE_AES_CBC_128_ENCRYPT      0x00800001u
#define TLS_OPCODE_AES_CBC_128_DECRYPT      0x00800101u
#define TLS_OPCODE_AES_CBC_256_ENCRYPT      0x01000001u
#define TLS_OPCODE_AES_CBC_256_DECRYPT      0x01000101u
#define TLS_OPCODE_AES_GCM_128_ENCRYPT      0x00800002u
#define TLS_OPCODE_AES_GCM_128_DECRYPT      0x00800102u
#define TLS_OPCODE_AES_GCM_256_ENCRYPT      0x01000002u
#define TLS_OPCODE_AES_GCM_256_DECRYPT      0x01000102u
#define TLS_OPCODE_HMAC_SHA1_HASH           0x00000603u
#define TLS_OPCODE_HMAC_SHA256_HASH         0x00000003u
#define TLS_OPCODE_HMAC_SHA384_HASH         0x00000003u
#define TLS_OPCODE_RSA_1024_PUBLIC_DECRYPT  0x04000300u
#define TLS_OPCODE_RSA_1024_PRIVATE_DECRYPT 0x04000500u
#define TLS_OPCODE_RSA_2048_PUBLIC_DECRYPT  0x08000300u
#define TLS_OPCODE_RSA_2048_PRIVATE_DECRYPT 0x08000500u
#define TLS_OPCODE_RSA_3072_PUBLIC_DECRYPT  0x0C000300u
#define TLS_OPCODE_RSA_3072_PRIVATE_DECRYPT 0x0C000500u
#define TLS_OPCODE_RSA_4096_PUBLIC_DECRYPT  0x10000300u
#define TLS_OPCODE_RSA_4096_PRIVATE_DECRYPT 0x10000500u
#define TLS_OPCODE_ECDHE_KEY_GENERATION     0x00000704u
#define TLS_OPCODE_ECDHE_SHARED_SECRET_CALC 0x00000804u
#define TLS_OPCODE_ECDSA_SIGNATURE          0x00000905u
/*---------------------------------------------------------------------------*/
typedef union ssl_crypto_opcode {
    struct {
        uint8_t function;
        uint8_t op;
        uint16_t bit;
    } s;
    uint32_t u32;
} ssl_crypto_opcode_t;
/*---------------------------------------------------------------------------*/
typedef struct ssl_crypto_op {
    struct thread_context *ctx;
    ssl_crypto_opcode_t opcode;

#if PKA_TWICE
    int cnt;
#endif /* PKA_TWICE */

    uint8_t *in;
    uint8_t *out;

    pka_operand_t *pka_in;
    pka_operand_t *pka_in_1;
    pka_operand_t *pka_in_2;
    pka_results_t *pka_out;

    uint8_t *key;
    uint8_t *iv;
    uint8_t *aad; /* used for AEAD crypto operation */

    uint32_t in_len;
    uint16_t key_len;
    uint16_t iv_len;
    uint32_t out_len;
    uint16_t aad_len; /* used for AEAD crypto operation */

    struct ssl_session *sess;
    void *data;

    uint8_t pka_flag;

    TAILQ_ENTRY(ssl_crypto_op) op_pool_link;
    TAILQ_ENTRY(ssl_crypto_op) op_trace_link;
} ssl_crypto_op_t; /* size: 144 */
/*---------------------------------------------------------------------------*/
typedef struct ssl_crypto {
} ssl_crypto_t;

typedef struct thread_context thread_context_t;
/*---------------------------------------------------------------------------*/
int
execute_rsa_crypto(ssl_crypto_op_t *op);

int
execute_ecdhe_key_generation(ssl_crypto_op_t *op);

int
execute_ecdhe_shared_secret_calculation(ssl_crypto_op_t *op);

int
execute_ecdsa_signature(ssl_crypto_op_t *op);

int
hkdf_extract(HMAC_CTX *hctx, unsigned char *out, size_t out_len,
             const unsigned char *salt, size_t salt_len,
             const unsigned char *key, size_t key_len, const EVP_MD *md);

int
hkdf_expand_label(HMAC_CTX *hctx, unsigned char *out, size_t out_len,
                  const unsigned char *key, size_t key_len,
                  const unsigned char *label, size_t label_len,
                  const unsigned char *info, size_t info_len, const EVP_MD *md);
/*---------------------------------------------------------------------------*/
int
execute_aes_crypto(EVP_CIPHER_CTX *ctx, ssl_crypto_op_t *op);
/*---------------------------------------------------------------------------*/
int
execute_mac_crypto(ssl_crypto_op_t *op);
/*---------------------------------------------------------------------------*/
void
HMAC_SHA1(uint8_t *key, int key_len, uint8_t *in, int in_len, uint8_t *out);
/*---------------------------------------------------------------------------*/
int
PRF(const EVP_MD *(*hash_func)(void), const int secret_len,
    const uint8_t *secret, const int label_len, const uint8_t *label,
    const int seed_len, const uint8_t *seed, const int out_len, uint8_t *out);

#endif /* __SSL_CRYPTO_H__ */