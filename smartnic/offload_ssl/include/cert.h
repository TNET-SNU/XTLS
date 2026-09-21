#ifndef __SSL_CONTEXT_H__
#define __SSL_CONTEXT_H__

#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "option.h"
#include "ssl.h"

#define MAX_CERTIFICATE_LENGTH 4096
#define RSA_PADDING RSA_PKCS1_PADDING

typedef
struct rsa_context {
    pka_operand_t *p;
    pka_operand_t *q;
    pka_operand_t *d_p;
    pka_operand_t *d_q;
    pka_operand_t *qinv;

    pka_operand_t *rsa_encrypt_key;
    pka_operand_t *rsa_decrypt_key;
    pka_operand_t *rsa_modulus;
    pka_operand_t *rsa_ciphertext; // is it necessary?
} rsa_context_t;

typedef
struct ecdsa_context {
    pka_operand_t *priv_key;
} ecdsa_context_t;

typedef
struct pka_context {
    union {
        rsa_context_t rsa;
        ecdsa_context_t ecdsa;
    };
} pka_t;

typedef
struct ssl_context {
    uint8_t key_exchange_algorithm;
    uint8_t certificate[MAX_CERTIFICATE_LENGTH];
    int certificate_length;
    pka_t *pka;
    RSA *rsa;
    EC_KEY *ecdsa;
} ssl_context_t;

int
cert_load_key_rsa(ssl_context_t* ctx);

int
cert_load_key_ecdsa(ssl_context_t* ctx);

#endif /* __SSL_CONTEXT_H__ */
