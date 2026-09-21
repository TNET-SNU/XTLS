#include "cert.h"
#include "option.h"

static int
load_certificate(const char *infile, const char* password,
                 char* certificate, int max_len)
{
    BIO *bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    X509 *x = NULL;
    BIO *cert;
    char password_[1024];
    strncpy(password_, password, 1024 - 1);
    password_[1024 - 1] = '\0';

    /* Allocate BIO */
    if ((cert = BIO_new(BIO_s_file())) == NULL) {
        ERR_print_errors(bio_err);
        return -1;
    }

    /* Load certificate to cert */
    if (BIO_read_filename(cert, infile) <= 0) {
        BIO_printf(bio_err, "Error opening %s %s\n",
                   "Certificate", infile);
        ERR_print_errors(bio_err);
        return -1;
    }

    /* Read Certificate in PEM Format */
    x = PEM_read_bio_X509(cert, NULL, NULL, password_);
    if (x == NULL) {
        fprintf(stderr, "Certificate is Null, file: %s, passwd: %s\n",
                        infile, password_);
        exit(EXIT_FAILURE);
    }

    /* Encode the Certificate */
    int len = i2d_X509(x, NULL);
    unsigned char *m = (unsigned char *)OPENSSL_malloc(len);
    unsigned char *d;
    d = (unsigned char *)m;
    if (unlikely(!d)) {
        fprintf(stderr, "Memory allocation for certificate failed\n");
        exit(EXIT_FAILURE);
    }

    len = i2d_X509(x, &d);
    if (len <= 0) {
        fprintf(stderr, "Wrong Certificate\n");
        exit(EXIT_FAILURE);
    }

    d = (unsigned char *)m;

    assert(len <= max_len);
    memcpy(certificate, m, len);

    OPENSSL_free(m);
    X509_free(x);
    BIO_free(cert);
    BIO_free(bio_err);

    return len;
}

static void
set_crt_rsa(RSA *rsa)
{
    uint8_t crt_available;

    const BIGNUM *p = NULL;
    const BIGNUM *q = NULL;
    const BIGNUM *dmp1 = NULL;
    const BIGNUM *dmq1 = NULL;
    const BIGNUM *iqmp = NULL;

    RSA_get0_factors(rsa, &p, &q);
    RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);

    crt_available = (
                    p != NULL &&
                    q != NULL &&
                    dmp1 != NULL &&
                    dmq1 != NULL &&
                    iqmp != NULL
                    );
    
    if (unlikely(!crt_available)) {
        fprintf(stderr, "--------------------------------------------\n");
        fprintf(stderr, "Chinese remainder theorem is not applicable!\n");
        fprintf(stderr, "--------------------------------------------\n");
    }
}

static RSA *
rsa_load_key(char *filename, char *passwd)
{
    BIO *key;
    RSA *rsa;
    OpenSSL_add_all_algorithms();

    key = BIO_new(BIO_s_file());
    assert(key != NULL);
    assert(BIO_read_filename(key, filename) == 1);
    rsa = PEM_read_bio_RSAPrivateKey(key, NULL, NULL, (void *)passwd);
    ERR_print_errors_fp(stderr);
    BIO_free(key);

    assert(rsa != NULL);
    set_crt_rsa(rsa);
    return rsa;
}

static EC_KEY *
ecdsa_load_key(char *filename, char *passwd)
{
    BIO *key = NULL;
    EC_KEY *ec_key = NULL;

    OpenSSL_add_all_algorithms();

    /* create BIO */
    key = BIO_new(BIO_s_file());
    assert(key != NULL);

    /* load file */
    assert(BIO_read_filename(key, filename) == 1);

    /* read ECDSA private key */
    ec_key = PEM_read_bio_ECPrivateKey(key, NULL, NULL, (void *)passwd);
    ERR_print_errors_fp(stderr);

    BIO_free(key);

    assert(ec_key != NULL);

    /* optional: check key validity */
    if (EC_KEY_check_key(ec_key) != 1) {
        fprintf(stderr, "Invalid EC private key\n");
        EC_KEY_free(ec_key);
        return NULL;
    }

    return ec_key;
}

static pka_t *
pka_load_key_rsa(RSA *rsa)
{
    pka_t *pka;

    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    const BIGNUM *d = NULL;
    const BIGNUM *p = NULL;
    const BIGNUM *q = NULL;
    const BIGNUM *dmp1 = NULL;
    const BIGNUM *dmq1 = NULL;
    const BIGNUM *iqmp = NULL;

    RSA_get0_key(rsa, &n, &e, &d);
    RSA_get0_factors(rsa, &p, &q);
    RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);

    pka = calloc(1, sizeof(pka_t));
    
    if (unlikely(!pka)) {
        fprintf(stderr, "Memory allocation for PKA failed.\n");
        exit(EXIT_FAILURE);
    }

    if (p && q && dmp1 && dmq1 && iqmp) {
        pka->rsa.p = bignum_to_operand_rsa((pka_bignum_t *)p);
        pka->rsa.q = bignum_to_operand_rsa((pka_bignum_t *)q);
        pka->rsa.d_p = bignum_to_operand_rsa((pka_bignum_t *)dmp1);
        pka->rsa.d_q = bignum_to_operand_rsa((pka_bignum_t *)dmq1);
        pka->rsa.qinv = bignum_to_operand_rsa((pka_bignum_t *)iqmp);
    }

    if (d) {
        pka->rsa.rsa_encrypt_key = bignum_to_operand_rsa((pka_bignum_t *)e);
        pka->rsa.rsa_decrypt_key = bignum_to_operand_rsa((pka_bignum_t *)d);
        pka->rsa.rsa_modulus = bignum_to_operand_rsa((pka_bignum_t *)n);
    }

    return pka;
}

static pka_t *
pka_load_key_ecdsa(EC_KEY *ec_key)
{
    pka_t *pka;
    const BIGNUM *priv = NULL;
    uint8_t temp_be[32];
    uint8_t temp[32];

    priv = EC_KEY_get0_private_key(ec_key);

    fprintf(stderr, "key bytes: %d\n", BN_num_bytes(priv));

    pka = calloc(1, sizeof(pka_t));
    
    if (unlikely(!pka)) {
        fprintf(stderr, "Memory allocation for PKA failed.\n");
        exit(EXIT_FAILURE);
    }

    if (priv) {
        pka->ecdsa.priv_key = bignum_to_operand((pka_bignum_t *)priv);
        pka->ecdsa.priv_key->big_endian = 0;
    }

#if VERBOSE_CERT
    fprintf(stderr, "ECDSA private key:\n");
    operand_to_string(pka->ecdsa.priv_key, temp_be, pka->ecdsa.priv_key->buf_len);
    for (int i = 0; i < pka->ecdsa.priv_key->buf_len; i++) {
        fprintf(stderr, "%02x", temp_be[i]);
    }
    fprintf(stderr, "\n");
#endif /* VERBOSE_CERT */

    return pka;
}

int
cert_load_key_rsa(ssl_context_t* ctx)
{
    ctx->certificate_length = load_certificate(option.key_file,
                                               option.key_passwd,
                                               (char *)ctx->certificate,
                                               MAX_CERTIFICATE_LENGTH);
#if VERBOSE_CERT
    fprintf(stderr, "certificate_length: %d\n", ctx->certificate_length);
#endif /* VERBOSE_CERT */

    if (ctx->certificate_length <= 0)
        return -1;

    fprintf(stderr, "Loading RSA key\n");
    ctx->rsa = rsa_load_key(option.key_file, option.key_passwd);
    if (unlikely(!ctx->rsa)) {
        fprintf(stderr, "rsa_load_key failed.\n");
        exit(EXIT_FAILURE);
    }
    ctx->pka = pka_load_key_rsa(ctx->rsa);
    if (unlikely(!ctx->pka)) {
        fprintf(stderr, "pka_load_key failed.\n");
        exit(EXIT_FAILURE);
    }
    return 0;
}

int
cert_load_key_ecdsa(ssl_context_t* ctx)
{
    ctx->certificate_length = load_certificate(option.key_file,
                                               option.key_passwd,
                                               (char *)ctx->certificate,
                                               MAX_CERTIFICATE_LENGTH);
#if VERBOSE_CERT
    fprintf(stderr, "certificate_length: %d\n", ctx->certificate_length);

    fprintf(stderr, "certificate:\n");
    for (int i = 0; i < ctx->certificate_length; i++) {
        fprintf(stderr, "%02x", ctx->certificate[i]);
        if ((i + 1) % 16 == 0)
            fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
#endif /* VERBOSE_CERT */

    if (ctx->certificate_length <= 0)
        return -1;

    fprintf(stderr, "Loading ECDSA key\n");
    ctx->ecdsa = ecdsa_load_key(option.key_file, option.key_passwd);
    if (unlikely(!ctx->ecdsa)) {
        fprintf(stderr, "ecdsa_load_key failed.\n");
        exit(EXIT_FAILURE);
    }

    ctx->pka = pka_load_key_ecdsa(ctx->ecdsa);
    if (unlikely(!ctx->pka)) {
        fprintf(stderr, "pka_load_key failed.\n");
        exit(EXIT_FAILURE);
    }
    
    return 0;
}
