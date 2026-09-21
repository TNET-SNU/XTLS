#include "pka_benchmark.h"

#define BIT_LEN 256

void
usage();

void 
print_hex(pka_operand_t *value);

int
from_hex_string(char *hex_string, pka_operand_t *value);

int
to_hex_string(pka_operand_t *value,
			  char          *string_buf,
			  uint32_t       buf_len);

int 
bn2binpad(const BIGNUM *bn, unsigned char *out, int out_len);

int
Get_RSA_key_pair(char *pem_filename);

int
Get_P256_key_pair(pka_handle_t handle, int big_endian);

int
Get_X25519_key_pair(pka_handle_t handle, int big_endian);

int
Get_ECDSA_key_pair(pka_handle_t handle, int big_endian);

int 
hkdf_extract(unsigned char *out, size_t out_len,
			 const unsigned char *salt, size_t salt_len,
			 const unsigned char *key,  size_t key_len,
			 const EVP_MD *md);

int 
hkdf_expand_label(unsigned char *out, size_t out_len,
				  const unsigned char *key, size_t key_len,
				  const unsigned char *label, size_t label_len,
				  const unsigned char *ctx, size_t ctx_len,
				  const EVP_MD *md);

pka_results_t* 
malloc_results(uint32_t result_cnt, uint32_t buf_len);

void 
free_results_buf(pka_results_t *results);

void 
free_results(pka_results_t *results);

void
PrintStatistics(uint64_t interval);
