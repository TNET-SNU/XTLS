#include "pka_benchmark.h"

#include <stdlib.h>
#include <stdatomic.h>
#include <time.h>

#include <rte_cycles.h>

#include "ring.h"
/*---------------------------------------------------------------------------*/
// eclipse function parameter for ECC
// All of the following constants are in big-endian format.

//static char P256_p_string[] =
//    "ffffffff 00000001 00000000 00000000 00000000 ffffffff"
//    "ffffffff ffffffff";

uint8_t P256_p_buf[] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

//static char P256_a_string[] =
//    "ffffffff 00000001 00000000 00000000 00000000 ffffffff"
//    "ffffffff fffffffc";

uint8_t P256_a_buf[] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
};

//static char P256_b_string[] =
//    "5ac635d8 aa3a93e7 b3ebbd55 769886bc 651d06b0 cc53b0f6"
//    "3bce3c3e 27d2604b";

uint8_t P256_b_buf[] =
{
    0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7,
    0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
    0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
    0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B
};

//static char P256_xg_string[] =
//    "6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0"
//    "f4a13945 d898c296";

// Base_pt:
uint8_t P256_xg_buf[] =
{
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
    0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
    0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96
};

//static char P256_yg_string[] =
//    "4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece"
//    "cbb64068 37bf51f5";

uint8_t P256_yg_buf[] =
{
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
    0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
    0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5
};

//static char P256_n_string[] =
//    "ffffffff 00000000 ffffffff ffffffff bce6faad a7179e84"
//    "f3b9cac2 fc632551";

// Base_pt_order:
uint8_t P256_n_buf[] =
{
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
};

// 2^255 - 19 in big-endian
uint8_t X25519_curve_p_buf[] =
{
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xED
};

// 486662 in big-endian
uint8_t X25519_curve_A_buf[] =
{
    0x07, 0x6D, 0x06
};

// In big endian order
uint8_t Curve255_bp_u_buf[] =
{
    0x09
};

// In big endian order
uint8_t Curve255_bp_v_buf[] =
{
    0x20, 0xAE, 0x19, 0xA1, 0xB8, 0xA0, 0x86, 0xB4,
    0xE0, 0x1E, 0xDD, 0x2C, 0x77, 0x48, 0xD1, 0x4C,
    0x92, 0x3D, 0x4D, 0x7E, 0x6D, 0x7C, 0x61, 0xB2,
    0x29, 0xE9, 0xC5, 0xA2, 0x7E, 0xCE, 0xD3, 0xD9
};

// In big endian order
uint8_t Curve255_bp_order_buf[] =
{
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xDE, 0xF9, 0xDE, 0xA2, 0xF7, 0x9C, 0xD6,
    0x58, 0x12, 0x63, 0x1A, 0x5C, 0xF5, 0xD3, 0xED
};

uint8_t HEX_CHARS[] = "0123456789ABCDEF";

uint8_t FROM_HEX[256] = {
	['0'] = 0,  ['1'] = 1,  ['2'] = 2,  ['3'] = 3,  ['4'] = 4,
	['5'] = 5,  ['6'] = 6,  ['7'] = 7,  ['8'] = 8,  ['9'] = 9,
	['a'] = 10, ['b'] = 11, ['c'] = 12, ['d']  = 13, ['e'] = 14, ['f'] = 15,
	['A'] = 10, ['B'] = 11, ['C'] = 12, ['D'] = 13, ['E'] = 14, ['F'] = 15
};
/*---------------------------------------------------------------------------------------*/
pka_instance_t instance;

/* EC specific variables
 * 
 * a, b, p: parameter of elliptic curve
 * ec_private_key: a big prime number k, less than P
 * x, y: public_key K = (x, y) = k*G, where G is well-known starting point on the graph
 * P256_base_pt: G
 * note: multiply and add operation in ECC are totally different with regular ones */
ecc_curve_t* P256_curve;
ecc_point_t* P256_base_pt;
pka_operand_t* P256_base_pt_order;

ecc_mont_curve_t* X25519_curve;
ecc_point_t* C255_base_pt;
pka_operand_t* C255_base_pt_order;
uint32_t C255_base_pt_order_byte_len;

pka_operand_t** ec_priv_key;
ecc_point_t** ec_pub_key_ep;
pka_operand_t** ec_pub_key_po;

pka_operand_t** remote_ec_priv_key;
ecc_point_t** remote_ec_pub_key_ep;
pka_operand_t** remote_ec_pub_key_po;

pka_operand_t** ec_priv_key_x25519_0;
pka_operand_t** ec_priv_key_x25519_1;
pka_operand_t** ec_pub_key_x25519;

pka_operand_t** remote_ec_priv_key_x25519;
pka_operand_t** remote_ec_pub_key_x25519;

ecc_point_t** remote_shared_secret_ep;
pka_operand_t** remote_shared_secret_po;
dsa_signature_t** answer;

pka_operand_t** k;
pka_operand_t** hash;
/*---------------------------------------------------------------------------------------*/
/* other global variables */
int cpu_num = 1;
int thread_num = 1;
int ring_num = 4;
int outstanding_cmd_num = 4;
int cmd_cnt_per_thread = 20000;
struct timespec start_ts = {0,};
struct timespec end_ts = {0,};

thread_ctx_t thread_ctx[MAX_THREAD_NUM];
sj_ring_t *pka_cmd_rings[MAX_THREAD_NUM];
sj_ring_t *pka_rslt_rings[MAX_THREAD_NUM];

int key_pair_gen = KEY_PAIR_GEN;
int ecdh_key_calculate = ECDH_KEY_CALCULATE;
int handshake_key_derive = HANDSHAKE_KEY_DERIVE;
int ecdsa_sig_gen = ECDSA_SIG_GEN;
int app_key_derive = APP_KEY_DERIVE;

int is_tls13_benchmark = 0;

int work_done = 0;

#if DBG_MODE
BIO *out;
#endif /* DBG_MODE */

size_t cmd_cnt[MAX_THREAD_NUM];
tls13_op_cnt_t tls13_op_cnt[MAX_THREAD_NUM];
size_t tls13_sess_cnt[MAX_THREAD_NUM];

static pka_barrier_t thread_start_barrier;

pka_results_t *memcpy_results[MAX_OUTSTANDING_CMD_NUM];

/* __thread int MAX_CNT = 20000; */
/* __thread int max_cmd_cnt = 20000; */

uint64_t pka_get_result_min = UINT64_MAX;
uint64_t pka_get_result_max;
uint64_t pka_get_result_sum;
uint64_t pka_get_result_cnt;
uint64_t pka_get_result_fail_cnt;
uint64_t pka_get_result_success_cnt;
/*---------------------------------------------------------------------------------------*/
void*
HKDFworker(void *arg)
{
	thread_ctx_t *ctx = (thread_ctx_t *)arg;
	int tid = ctx->tid;
	int rand_num;
	uint32_t seed = time(NULL) ^ pthread_self();

	/* set initial values */
	sj_ring_enqueue(pka_cmd_rings[tid], &app_key_derive);

	/* wait for all worker ready */
	pka_barrier_wait(&thread_start_barrier);

	while (!work_done) {
		rand_num = rand_r(&seed) % 2;

		if (rand_num == HANDSHAKE_KEY_DERIVE) {
			if (sj_ring_enqueue(pka_cmd_rings[tid], &handshake_key_derive) != 0) {
				continue;
			}

			uint8_t handshake_msgs[338] = {0}; /* dummy handshake messages */
			uint8_t early_secret[48] = {0};
			uint8_t early_secret_salt[48] = {0};
			uint8_t empty_hash[48];
			uint8_t hello_hash[48];
			uint8_t derived_secret[48];
			uint8_t handshake_secret[48];
			uint8_t shared_secret[32] = {0}; /* dummy shared secret */
			uint8_t client_secret[48];
			uint8_t server_secret[48];
			uint8_t client_handshake_key[48];
			uint8_t server_handshake_key[48];
			uint8_t client_handshake_iv[12];
			uint8_t server_handshake_iv[12];

			SHA384(handshake_msgs,
				   338,
				   hello_hash);
			
			if (hkdf_extract(early_secret, 48,
							early_secret_salt, 48,
							early_secret_salt, 48,
							EVP_sha384()) == 0) {
				fprintf(stderr, "hkdf_extract failed!\n");
				return NULL;
			}

			SHA384(NULL, 0, empty_hash);

			if (hkdf_expand_label(derived_secret, 48,
								early_secret, 48,
								(unsigned char *)"derived", strlen("derived"),
								empty_hash, 48,
								EVP_sha384()) == 0) {
				fprintf(stderr, "hkdf_expand_label failed!\n");
				return NULL;
			}

			if (hkdf_extract(handshake_secret, 48,
							derived_secret, 48,
							shared_secret, 32,
							EVP_sha384()) == 0) {
				fprintf(stderr, "hkdf_extract failed!\n");
				return NULL;
			}

			if (hkdf_expand_label(client_secret, 48,
								handshake_secret, 48,
								(unsigned char *)"c hs traffic", strlen("c hs traffic"),
								hello_hash, 48,
								EVP_sha384()) == 0) {
				fprintf(stderr, "hkdf_expand_label failed!\n");
				return NULL;
			}

			if (hkdf_expand_label(server_secret, 48,
								handshake_secret, 48,
								(unsigned char *)"s hs traffic", strlen("s hs traffic"),
								hello_hash, 48,
								EVP_sha384()) == 0) {
				fprintf(stderr, "hkdf_expand_label failed!\n");
				return NULL;
			}

			if (hkdf_expand_label(client_handshake_key, 32,
								client_secret, 48,
								(unsigned char *)"key", strlen("key"),
								(unsigned char *)"", 0,
								EVP_sha384()) == 0) {
				fprintf(stderr, "hkdf_expand_label failed!\n");
				return NULL;
			}

			if (hkdf_expand_label(server_handshake_key, 32,
								server_secret, 48,
								(unsigned char *)"key", strlen("key"),
								(unsigned char *)"", 0,
								EVP_sha384()) == 0) {
				fprintf(stderr, "hkdf_expand_label failed!\n");
				return NULL;
			}

			if (hkdf_expand_label(client_handshake_iv, 12,
								client_secret, 48,
								(unsigned char *)"iv", strlen("iv"),
								(unsigned char *)"", 0,
								EVP_sha384()) == 0) {
				fprintf(stderr, "hkdf_expand_label failed!\n");
				return NULL;
			}

			if (hkdf_expand_label(server_handshake_iv, 12,
								server_secret, 48,
								(unsigned char *)"iv", strlen("iv"),
								(unsigned char *)"", 0,
								EVP_sha384()) == 0) {
				fprintf(stderr, "hkdf_expand_label failed!\n");
				return NULL;
			}

			ctx->outstanding_hkdf_num++;
		} else if (rand_num == APP_KEY_DERIVE) {
			if (sj_ring_enqueue(pka_cmd_rings[tid], &app_key_derive) != 0) {
				continue;
			}

			uint8_t handshake_msgs[973] = {0}; /* dummy handshake messages */
			uint8_t empty_hash[48];
			uint8_t handshake_hash[48];
			uint8_t handshake_secret[48];
			uint8_t derived_secret[48];    
			uint8_t empty_salt[48] = {0};
			uint8_t master_secret[48];
			uint8_t app_client_secret[48];
			uint8_t app_server_secret[48];
			uint8_t client_application_key[48];
			uint8_t server_application_key[48];
			uint8_t client_application_iv[12];
			uint8_t server_application_iv[12];

			SHA384(NULL, 0, empty_hash);
			
			SHA384(handshake_msgs,
				973,
				handshake_hash);

			if (hkdf_expand_label(derived_secret, 48,
								handshake_secret, 48,
								(unsigned char *)"derived", strlen("derived"),
								empty_hash, 48,
								EVP_sha384()) == 0) {
				fprintf(stderr, "hkdf_expand_label failed!\n");
				return NULL;
			}

			if (hkdf_extract(master_secret, 48,
							derived_secret, 48,
							empty_salt, 48,
							EVP_sha384()) == 0) {
				fprintf(stderr, "hkdf_extract failed!\n");
				return NULL;
			}

			if (hkdf_expand_label(app_client_secret, 48,
								master_secret, 48,
								(unsigned char *)"c ap traffic", strlen("c ap traffic"),
								handshake_hash, 48,
								EVP_sha384()) == 0) {
				fprintf(stderr, "hkdf_expand_label failed!\n");
				return NULL;
			}

			if (hkdf_expand_label(app_server_secret, 48,
								master_secret, 48,
								(unsigned char *)"s ap traffic", strlen("s ap traffic"),
								handshake_hash, 48,
								EVP_sha384()) == 0) {
				fprintf(stderr, "hkdf_expand_label failed!\n");
				return NULL;
			}

			if (hkdf_expand_label(client_application_key, 32,
								app_client_secret, 48,
								(unsigned char *)"key", strlen("key"),
								(unsigned char *)"", 0,
								EVP_sha384()) == 0) {
				fprintf(stderr, "hkdf_expand_label failed!\n");
				return NULL;
			}

			if (hkdf_expand_label(server_application_key, 32,
								app_server_secret, 48,
								(unsigned char *)"key", strlen("key"),
								(unsigned char *)"", 0,
								EVP_sha384()) == 0) {
				fprintf(stderr, "hkdf_expand_label failed!\n");
				return NULL;
			}

			if (hkdf_expand_label(client_application_iv, 12,
								app_client_secret, 48,
								(unsigned char *)"iv", strlen("iv"),
								(unsigned char *)"", 0,
								EVP_sha384()) == 0) {
				fprintf(stderr, "hkdf_expand_label failed!\n");
				return NULL;
			}

			if (hkdf_expand_label(server_application_iv, 12,
								app_server_secret, 48,
								(unsigned char *)"iv", strlen("iv"),
								(unsigned char *)"", 0,
								EVP_sha384()) == 0) {
				fprintf(stderr, "hkdf_expand_label failed!\n");
				return NULL;
			}
		}
	}

	return NULL;
}

void*
ASYMworker(void *arg)
{
	pka_handle_t      handle;
	pka_results_t    *results;
	thread_ctx_t 	 *ctx = (thread_ctx_t *)arg;

	int worker_id = *(int *)arg;
	int max_cmd_cnt = cmd_cnt_per_thread;
	int cnt = 0;
	int i, idx, ret;
	uint64_t test_start_time = 0, test_end_time = 0;

	struct timespec last_print, now;
	clock_gettime(CLOCK_MONOTONIC, &last_print);

	int *user_data = malloc(1048576 * sizeof(int));

	for (i = 0; i < 1048576; i++) {
		user_data[i] = i;
	}

	handle = pka_init_local(instance);
	int big_endian = pka_get_rings_byte_order(handle);
	if (worker_id == 0) {
		Get_ECDSA_key_pair(handle, big_endian);
		Get_X25519_key_pair(handle, big_endian);
	}
		
	/* wait for all worker ready */
	pka_barrier_wait(&thread_start_barrier);

	results = malloc_results(MAX_RESULT_CNT, MAX_BYTE_LEN + 8);

	/* decrypt start */
	if (worker_id == 0) {
		test_start_time = pka_cpu_cycles();
		clock_gettime(CLOCK_MONOTONIC, &start_ts);
	}

	int pka_status = SUCCESS;

	while (cnt < max_cmd_cnt) {
		for (i = 1; i < thread_num; i++) {
			int* tls_state;
			idx = cnt % (outstanding_cmd_num - 1);

			if (sj_ring_dequeue(pka_cmd_rings[i], (void **)&tls_state) == 0) {
				if (*tls_state == HANDSHAKE_KEY_DERIVE) {
					if ((pka_status = pka_ecdsa_signature_generate(handle, 
																&user_data[rand() % 1048576], 
																P256_curve, P256_base_pt, P256_base_pt_order,
																ec_priv_key[idx], 
																hash[idx], k[idx])) < 0) {
						fprintf(stderr, "pka_ecdsa_signature_generate failed: status=%d\n", pka_status);
						exit(0);
					}

					cnt++;
					ctx->outstanding_pka_num++;
				} else if (*tls_state == APP_KEY_DERIVE) {
					rand_non_zero_integer_w_pka_hwrng_and_clamping(handle,
										ec_priv_key_x25519_0[idx],
										C255_base_pt_order);
						
					if ((pka_status = pka_mont_ecdh_mult(handle, 
										&user_data[rand() % 1048576], 
										X25519_curve, 
										remote_ec_pub_key_x25519[idx], 
										ec_priv_key_x25519_0[idx])) < 0) {
						fprintf(stderr, "pka_mont_ecdh_mult failed: status=%d\n", pka_status);
						exit(0);
					}

					cnt++;
					ctx->outstanding_pka_num++;
					idx++;

					if ((pka_status = pka_mont_ecdh_mult(handle, 
										&user_data[rand() % 1048576], 
										X25519_curve, 
										remote_ec_pub_key_x25519[idx], 
										ec_priv_key_x25519_0[idx])) < 0) {
						fprintf(stderr, "pka_mont_ecdh_mult failed: status=%d\n", pka_status);
						exit(0);
					}

					cnt++;
					ctx->outstanding_pka_num++;
				}
			}
		}

		while (ctx->outstanding_pka_num >= 0) {
			ret = pka_get_result(handle, results);

			if (ret != SUCCESS) {
				break;
			}

			ctx->outstanding_pka_num--;

			switch (results->opcode) {
				case CC_ECDSA_GENERATE:
					tls13_op_cnt[worker_id].ecdsa_done++;
					break;

				case CC_MONT_ECDH_MULTIPLY:
					tls13_op_cnt[worker_id].ecdh_done++;
					break;

				default:
					break;
			}
		}

		clock_gettime(CLOCK_MONOTONIC, &now);
		long diff = (now.tv_sec - last_print.tv_sec) * 1e9 +
					(now.tv_nsec - last_print.tv_nsec);

		if (diff > 1e9) {
			PrintStatistics(diff);
			clock_gettime(CLOCK_MONOTONIC, &last_print);

			double elapsed_sec =
				(now.tv_nsec - start_ts.tv_nsec) / 1e9 +
				(now.tv_sec - start_ts.tv_sec);

			printf("pka_get_result min=%lu, max=%lu, avg=%lu\n"
				"pka_get_result cnt per sec=%lu, total cnt=%lu\n"
				"pka_get_result fail cnt=%lu, success cnt=%lu\n",
				pka_get_result_min,
				pka_get_result_max,
				(pka_get_result_sum / pka_get_result_cnt),
				(unsigned long)(pka_get_result_cnt / elapsed_sec),
				pka_get_result_cnt,
				pka_get_result_fail_cnt,
				pka_get_result_success_cnt);
		}
	}

	test_end_time = pka_cpu_cycles();
	clock_gettime(CLOCK_MONOTONIC, &end_ts);

	work_done = 1;

	int cpu_frequency = pka_cpu_hz_max();
	printf("total latency: %.6f secs for %d TLS13_ASYM sessions\n",
	(double)(1000000000ULL * (test_end_time - test_start_time) / cpu_frequency) / 1e9,
	cmd_cnt_per_thread * thread_num);
	printf("following to Linux timer, %f secs spent for %d sessions\n", 
		(float)(end_ts.tv_nsec - start_ts.tv_nsec) / 1e9
			+ (float)(end_ts.tv_sec - start_ts.tv_sec), 
		cmd_cnt_per_thread * thread_num);

	free(user_data);
	free_results(results);
	pka_term_local(handle);

	return NULL;
}
/*---------------------------------------------------------------------------------------*/
int
main(int argc, char *argv[])
{
	pthread_t p_thread[MAX_THREAD_NUM];
	pthread_attr_t attr[MAX_THREAD_NUM]; 
	cpu_set_t *cpusetp[MAX_THREAD_NUM]; 
	int cpu_size, i;

	for (i = 0; i < MAX_OUTSTANDING_CMD_NUM; i++) {
		memcpy_results[i] = malloc_results(MAX_RESULT_CNT, MAX_BYTE_LEN + 8);
	}

#if DBG_MODE
	out = BIO_new_fp(stdout, BIO_CLOSE);
#endif /* DBG_MODE */

	srand(time(NULL));

	/* parse options of commandline */
	while((i = getopt(argc, argv, "t:r:o:n:")) >= 0) {
		switch(i) {
			case 't':
				thread_num = atoi(optarg);
				if (thread_num <= 0 || thread_num > PKA_MAX_QUEUE_CNT) {
					fprintf(stderr, "Error: 0 < thread_num <= 16\n");
					exit(1);
				}
				break;
			case 'r':
				ring_num = atoi(optarg);
				if (ring_num <= 0 || ring_num > PKA_MAX_RING_CNT) {
					fprintf(stderr, "Error: 0 < ring_num <= %d\n", PKA_MAX_RING_CNT);
					exit(1);
				}
				break;
			case 'o':
				outstanding_cmd_num = atoi(optarg);
				if (outstanding_cmd_num <= 0) {
					fprintf(stderr, "Error: 0 < max_outstanding\n");
					exit(1);
				}
				if (outstanding_cmd_num > MAX_OUTSTANDING_CMD_NUM) {
					fprintf(stderr, "Error:MAX_OUTSTANDING_CMD_NUM >= max_outstanding\n");
					exit(1);
				}
				break;
			case 'n':
				cmd_cnt_per_thread = atoi(optarg);
				if (cmd_cnt_per_thread <= 0) {
					fprintf(stderr, "Error: 0 < command_num_per_thread\n");
					exit(1);
				}
				break;
			case '?':
				usage();
				exit(1);
		}
	}

	/* Global PKA initialization. This function must be called once per instance
	 * before calling any other PKA API functions.
	 */
	int pka_sync_mode = PKA_F_SYNC_MODE_DISABLE;

	instance = pka_init_global("pka_benchmark_app", PKA_F_PROCESS_MODE_SINGLE |
							   pka_sync_mode,
							   ring_num, PKA_MAX_QUEUE_CNT,
							   CMD_QUEUE_SIZE, RSLT_QUEUE_SIZE);
 
	if (instance == PKA_INSTANCE_INVALID) {
		perror("pka_init_global");
		exit(0);
	}

	/* -------------------------------------------------------------------- */
	/* create thread ctx */
	for (i = 0; i < thread_num; i++) {
		thread_ctx[i].tid = i;
		thread_ctx[i].outstanding_hkdf_num = 0;
		thread_ctx[i].outstanding_pka_num = 0;
	}

	/* create rings */
	for (i = 1; i < thread_num; i++) {
		char pka_cmd_ring_name[32];
		snprintf(pka_cmd_ring_name, 
				 sizeof(pka_cmd_ring_name),
				 "pka_cmd_ring_%u", i);

		pka_cmd_rings[i] = sj_ring_create(pka_cmd_ring_name, outstanding_cmd_num);

		char pka_result_ring_name[32];
		snprintf(pka_result_ring_name, 
				 sizeof(pka_result_ring_name),
				 "pka_result_ring_%u", i);

		pka_rslt_rings[i] = sj_ring_create(pka_result_ring_name, outstanding_cmd_num);
	}

    /* create threads */
	long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpu < 1) ncpu = 1;

	pka_barrier_init(&thread_start_barrier, thread_num);

    for (i = 0; i < thread_num; i++) {
        /* set core */
        if ((cpusetp[i] = CPU_ALLOC(thread_num)) == NULL) {
            fprintf(stderr, "Error: cpu_set initialize failed\n");
            exit(0);
        }
		cpu_size = CPU_ALLOC_SIZE(thread_num);
        CPU_ZERO_S(cpu_size, cpusetp[i]);
        CPU_SET_S(i % ncpu, cpu_size, cpusetp[i]);

        /* set thread attribute (core pinning) */
        if (pthread_attr_init(&attr[i]) != 0) {
            fprintf(stderr, "Error: thread attribute initialize failed\n");
            exit(0);
        }
        pthread_attr_setaffinity_np(&attr[i], cpu_size, cpusetp[i]);

        /* create thread */
        cmd_cnt[i] = 0;

		/* PKA-dedicated thread */
		if (i == 0) {
			int rc = pthread_create(&p_thread[i], &attr[i], ASYMworker, (void *)&thread_ctx[i]);
			if (rc != 0) {
				fprintf(stderr, "Error: ASYM worker pthread_create failed: %s (rc = %d)\n", strerror(rc), rc);
				exit(0);
			}
		} 
		/* HKDF threads */
		else {
			int rc = pthread_create(&p_thread[i], &attr[i], HKDFworker, (void *)&thread_ctx[i]);
			if (rc != 0) {
				fprintf(stderr, "Error: HKDF worker pthread_create failed: %s (rc = %d)\n", strerror(rc), rc);
				exit(0);
			}
		}
    }

    /* wait threads */
    for (i = 0; i < thread_num; i++) {
        pthread_join(p_thread[i], NULL);
        CPU_FREE(cpusetp[i]);
    }

	free(ec_priv_key);

	free(remote_ec_priv_key);

	// Release the given handle and PK instance. Note that these calls will free
	// rings related to the PK instance and will mark them as available again  
	pka_term_global(instance); 

	return 0;
}
