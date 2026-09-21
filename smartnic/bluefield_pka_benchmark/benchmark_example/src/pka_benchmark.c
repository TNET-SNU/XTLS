#include "pka_benchmark.h"

#include <stdlib.h>
#include <time.h>

#include <rte_cycles.h>
#include <rte_ring.h>

#include <ck_ring.h>

#include <stdatomic.h>
/*---------------------------------------------------------------------------*/
// eclipse function parameter for ECC
// All of the following constants are in big-endian format.

// static char P256_p_string[] =
//     "ffffffff 00000001 00000000 00000000 00000000 ffffffff"
//     "ffffffff ffffffff";

uint8_t P256_p_buf[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// static char P256_a_string[] =
//     "ffffffff 00000001 00000000 00000000 00000000 ffffffff"
//     "ffffffff fffffffc";

uint8_t P256_a_buf[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC};

// static char P256_b_string[] =
//     "5ac635d8 aa3a93e7 b3ebbd55 769886bc 651d06b0 cc53b0f6"
//     "3bce3c3e 27d2604b";

uint8_t P256_b_buf[] = {0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7,
                        0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
                        0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
                        0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B};

// static char P256_xg_string[] =
//     "6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0"
//     "f4a13945 d898c296";

// Base_pt:
uint8_t P256_xg_buf[] = {0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
                         0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
                         0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
                         0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96};

// static char P256_yg_string[] =
//     "4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece"
//     "cbb64068 37bf51f5";

uint8_t P256_yg_buf[] = {0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
                         0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
                         0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
                         0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5};

// static char P256_n_string[] =
//     "ffffffff 00000000 ffffffff ffffffff bce6faad a7179e84"
//     "f3b9cac2 fc632551";

// Base_pt_order:
uint8_t P256_n_buf[] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
                        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};

// 2^255 - 19 in big-endian
uint8_t X25519_curve_p_buf[] = {0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xED};

// 486662 in big-endian
uint8_t X25519_curve_A_buf[] = {0x07, 0x6D, 0x06};

// In big endian order
uint8_t Curve255_bp_u_buf[] = {0x09};

// In big endian order
uint8_t Curve255_bp_v_buf[] = {0x20, 0xAE, 0x19, 0xA1, 0xB8, 0xA0, 0x86, 0xB4,
                               0xE0, 0x1E, 0xDD, 0x2C, 0x77, 0x48, 0xD1, 0x4C,
                               0x92, 0x3D, 0x4D, 0x7E, 0x6D, 0x7C, 0x61, 0xB2,
                               0x29, 0xE9, 0xC5, 0xA2, 0x7E, 0xCE, 0xD3, 0xD9};

// In big endian order
uint8_t Curve255_bp_order_buf[] = {
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0xDE, 0xF9, 0xDE, 0xA2, 0xF7,
    0x9C, 0xD6, 0x58, 0x12, 0x63, 0x1A, 0x5C, 0xF5, 0xD3, 0xED};

uint8_t HEX_CHARS[] = "0123456789ABCDEF";

uint8_t FROM_HEX[256] = {
    ['0'] = 0,  ['1'] = 1,  ['2'] = 2,  ['3'] = 3,  ['4'] = 4,  ['5'] = 5,
    ['6'] = 6,  ['7'] = 7,  ['8'] = 8,  ['9'] = 9,  ['a'] = 10, ['b'] = 11,
    ['c'] = 12, ['d'] = 13, ['e'] = 14, ['f'] = 15, ['A'] = 10, ['B'] = 11,
    ['C'] = 12, ['D'] = 13, ['E'] = 14, ['F'] = 15};
/*---------------------------------------------------------------------------------------*/
pka_instance_t instance;

/* RSA specific variables
 *
 * p, q: two prime numbers to make a key pair
 * dmp1, dmpq1, iqmp: values for CRT, conducted from p, q
 * n: modulus
 * e: exponent(public key)
 * d: exponent(private key)                                 */
EVP_PKEY *rsa_private_key;
pka_operand_t *p, *q, *d_p, *d_q, *qinv;
pka_operand_t *rsa_encrypt_key, *rsa_decrypt_key, *rsa_modulus, *rsa_ciphertext;

/* EC specific variables
 *
 * a, b, p: parameter of elliptic curve
 * ec_private_key: a big prime number k, less than P
 * x, y: public_key K = (x, y) = k*G, where G is well-known starting point on
 * the graph P256_base_pt: G note: multiply and add operation in ECC are totally
 * different with regular ones */
ecc_curve_t *P256_curve;
ecc_point_t *P256_base_pt;
pka_operand_t *P256_base_pt_order;

ecc_mont_curve_t *X25519_curve;
ecc_point_t *C255_base_pt;
pka_operand_t *C255_base_pt_order;
uint32_t C255_base_pt_order_byte_len;

pka_operand_t **ec_priv_key;
ecc_point_t **ec_pub_key_ep;
pka_operand_t **ec_pub_key_po;

pka_operand_t **remote_ec_priv_key;
ecc_point_t **remote_ec_pub_key_ep;
pka_operand_t **remote_ec_pub_key_po;

pka_operand_t **ec_priv_key_x25519_0;
pka_operand_t **ec_priv_key_x25519_1;
pka_operand_t **ec_pub_key_x25519;

pka_operand_t **remote_ec_priv_key_x25519;
pka_operand_t **remote_ec_pub_key_x25519;

ecc_point_t **remote_shared_secret_ep;
pka_operand_t **remote_shared_secret_po;
dsa_signature_t **answer;

pka_operand_t **k;
pka_operand_t **hash;
/*---------------------------------------------------------------------------------------*/
/* other global variables */
enum {
    RSA_DECRYPTION = 0,
    P256,
    X25519,
    ECDSA_SIG_GEN,
    TLS13_ASYM,
    TLS13_ASYM_HKDF,
    RAND,
    SPSC
};
int operation_mode = 0;
int cpu_num = 1;
int thread_num = 1;
int ring_num = 4;
int outstanding_cmd_num = 4;
int cmd_cnt_per_thread = 20000;
struct timespec start_ts = {
    0,
};
struct timespec end_ts = {
    0,
};

int is_tls13_benchmark = 0;

int work_done = 0;

#if DBG_MODE
BIO *out;
#endif /* DBG_MODE */

size_t cmd_cnt[MAX_THREAD_NUM];
tls13_op_cnt_t tls13_op_cnt[MAX_THREAD_NUM];
size_t tls13_sess_cnt[MAX_THREAD_NUM];

static pka_barrier_t thread_start_barrier;
ck_ring_t submit_pka_ring;
ck_ring_buffer_t submit_pka_ring_buffer[2 * MAX_OUTSTANDING_CMD_NUM];

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
void *
RSAworker(void *arg)
{
    /* UNUSED(arg); */
    char *plaintext = "0x112233445566778899101112131415161718192021222324252627"
                      "282930313233343536373839404142434445464748"; /* 48 B */
    int worker_id = *(int *)arg;
    int max_cmd_cnt = cmd_cnt_per_thread;
    int cnt = 0;
    int cur_command_cnt = 0;
    pka_handle_t handle;
    pka_results_t *results;
    pka_operand_t msg;
    uint32_t result_len;

    uint64_t test_start_time = 0, test_end_time = 0;

    struct timespec last_print, now;
    clock_gettime(CLOCK_MONOTONIC, &last_print);

#if DBG_MODE
    char result_buf[2][100];
    static __thread int cnt_correct = 0;
    result_buf[0][0] = result_buf[1][0] = '\0';
#endif /* DBG_MODE */

    int *user_data = malloc(outstanding_cmd_num * sizeof(int));

    /* wait for all worker ready */
    pka_barrier_wait(&thread_start_barrier);

    handle = pka_init_local(instance);
    results = malloc_results(2, MAX_BYTE_LEN + 8);

    /* encrypt first */
    msg.buf_ptr = NULL;

    if (from_hex_string(plaintext, &msg) < 0) {
        perror("from_hex_string");
        exit(0);
    }

#if DBG_MODE
    printf("\n------------------encrypt----------------------\n");
    print_operand("encrypt_key = ", rsa_encrypt_key, "\n");
    print_operand("modulus = ", rsa_modulus, "\n");
    print_operand("msg = ", &msg, "\n\n");
#endif /* DBG_MODE */

    if (pka_modular_exp(handle, NULL, rsa_encrypt_key, rsa_modulus, &msg) < 0) {
        perror("pka_modular_exp");
        exit(0);
    }

    /* get result using polling */
    while (pka_get_result(handle, results) != SUCCESS) {
        pka_wait();
        continue;
    }

    result_len = results->results[0].actual_len;
    rsa_ciphertext = malloc_operand(result_len);
    copy_operand(&results->results[0], rsa_ciphertext);

    if (rsa_ciphertext == NULL) {
        perror("copy_operand:");
        exit(0);
    }

#if DBG_MODE
    print_operand("encryption result = ", rsa_ciphertext, "\n\n");
#endif /* DBG_MODE */

    /* decrypt start */
    if (worker_id == 0) {
        test_start_time = pka_cpu_cycles();
        clock_gettime(CLOCK_MONOTONIC, &start_ts);
    }

    int pka_status = SUCCESS;

#if DBG_MODE
    printf("\n------------------[%d]decrypt----------------------\n",
           worker_id);
    print_operand("p = ", p, "\n");
    print_operand("q = ", q, "\n");
    print_operand("d_p = ", d_p, "\n");
    print_operand("d_q = ", d_q, "\n");
    print_operand("qinv = ", qinv, "\n\n");
#endif /* DBG_MODE */

    while (cnt < max_cmd_cnt || cur_command_cnt > 0) {
        while (cnt < max_cmd_cnt && cur_command_cnt < outstanding_cmd_num) {
            /* send decryption request to PKA HW */
            user_data[cnt % outstanding_cmd_num] = cnt;
            if (p) {
                if ((pka_status = pka_modular_exp_crt(
                         handle, &user_data[cnt % outstanding_cmd_num],
                         rsa_ciphertext, p, q, d_p, d_q, qinv)) < 0) {
                    perror("pka_modular_exp_crt");
                    exit(0);
                }
            } else if (rsa_decrypt_key) {
                if ((pka_status = pka_modular_exp(
                         handle, &user_data[cnt % outstanding_cmd_num],
                         rsa_decrypt_key, rsa_modulus, rsa_ciphertext)) < 0) {
                    perror("pka_modular_exp");
                    exit(0);
                }
            } else {
                fprintf(stderr, "Error: key pair does not exist\n");
                exit(0);
            }
            cnt++;
            cur_command_cnt++;
        }

        if (pka_status == FAILURE)
            fprintf(stderr, "pka cmd submittion failed\n");

        /* get result using polling */
        // while (cur_command_cnt > 0) {
        if (pka_get_result(handle, results) != SUCCESS) {
            continue;
        } else {
            if (results->status != 0) {
                fprintf(stderr, "PKA HW Operation Failed! Status: %d\n",
                        results->status);
                cur_command_cnt--;
                cmd_cnt[worker_id]++;
                continue;
            }
#if CHECK_CORRECTNESS
            /* check correctness */
            if (memcmp(results->results[0].buf_ptr, msg.buf_ptr,
                       msg.actual_len) != 0) {
                fprintf(
                    stderr,
                    "Error: decrypt result is different to original text!\n");
                print_operand("decryption result = ", &results->results[0],
                              "\n");
                print_operand("original text = ", &msg, "\n");
                exit(0);
            }
#endif /* CHECK_CORRECTNESS */

            cur_command_cnt--;
            cmd_cnt[worker_id]++;
        }
        // }

        if (worker_id == 0) {
            clock_gettime(CLOCK_MONOTONIC, &now);
            long diff = (now.tv_sec - last_print.tv_sec) * 1000000000 +
                        (now.tv_nsec - last_print.tv_nsec);

            if (diff > 1000000000) {
                PrintStatistics(diff);
                clock_gettime(CLOCK_MONOTONIC, &last_print);
            }
        }
    }

    if (worker_id == 0) {
        test_end_time = pka_cpu_cycles();
        clock_gettime(CLOCK_MONOTONIC, &end_ts);

        int cpu_frequency = pka_cpu_hz_max();
        printf("total latency: %.6f secs for %d RSA decryption\n",
               (double)(1000000000ULL * (test_end_time - test_start_time) /
                        cpu_frequency) /
                   1e9,
               cmd_cnt_per_thread * thread_num);
        printf(
            "following to Linux timer, %f secs spent for %d RSA decryption\n",
            (float)(end_ts.tv_nsec - start_ts.tv_nsec) / 1000000000 +
                (float)(end_ts.tv_sec - start_ts.tv_sec),
            cmd_cnt_per_thread * thread_num);
    }

    free_results(results);
    pka_term_local(handle);
    free(user_data);

    return NULL;
}

void *
P256worker(void *arg)
{
    pka_handle_t handle;
    pka_results_t *results;

    int worker_id = *(int *)arg;
    int max_cmd_cnt = cmd_cnt_per_thread;
    int cnt = 0;
    int cur_command_cnt = 0;
    int i;
    uint64_t test_start_time = 0, test_end_time = 0;

    struct timespec last_print, now;
    clock_gettime(CLOCK_MONOTONIC, &last_print);

    int *user_data = malloc(outstanding_cmd_num * sizeof(int));

    for (i = 0; i < outstanding_cmd_num; i++) {
        user_data[i] = i;
    }

    /* wait for all worker ready */
    pka_barrier_wait(&thread_start_barrier);

    handle = pka_init_local(instance);
    int big_endian = pka_get_rings_byte_order(handle);
    if (worker_id == 0)
        Get_P256_key_pair(handle, big_endian);

    /* wait for all worker ready */
    pka_barrier_wait(&thread_start_barrier);

#if DBG_MODE
    fprintf(stderr, "PKA Rings Byte Order: %s-endian\n",
            big_endian ? "Big" : "Little");
#endif /* DBG_MODE */

    results = malloc_results(MAX_RESULT_CNT, MAX_BYTE_LEN + 8);

#if DBG_MODE
    printf("\n\n------------------multiply----------------------\n");
    print_operand("curve.p = ", &P256_curve->p, "\n");
    print_operand("curve.a = ", &P256_curve->a, "\n");
    print_operand("curve.b = ", &P256_curve->b, "\n");
    print_operand("K2.x = ", &ec_pub_key_2->x, "\n");
    print_operand("K2.y = ", &ec_pub_key_2->y, "\n");
    print_operand("k1 = ", ec_priv_key, "\n");
    print_operand("operand_ecdh = ", operand_ecdh[cnt % 100], "\n\n");
#endif /* DBG_MODE */

    /* decrypt start */
    if (worker_id == 0) {
        test_start_time = pka_cpu_cycles();
        clock_gettime(CLOCK_MONOTONIC, &start_ts);
    }

    int pka_status = SUCCESS;
    int idx;

    while (cnt < max_cmd_cnt || cur_command_cnt > 0) {
        while (cnt < max_cmd_cnt && cur_command_cnt < outstanding_cmd_num) {
            /* send decryption request to PKA HW */
            idx = cnt % outstanding_cmd_num;

#if DBG_MODE
            if (!P256_curve->p.buf_ptr || !P256_curve->a.buf_ptr ||
                !P256_curve->b.buf_ptr) {
                fprintf(stderr, "Invalid curve!\n");
                exit(0);
            }

            if (!remote_ec_pub_key_ep[idx]->x.buf_ptr ||
                !remote_ec_pub_key_ep[idx]->y.buf_ptr ||
                !ec_priv_key[idx]->buf_ptr) {
                fprintf(stderr, "Invalid EC operands!\n");
                exit(0);
            }
#endif /* DBG_MODE */

            if ((pka_status = pka_ecc_pt_mult(
                     handle, &user_data[idx], P256_curve,
                     remote_ec_pub_key_ep[idx], ec_priv_key[idx])) < 0) {
                fprintf(stderr, "pka_ecc_pt_mult failed: status=%d\n",
                        pka_status);
                exit(0);
            }

            cnt++;
            cur_command_cnt++;
        }

        if (pka_status == FAILURE)
            fprintf(stderr, "pka cmd submittion failed\n");

        /* get result using polling */
        // while (cur_command_cnt > 0) {
        if (pka_get_result(handle, results) != SUCCESS) {
            continue;
        } else {
            if (results->status != 0) {
                fprintf(stderr, "PKA HW Operation Failed! Status: %d\n",
                        results->status);
                cur_command_cnt--;
                cmd_cnt[worker_id]++;
                continue;
            }
#if DBG_MODE
            print_operand("result 1 = ", &results->results[0], "\n\n");
            print_operand("result 2 = ", &results->results[1], "\n\n");
#endif /* DBG_MODE */

#if CHECK_CORRECTNESS
            int answer_idx = *(int *)results->user_data;

            /* check correctness */
            if (results->results[0].actual_len !=
                    remote_shared_secret_ep[answer_idx]->x.actual_len ||
                memcmp(results->results[0].buf_ptr,
                       remote_shared_secret_ep[answer_idx]->x.buf_ptr,
                       remote_shared_secret_ep[answer_idx]->x.actual_len) !=
                    0) {

                fprintf(stderr, "ECDH mismatch on X coordinate!\n");
                print_operand("PKA X = ", &results->results[0], "\n");
                print_operand("Expected X = ",
                              &remote_shared_secret_ep[answer_idx]->x, "\n");
                exit(0);
            }

            if (results->results[1].actual_len !=
                    remote_shared_secret_ep[answer_idx]->y.actual_len ||
                memcmp(results->results[1].buf_ptr,
                       remote_shared_secret_ep[answer_idx]->y.buf_ptr,
                       remote_shared_secret_ep[answer_idx]->y.actual_len) !=
                    0) {

                fprintf(stderr, "ECDH mismatch on Y coordinate!\n");
                print_operand("PKA Y = ", &results->results[1], "\n");
                print_operand("Expected Y = ",
                              &remote_shared_secret_ep[answer_idx]->y, "\n");
                exit(0);
            }
#endif /* CHECK_CORRECTNESS */

            cur_command_cnt--;
            cmd_cnt[worker_id]++;
        }
        // }

        if (worker_id == 0) {
            clock_gettime(CLOCK_MONOTONIC, &now);
            long diff = (now.tv_sec - last_print.tv_sec) * 1000000000 +
                        (now.tv_nsec - last_print.tv_nsec);

            if (diff > 1000000000) {
                PrintStatistics(diff);
                clock_gettime(CLOCK_MONOTONIC, &last_print);
            }
        }
    }

    if (worker_id == 0) {
        test_end_time = pka_cpu_cycles();
        clock_gettime(CLOCK_MONOTONIC, &end_ts);

        int cpu_frequency = pka_cpu_hz_max();
        printf("total latency: %.6f secs for %d ECDH decryption\n",
               (double)(1000000000ULL * (test_end_time - test_start_time) /
                        cpu_frequency) /
                   1e9,
               cmd_cnt_per_thread * thread_num);
        printf(
            "following to Linux timer, %f secs spent for %d ECDH decryption\n",
            (float)(end_ts.tv_nsec - start_ts.tv_nsec) / 1e9 +
                (float)(end_ts.tv_sec - start_ts.tv_sec),
            cmd_cnt_per_thread * thread_num);
    }

    free(user_data);
    free_results(results);
    pka_term_local(handle);

    return NULL;
}

void *
X25519worker(void *arg)
{
    pka_handle_t handle;
    pka_results_t *results;

    int worker_id = *(int *)arg;
    int max_cmd_cnt = cmd_cnt_per_thread;
    int cnt = 0;
    int cur_command_cnt = 0;
    int i;
    uint64_t test_start_time = 0, test_end_time = 0;

    struct timespec last_print, now;
    clock_gettime(CLOCK_MONOTONIC, &last_print);

    int *user_data = malloc(outstanding_cmd_num * sizeof(int));

    for (i = 0; i < outstanding_cmd_num; i++) {
        user_data[i] = i;
    }

    /* wait for all worker ready */
    pka_barrier_wait(&thread_start_barrier);

    handle = pka_init_local(instance);
    int big_endian = pka_get_rings_byte_order(handle);
    if (worker_id == 0)
        Get_X25519_key_pair(handle, big_endian);

    /* wait for all worker ready */
    pka_barrier_wait(&thread_start_barrier);

#if DBG_MODE
    fprintf(stderr, "PKA Rings Byte Order: %s-endian\n",
            big_endian ? "Big" : "Little");
#endif /* DBG_MODE */

    results = malloc_results(MAX_RESULT_CNT, MAX_BYTE_LEN + 8);

#if DBG_MODE
    printf("\n\n------------------multiply----------------------\n");
    print_operand("curve.p = ", &P256_curve->p, "\n");
    print_operand("curve.a = ", &P256_curve->a, "\n");
    print_operand("curve.b = ", &P256_curve->b, "\n");
    print_operand("K2.x = ", &ec_pub_key_2->x, "\n");
    print_operand("K2.y = ", &ec_pub_key_2->y, "\n");
    print_operand("k1 = ", ec_priv_key, "\n");
    print_operand("operand_ecdh = ", operand_ecdh[cnt % 100], "\n\n");
#endif /* DBG_MODE */

    /* decrypt start */
    if (worker_id == 0) {
        test_start_time = pka_cpu_cycles();
        clock_gettime(CLOCK_MONOTONIC, &start_ts);
    }

    int pka_status = SUCCESS;
    int idx;

    while (cnt < max_cmd_cnt || cur_command_cnt > 0) {
        while (cnt < max_cmd_cnt && cur_command_cnt < outstanding_cmd_num) {
            /* send decryption request to PKA HW */
            idx = cnt % outstanding_cmd_num;

#if DBG_MODE
            if (!X25519_curve->p.buf_ptr || !X25519_curve->a.buf_ptr ||
                !X25519_curve->b.buf_ptr) {
                fprintf(stderr, "Invalid curve!\n");
                exit(0);
            }

            if (!remote_ec_pub_key_po[idx]->x.buf_ptr ||
                !remote_ec_pub_key_po[idx]->y.buf_ptr ||
                !ec_priv_key[idx]->buf_ptr) {
                fprintf(stderr, "Invalid EC operands!\n");
                exit(0);
            }
#endif /* DBG_MODE */

            if ((pka_status =
                     pka_mont_ecdh_mult(handle, &user_data[idx], X25519_curve,
                                        remote_ec_pub_key_x25519[idx],
                                        ec_priv_key_x25519_0[idx])) < 0) {
                fprintf(stderr, "pka_mont_ecdh_mult failed: status=%d\n",
                        pka_status);
                exit(0);
            }

            cnt++;
            cur_command_cnt++;
        }

        if (pka_status == FAILURE)
            fprintf(stderr, "pka cmd submittion failed\n");

        /* get result using polling */
        // while (cur_command_cnt > 0) {
        if (pka_get_result(handle, results) != SUCCESS) {
            continue;
        } else {
            if (results->status != 0) {
                fprintf(stderr, "PKA HW Operation Failed! Status: %d\n",
                        results->status);
                cur_command_cnt--;
                cmd_cnt[worker_id]++;
                continue;
            }
#if DBG_MODE
            print_operand("result 1 = ", &results->results[0], "\n\n");
            print_operand("result 2 = ", &results->results[1], "\n\n");
#endif /* DBG_MODE */

#if CHECK_CORRECTNESS
            int answer_idx = *(int *)results->user_data;

            /* check correctness */
            if (results->results[0].actual_len !=
                    remote_shared_secret_po[answer_idx]->actual_len ||
                memcmp(results->results[0].buf_ptr,
                       remote_shared_secret_po[answer_idx]->buf_ptr,
                       remote_shared_secret_po[answer_idx]->actual_len) != 0) {

                fprintf(stderr, "ECDH mismatch on X coordinate!\n");
                print_operand("PKA shared secret = ", &results->results[0],
                              "\n");
                print_operand("Expected shared secret = ",
                              remote_shared_secret_po[answer_idx], "\n");
                exit(0);
            }
#endif /* CHECK_CORRECTNESS */

            cur_command_cnt--;
            cmd_cnt[worker_id]++;
        }
        // }

        if (worker_id == 0) {
            clock_gettime(CLOCK_MONOTONIC, &now);
            long diff = (now.tv_sec - last_print.tv_sec) * 1000000000 +
                        (now.tv_nsec - last_print.tv_nsec);

            if (diff > 1000000000) {
                PrintStatistics(diff);
                clock_gettime(CLOCK_MONOTONIC, &last_print);
            }
        }
    }

    if (worker_id == 0) {
        test_end_time = pka_cpu_cycles();
        clock_gettime(CLOCK_MONOTONIC, &end_ts);

        int cpu_frequency = pka_cpu_hz_max();
        printf("total latency: %.6f secs for %d ECDH decryption\n",
               (double)(1000000000ULL * (test_end_time - test_start_time) /
                        cpu_frequency) /
                   1e9,
               cmd_cnt_per_thread * thread_num);
        printf(
            "following to Linux timer, %f secs spent for %d ECDH decryption\n",
            (float)(end_ts.tv_nsec - start_ts.tv_nsec) / 1e9 +
                (float)(end_ts.tv_sec - start_ts.tv_sec),
            cmd_cnt_per_thread * thread_num);
    }

    free(user_data);
    free_results(results);
    pka_term_local(handle);

    return NULL;
}

void *
ECDSAworker(void *arg)
{
    pka_handle_t handle;
    pka_results_t *results;

    int worker_id = *(int *)arg;
    int max_cmd_cnt = cmd_cnt_per_thread;
    int cnt = 0;
    int cur_command_cnt = 0;
    int i;
    uint64_t test_start_time = 0, test_end_time = 0;

    struct timespec last_print, now;
    clock_gettime(CLOCK_MONOTONIC, &last_print);

    int *user_data = malloc(outstanding_cmd_num * sizeof(int));

    for (i = 0; i < outstanding_cmd_num; i++) {
        user_data[i] = i;
    }

    /* wait for all worker ready */
    pka_barrier_wait(&thread_start_barrier);

    handle = pka_init_local(instance);
    int big_endian = pka_get_rings_byte_order(handle);
    if (worker_id == 0)
        Get_ECDSA_key_pair(handle, big_endian);

    /* wait for all worker ready */
    pka_barrier_wait(&thread_start_barrier);

#if DBG_MODE
    fprintf(stderr, "PKA Rings Byte Order: %s-endian\n",
            big_endian ? "Big" : "Little");
#endif /* DBG_MODE */

    results = malloc_results(MAX_RESULT_CNT, MAX_BYTE_LEN + 8);

#if DBG_MODE
    printf("\n\n------------------multiply----------------------\n");
    print_operand("curve.p = ", &P256_curve->p, "\n");
    print_operand("curve.a = ", &P256_curve->a, "\n");
    print_operand("curve.b = ", &P256_curve->b, "\n");
    print_operand("K2.x = ", &ec_pub_key_2->x, "\n");
    print_operand("K2.y = ", &ec_pub_key_2->y, "\n");
    print_operand("k1 = ", ec_priv_key, "\n");
    print_operand("operand_ecdh = ", operand_ecdh[cnt % 100], "\n\n");
#endif /* DBG_MODE */

    /* decrypt start */
    if (worker_id == 0) {
        test_start_time = pka_cpu_cycles();
        clock_gettime(CLOCK_MONOTONIC, &start_ts);
    }

    int pka_status = SUCCESS;
    int idx;

    while (cnt < max_cmd_cnt || cur_command_cnt > 0) {
        while (cnt < max_cmd_cnt && cur_command_cnt < outstanding_cmd_num) {
            /* send decryption request to PKA HW */
            idx = cnt % outstanding_cmd_num;

#if DBG_MODE
            if (!X25519_curve->p.buf_ptr || !X25519_curve->a.buf_ptr ||
                !X25519_curve->b.buf_ptr) {
                fprintf(stderr, "Invalid curve!\n");
                exit(0);
            }

            if (!remote_ec_pub_key[idx]->x.buf_ptr ||
                !remote_ec_pub_key[idx]->y.buf_ptr ||
                !ec_priv_key[idx]->buf_ptr) {
                fprintf(stderr, "Invalid EC operands!\n");
                exit(0);
            }
#endif /* DBG_MODE */

            if ((pka_status = pka_ecdsa_signature_generate(
                     handle, &user_data[idx], P256_curve, P256_base_pt,
                     P256_base_pt_order, ec_priv_key[idx], hash[idx], k[idx])) <
                0) {
                fprintf(stderr,
                        "pka_ecdsa_signature_generate failed: status=%d\n",
                        pka_status);
                exit(0);
            }

            cnt++;
            cur_command_cnt++;
        }

        if (pka_status == FAILURE)
            fprintf(stderr, "pka cmd submittion failed\n");

        /* get result using polling */
        // while (cur_command_cnt > 0) {
        if (pka_get_result(handle, results) != SUCCESS) {
            continue;
        } else {
            if (results->status != 0) {
                fprintf(stderr, "PKA HW Operation Failed! Status: %d\n",
                        results->status);
                cur_command_cnt--;
                cmd_cnt[worker_id]++;
                continue;
            }
#if DBG_MODE
            print_operand("result 1 = ", &results->results[0], "\n\n");
            print_operand("result 2 = ", &results->results[1], "\n\n");
#endif /* DBG_MODE */

#if CHECK_CORRECTNESS
            int answer_idx = *(int *)results->user_data;

            /* check correctness
             * (in ECDSA correctness check, we don't check the actual_len)
             * (because, answer's actual_len is the real_len, 31 and
             * )*/

            if (memcmp(results->results[0].buf_ptr,
                       answer[answer_idx]->r.buf_ptr,
                       answer[answer_idx]->r.actual_len) != 0) {

                fprintf(stderr, "ECDSA mismatch on r!\n");

                fprintf(stderr, "resutls actual len=%u, answer len=%u\n",
                        results->results[0].actual_len,
                        answer[answer_idx]->r.actual_len);

                print_operand("PKA X = ", &results->results[0], "\n");
                print_operand("Expected X = ", &answer[answer_idx]->r, "\n");
                exit(0);
            }

            if (memcmp(results->results[1].buf_ptr,
                       answer[answer_idx]->s.buf_ptr,
                       answer[answer_idx]->s.actual_len) != 0) {

                fprintf(stderr, "ECDSA mismatch on s!\n");

                fprintf(stderr, "resutls actual len=%u, answer len=%u\n",
                        results->results[1].actual_len,
                        answer[answer_idx]->s.actual_len);

                print_operand("PKA Y = ", &results->results[1], "\n");
                print_operand("Expected Y = ", &answer[answer_idx]->s, "\n");
                exit(0);
            }
#endif /* CHECK_CORRECTNESS */

            cur_command_cnt--;
            cmd_cnt[worker_id]++;
        }
        // }

        if (worker_id == 0) {
            clock_gettime(CLOCK_MONOTONIC, &now);
            long diff = (now.tv_sec - last_print.tv_sec) * 1000000000 +
                        (now.tv_nsec - last_print.tv_nsec);

            if (diff > 1000000000) {
                PrintStatistics(diff);
                clock_gettime(CLOCK_MONOTONIC, &last_print);
            }
        }
    }

    if (worker_id == 0) {
        test_end_time = pka_cpu_cycles();
        clock_gettime(CLOCK_MONOTONIC, &end_ts);

        int cpu_frequency = pka_cpu_hz_max();
        printf("total latency: %.6f secs for %d ECDH decryption\n",
               (double)(1000000000ULL * (test_end_time - test_start_time) /
                        cpu_frequency) /
                   1e9,
               cmd_cnt_per_thread * thread_num);
        printf(
            "following to Linux timer, %f secs spent for %d ECDH decryption\n",
            (float)(end_ts.tv_nsec - start_ts.tv_nsec) / 1e9 +
                (float)(end_ts.tv_sec - start_ts.tv_sec),
            cmd_cnt_per_thread * thread_num);
    }

    free(user_data);
    free_results(results);
    pka_term_local(handle);

    return NULL;
}

void *
TLS13worker(void *arg)
{
    pka_handle_t handle;
    pka_results_t *results;

    int worker_id = *(int *)arg;
    int max_cmd_cnt = cmd_cnt_per_thread;
    int cnt = 0;
    int cur_command_cnt = 0;
    int i, idx, ret;
    uint64_t test_start_time = 0, test_end_time = 0;

    struct timespec last_print, now;
    clock_gettime(CLOCK_MONOTONIC, &last_print);

    int *user_data = malloc(1048576 * sizeof(int));

    for (i = 0; i < 1048576; i++) {
        user_data[i] = i;
    }

    /* wait for all worker ready */
    pka_barrier_wait(&thread_start_barrier);

    handle = pka_init_local(instance);
    int big_endian = pka_get_rings_byte_order(handle);
    if (worker_id == 0) {
        Get_ECDSA_key_pair(handle, big_endian);
        Get_X25519_key_pair(handle, big_endian);
    }

    /* wait for all worker ready */
    pka_barrier_wait(&thread_start_barrier);

#if DBG_MODE
    fprintf(stderr, "PKA Rings Byte Order: %s-endian\n",
            big_endian ? "Big" : "Little");
#endif /* DBG_MODE */

    results = malloc_results(MAX_RESULT_CNT, MAX_BYTE_LEN + 8);

#if DBG_MODE
    printf("\n\n------------------multiply----------------------\n");
    print_operand("curve.p = ", &P256_curve->p, "\n");
    print_operand("curve.a = ", &P256_curve->a, "\n");
    print_operand("curve.b = ", &P256_curve->b, "\n");
    print_operand("K2.x = ", &ec_pub_key_2->x, "\n");
    print_operand("K2.y = ", &ec_pub_key_2->y, "\n");
    print_operand("k1 = ", ec_priv_key, "\n");
    print_operand("operand_ecdh = ", operand_ecdh[cnt % 100], "\n\n");
#endif /* DBG_MODE */

    /* decrypt start */
    if (worker_id == 0) {
        test_start_time = pka_cpu_cycles();
        clock_gettime(CLOCK_MONOTONIC, &start_ts);
    }

    int pka_status = SUCCESS;

    while (cnt < max_cmd_cnt || cur_command_cnt > 0) {
        while (cnt < max_cmd_cnt && cur_command_cnt < outstanding_cmd_num) {
            /* send decryption request to PKA HW */
            idx = cnt % outstanding_cmd_num;

#if DBG_MODE
            if (!X25519_curve->p.buf_ptr || !X25519_curve->a.buf_ptr ||
                !X25519_curve->b.buf_ptr) {
                fprintf(stderr, "Invalid curve!\n");
                exit(0);
            }

            if (!remote_ec_pub_key[idx]->x.buf_ptr ||
                !remote_ec_pub_key[idx]->y.buf_ptr ||
                !ec_priv_key[idx]->buf_ptr) {
                fprintf(stderr, "Invalid EC operands!\n");
                exit(0);
            }
#endif /* DBG_MODE */

            if (!(cnt % 3)) {
                /* ECDSA sign */
#if RAND_OPERAND_0
#if !PKA_RNG
                rand_non_zero_integer_wo_syscall_32bytes(handle, hash[idx]);
#else  /* PKA_RNG */
                // pka_get_rand_bytes(handle,
                // 				   hash[idx]->buf_ptr,
                // 				   32);
#endif /* PKA_RNG */
#endif /* RAND_OPERAND_0 */

#if RAND_OPERAND_1
#if !PKA_RNG
                rand_non_zero_integer_wo_syscall_32bytes(handle, k[idx]);
#else  /* PKA_RNG */
                // pka_get_rand_bytes(handle,
                // 					k[idx]->buf_ptr,
                // 					32);
#endif /* PKA_RNG */
#endif /* RAND_OPERAND_1 */

                if ((pka_status = pka_ecdsa_signature_generate(
                         handle, &user_data[rand() % 1048576], P256_curve,
                         P256_base_pt, P256_base_pt_order, ec_priv_key[idx],
                         hash[idx], k[idx])) < 0) {
                    fprintf(stderr,
                            "pka_ecdsa_signature_generate failed: status=%d\n",
                            pka_status);
                    exit(0);
                }
            } else if (!((cnt + 1) % 3)) {
                /* X25519 ECDHE */
#if RAND_OPERAND_0
#if !PKA_RNG
                rand_non_zero_integer_wo_syscall(
                    handle, ec_priv_key_x25519_0[idx], C255_base_pt_order);
#else  /* PKA_RNG */
                rand_non_zero_integer_w_pka_hwrng_and_clamping(
                    handle, ec_priv_key_x25519_0[idx], C255_base_pt_order);
#endif /* PKA_RNG */
#endif /* RAND_OPERAND_0 */
                if ((pka_status = pka_mont_ecdh_mult(
                         handle, &user_data[rand() % 1048576], X25519_curve,
                         remote_ec_pub_key_x25519[idx],
                         ec_priv_key_x25519_0[idx])) < 0) {
                    fprintf(stderr, "pka_mont_ecdh_mult failed: status=%d\n",
                            pka_status);
                    exit(0);
                }
            } else {
                /* X25519 shared secret calc. */
#if RAND_OPERAND_1
#if !PKA_RNG
                rand_non_zero_integer_wo_syscall(
                    handle, ec_priv_key_x25519_1[idx], C255_base_pt_order);
#else  /* PKA_RNG */
                // pka_get_rand_bytes(handle,
                // 				   ec_priv_key_x25519_1[idx]->buf_ptr,
                // 				   32);
#endif /* PKA_RNG */
#endif /* RAND_OPERAND_1 */

                if ((pka_status = pka_mont_ecdh_mult(
                         handle, &user_data[rand() % 1048576], X25519_curve,
                         remote_ec_pub_key_x25519[idx],
                         ec_priv_key_x25519_1[idx])) < 0) {
                    fprintf(stderr, "pka_mont_ecdh_mult failed: status=%d\n",
                            pka_status);
                    exit(0);
                }
            }

            cnt++;
            cur_command_cnt++;
        }

        if (pka_status == FAILURE)
            fprintf(stderr, "pka cmd submittion failed\n");

        /* get result using polling */
        while (cur_command_cnt > 0) {
            uint64_t start = rte_rdtsc();
            ret = pka_get_result(handle, results);
            uint64_t end = rte_rdtsc();

            uint64_t diff = end - start;
            if (diff < pka_get_result_min)
                pka_get_result_min = diff;
            if (diff > pka_get_result_max)
                pka_get_result_max = diff;
            pka_get_result_sum += diff;
            pka_get_result_cnt++;

            if (unlikely(ret == FAILURE))
                pka_get_result_fail_cnt++;
            else
                pka_get_result_success_cnt++;

            if (ret != SUCCESS) {
                break;
            } else {
                if (results->status != 0) {
                    fprintf(stderr, "PKA HW Operation Failed! Status: %d\n",
                            results->status);
                    cur_command_cnt--;
                    continue;
                }
#if DBG_MODE
                print_operand("result 1 = ", &results->results[0], "\n\n");
                print_operand("result 2 = ", &results->results[1], "\n\n");
#endif /* DBG_MODE */

#if CHECK_CORRECTNESS && !(RAND_OPERAND_0 || RAND_OPERAND_1)
                int answer_idx = *(int *)results->user_data;

                /* check correctness */
                if (results->opcode == CC_ECDSA_GENERATE) {
                    if (memcmp(results->results[0].buf_ptr,
                               answer[answer_idx]->r.buf_ptr,
                               answer[answer_idx]->r.actual_len) != 0) {

                        fprintf(stderr, "ECDSA mismatch on r!\n");

                        fprintf(stderr,
                                "resutls actual len=%u, answer len=%u\n",
                                results->results[0].actual_len,
                                answer[answer_idx]->r.actual_len);

                        print_operand("PKA X = ", &results->results[0], "\n");
                        print_operand("Expected X = ", &answer[answer_idx]->r,
                                      "\n");
                        exit(0);
                    }

                    if (memcmp(results->results[1].buf_ptr,
                               answer[answer_idx]->s.buf_ptr,
                               answer[answer_idx]->s.actual_len) != 0) {

                        fprintf(stderr, "ECDSA mismatch on s!\n");

                        fprintf(stderr,
                                "resutls actual len=%u, answer len=%u\n",
                                results->results[1].actual_len,
                                answer[answer_idx]->s.actual_len);

                        print_operand("PKA Y = ", &results->results[1], "\n");
                        print_operand("Expected Y = ", &answer[answer_idx]->s,
                                      "\n");
                        exit(0);
                    }
                } else if (results->opcode == CC_MONT_ECDH_MULTIPLY) {
                    if (results->results[0].actual_len !=
                            remote_shared_secret_po[answer_idx]->actual_len ||
                        memcmp(
                            results->results[0].buf_ptr,
                            remote_shared_secret_po[answer_idx]->buf_ptr,
                            remote_shared_secret_po[answer_idx]->actual_len) !=
                            0) {

                        fprintf(stderr, "ECDH mismatch on X coordinate!\n");
                        print_operand(
                            "PKA shared secret = ", &results->results[0], "\n");
                        print_operand("Expected shared secret = ",
                                      remote_shared_secret_po[answer_idx],
                                      "\n");
                        exit(0);
                    }
                } else {
                    fprintf(stderr,
                            "Unknown opcode result for correctness check: %d\n",
                            results->opcode);
                    exit(0);
                }
#endif /* CHECK_CORRECTNESS && (!RAND_OPERAND_0 && !RAND_OPERAND_1) */

                cur_command_cnt--;

                for (int i = 0; i < results->result_cnt; i++) {
                    memcpy_results[rand() % MAX_OUTSTANDING_CMD_NUM]
                        ->results[i]
                        .buf_len = results->results[i].buf_len;

                    memcpy_results[rand() % MAX_OUTSTANDING_CMD_NUM]
                        ->results[i]
                        .actual_len = results->results[i].actual_len;

                    memcpy(memcpy_results[rand() % MAX_OUTSTANDING_CMD_NUM]
                               ->results[i]
                               .buf_ptr,
                           results->results[i].buf_ptr,
                           results->results[i].buf_len);
                }

                atomic_thread_fence(memory_order_release);

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
        }

        if (worker_id == 0) {
            clock_gettime(CLOCK_MONOTONIC, &now);
            long diff = (now.tv_sec - last_print.tv_sec) * 1000000000 +
                        (now.tv_nsec - last_print.tv_nsec);

            if (diff > 1000000000) {
                PrintStatistics(diff);
                clock_gettime(CLOCK_MONOTONIC, &last_print);

                double elapsed_sec = (now.tv_nsec - start_ts.tv_nsec) / 1e9 +
                                     (now.tv_sec - start_ts.tv_sec);

                printf("pka_get_result min=%lu, max=%lu, avg=%lu\n"
                       "pka_get_result cnt per sec=%lu, total cnt=%lu\n"
                       "pka_get_result fail cnt=%lu, success cnt=%lu\n",
                       pka_get_result_min, pka_get_result_max,
                       (pka_get_result_sum / pka_get_result_cnt),
                       (unsigned long)(pka_get_result_cnt / elapsed_sec),
                       pka_get_result_cnt, pka_get_result_fail_cnt,
                       pka_get_result_success_cnt);
            }
        }
    }

    if (worker_id == 0) {
        test_end_time = pka_cpu_cycles();
        clock_gettime(CLOCK_MONOTONIC, &end_ts);

        int cpu_frequency = pka_cpu_hz_max();
        printf("total latency: %.6f secs for %d TLS13_ASYM sessions\n",
               (double)(1000000000ULL * (test_end_time - test_start_time) /
                        cpu_frequency) /
                   1e9,
               cmd_cnt_per_thread * thread_num);
        printf("following to Linux timer, %f secs spent for %d sessions\n",
               (float)(end_ts.tv_nsec - start_ts.tv_nsec) / 1e9 +
                   (float)(end_ts.tv_sec - start_ts.tv_sec),
               cmd_cnt_per_thread * thread_num);
    }

    free(user_data);
    free_results(results);
    pka_term_local(handle);

    return NULL;
}

#if !TEST_RSA
void *
TLS13HKDFworker(void *arg)
{
    pka_handle_t handle;
    pka_results_t *results;

    int worker_id = *(int *)arg;
    int max_cmd_cnt = cmd_cnt_per_thread;
    int cnt = 0;
    int cur_command_cnt = 0;
    int i, idx, ret;
    uint64_t test_start_time = 0, test_end_time = 0;

    struct timespec last_print, now;
    clock_gettime(CLOCK_MONOTONIC, &last_print);

    int *user_data = malloc(1048576 * sizeof(int));

    for (i = 0; i < 1048576; i++) {
        user_data[i] = i;
    }

    /* wait for all worker ready */
    pka_barrier_wait(&thread_start_barrier);

    handle = pka_init_local(instance);
    int big_endian = pka_get_rings_byte_order(handle);
    if (worker_id == 0) {
        Get_ECDSA_key_pair(handle, big_endian);
        Get_X25519_key_pair(handle, big_endian);
    }

    /* wait for all worker ready */
    pka_barrier_wait(&thread_start_barrier);

#if DBG_MODE
    fprintf(stderr, "PKA Rings Byte Order: %s-endian\n",
            big_endian ? "Big" : "Little");
#endif /* DBG_MODE */

    results = malloc_results(MAX_RESULT_CNT, MAX_BYTE_LEN + 8);

#if DBG_MODE
    printf("\n\n------------------multiply----------------------\n");
    print_operand("curve.p = ", &P256_curve->p, "\n");
    print_operand("curve.a = ", &P256_curve->a, "\n");
    print_operand("curve.b = ", &P256_curve->b, "\n");
    print_operand("K2.x = ", &ec_pub_key_2->x, "\n");
    print_operand("K2.y = ", &ec_pub_key_2->y, "\n");
    print_operand("k1 = ", ec_priv_key, "\n");
    print_operand("operand_ecdh = ", operand_ecdh[cnt % 100], "\n\n");
#endif /* DBG_MODE */

    /* decrypt start */
    if (worker_id == 0) {
        test_start_time = pka_cpu_cycles();
        clock_gettime(CLOCK_MONOTONIC, &start_ts);
    }

    int pka_status = SUCCESS;

    while (cnt < max_cmd_cnt || cur_command_cnt > 0) {
        while (cnt < max_cmd_cnt && cur_command_cnt < outstanding_cmd_num) {
            /* send decryption request to PKA HW */
            idx = cnt % outstanding_cmd_num;

#if DBG_MODE
            if (!X25519_curve->p.buf_ptr || !X25519_curve->a.buf_ptr ||
                !X25519_curve->b.buf_ptr) {
                fprintf(stderr, "Invalid curve!\n");
                exit(0);
            }

            if (!remote_ec_pub_key[idx]->x.buf_ptr ||
                !remote_ec_pub_key[idx]->y.buf_ptr ||
                !ec_priv_key[idx]->buf_ptr) {
                fprintf(stderr, "Invalid EC operands!\n");
                exit(0);
            }
#endif /* DBG_MODE */

            if (!(cnt % 3)) { /* handshake msgs len: 973 */
                              /* ECDSA sign */
#if RAND_OPERAND_0
#if !PKA_RNG
                rand_non_zero_integer_wo_syscall_32bytes(handle, hash[idx]);
#else  /* PKA_RNG */
                // pka_get_rand_bytes(handle,
                // 				   hash[idx]->buf_ptr,
                // 				   32);
#endif /* PKA_RNG */
#endif /* RAND_OPERAND_0 */

#if RAND_OPERAND_1
#if !PKA_RNG
                rand_non_zero_integer_wo_syscall_32bytes(handle, k[idx]);
#else  /* PKA_RNG */
                // pka_get_rand_bytes(handle,
                // 					k[idx]->buf_ptr,
                // 					32);
#endif /* PKA_RNG */
#endif /* RAND_OPERAND_1 */

                if ((pka_status = pka_ecdsa_signature_generate(
                         handle, &user_data[rand() % 1048576], P256_curve,
                         P256_base_pt, P256_base_pt_order, ec_priv_key[idx],
                         hash[idx], k[idx])) < 0) {
                    fprintf(stderr,
                            "pka_ecdsa_signature_generate failed: status=%d\n",
                            pka_status);
                    exit(0);
                }

                /* HKDF part */
                uint8_t handshake_msgs[973] = {
                    0}; /* dummy handshake messages */
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

                SHA384(handshake_msgs, 973, handshake_hash);

                if (hkdf_expand_label(derived_secret, 48, handshake_secret, 48,
                                      (unsigned char *)"derived",
                                      strlen("derived"), empty_hash, 48,
                                      EVP_sha384()) == 0) {
                    fprintf(stderr, "hkdf_expand_label failed!\n");
                    return NULL;
                }

                if (hkdf_extract(master_secret, 48, derived_secret, 48,
                                 empty_salt, 48, EVP_sha384()) == 0) {
                    fprintf(stderr, "hkdf_extract failed!\n");
                    return NULL;
                }

                if (hkdf_expand_label(app_client_secret, 48, master_secret, 48,
                                      (unsigned char *)"c ap traffic",
                                      strlen("c ap traffic"), handshake_hash,
                                      48, EVP_sha384()) == 0) {
                    fprintf(stderr, "hkdf_expand_label failed!\n");
                    return NULL;
                }

                if (hkdf_expand_label(app_server_secret, 48, master_secret, 48,
                                      (unsigned char *)"s ap traffic",
                                      strlen("s ap traffic"), handshake_hash,
                                      48, EVP_sha384()) == 0) {
                    fprintf(stderr, "hkdf_expand_label failed!\n");
                    return NULL;
                }

                if (hkdf_expand_label(
                        client_application_key, 32, app_client_secret, 48,
                        (unsigned char *)"key", strlen("key"),
                        (unsigned char *)"", 0, EVP_sha384()) == 0) {
                    fprintf(stderr, "hkdf_expand_label failed!\n");
                    return NULL;
                }

                if (hkdf_expand_label(
                        server_application_key, 32, app_server_secret, 48,
                        (unsigned char *)"key", strlen("key"),
                        (unsigned char *)"", 0, EVP_sha384()) == 0) {
                    fprintf(stderr, "hkdf_expand_label failed!\n");
                    return NULL;
                }

                if (hkdf_expand_label(
                        client_application_iv, 12, app_client_secret, 48,
                        (unsigned char *)"iv", strlen("iv"),
                        (unsigned char *)"", 0, EVP_sha384()) == 0) {
                    fprintf(stderr, "hkdf_expand_label failed!\n");
                    return NULL;
                }

                if (hkdf_expand_label(
                        server_application_iv, 12, app_server_secret, 48,
                        (unsigned char *)"iv", strlen("iv"),
                        (unsigned char *)"", 0, EVP_sha384()) == 0) {
                    fprintf(stderr, "hkdf_expand_label failed!\n");
                    return NULL;
                }

            } else if (!((cnt + 1) % 3)) { /* handshake msgs len: 338 */
                                           /* X25519 ECDHE */
#if RAND_OPERAND_0
#if !PKA_RNG
                rand_non_zero_integer_wo_syscall(
                    handle, ec_priv_key_x25519_0[idx], C255_base_pt_order);
#else  /* PKA_RNG */
                rand_non_zero_integer_w_pka_hwrng_and_clamping(
                    handle, ec_priv_key_x25519_0[idx], C255_base_pt_order);
#endif /* PKA_RNG */
#endif /* RAND_OPERAND_0 */
                if ((pka_status = pka_mont_ecdh_mult(
                         handle, &user_data[rand() % 1048576], X25519_curve,
                         remote_ec_pub_key_x25519[idx],
                         ec_priv_key_x25519_0[idx])) < 0) {
                    fprintf(stderr, "pka_mont_ecdh_mult failed: status=%d\n",
                            pka_status);
                    exit(0);
                }

                /* HKDF part */
                uint8_t handshake_msgs[338] = {
                    0}; /* dummy handshake messages */
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

                SHA384(handshake_msgs, 338, hello_hash);

                if (hkdf_extract(early_secret, 48, early_secret_salt, 48,
                                 early_secret_salt, 48, EVP_sha384()) == 0) {
                    fprintf(stderr, "hkdf_extract failed!\n");
                    return NULL;
                }

                SHA384(NULL, 0, empty_hash);

                if (hkdf_expand_label(derived_secret, 48, early_secret, 48,
                                      (unsigned char *)"derived",
                                      strlen("derived"), empty_hash, 48,
                                      EVP_sha384()) == 0) {
                    fprintf(stderr, "hkdf_expand_label failed!\n");
                    return NULL;
                }

                if (hkdf_extract(handshake_secret, 48, derived_secret, 48,
                                 shared_secret, 32, EVP_sha384()) == 0) {
                    fprintf(stderr, "hkdf_extract failed!\n");
                    return NULL;
                }

                if (hkdf_expand_label(client_secret, 48, handshake_secret, 48,
                                      (unsigned char *)"c hs traffic",
                                      strlen("c hs traffic"), hello_hash, 48,
                                      EVP_sha384()) == 0) {
                    fprintf(stderr, "hkdf_expand_label failed!\n");
                    return NULL;
                }

                if (hkdf_expand_label(server_secret, 48, handshake_secret, 48,
                                      (unsigned char *)"s hs traffic",
                                      strlen("s hs traffic"), hello_hash, 48,
                                      EVP_sha384()) == 0) {
                    fprintf(stderr, "hkdf_expand_label failed!\n");
                    return NULL;
                }

                if (hkdf_expand_label(client_handshake_key, 32, client_secret,
                                      48, (unsigned char *)"key", strlen("key"),
                                      (unsigned char *)"", 0,
                                      EVP_sha384()) == 0) {
                    fprintf(stderr, "hkdf_expand_label failed!\n");
                    return NULL;
                }

                if (hkdf_expand_label(server_handshake_key, 32, server_secret,
                                      48, (unsigned char *)"key", strlen("key"),
                                      (unsigned char *)"", 0,
                                      EVP_sha384()) == 0) {
                    fprintf(stderr, "hkdf_expand_label failed!\n");
                    return NULL;
                }

                if (hkdf_expand_label(client_handshake_iv, 12, client_secret,
                                      48, (unsigned char *)"iv", strlen("iv"),
                                      (unsigned char *)"", 0,
                                      EVP_sha384()) == 0) {
                    fprintf(stderr, "hkdf_expand_label failed!\n");
                    return NULL;
                }

                if (hkdf_expand_label(server_handshake_iv, 12, server_secret,
                                      48, (unsigned char *)"iv", strlen("iv"),
                                      (unsigned char *)"", 0,
                                      EVP_sha384()) == 0) {
                    fprintf(stderr, "hkdf_expand_label failed!\n");
                    return NULL;
                }
            } else {
                /* X25519 shared secret calc. */
#if RAND_OPERAND_1
#if !PKA_RNG
                rand_non_zero_integer_wo_syscall(
                    handle, ec_priv_key_x25519_1[idx], C255_base_pt_order);
#else  /* PKA_RNG */
                // pka_get_rand_bytes(handle,
                // 				   ec_priv_key_x25519_1[idx]->buf_ptr,
                // 				   32);
#endif /* PKA_RNG */
#endif /* RAND_OPERAND_1 */

                if ((pka_status = pka_mont_ecdh_mult(
                         handle, &user_data[rand() % 1048576], X25519_curve,
                         remote_ec_pub_key_x25519[idx],
                         ec_priv_key_x25519_1[idx])) < 0) {
                    fprintf(stderr, "pka_mont_ecdh_mult failed: status=%d\n",
                            pka_status);
                    exit(0);
                }
            }

            cnt++;
            cur_command_cnt++;
        }

        if (pka_status == FAILURE)
            fprintf(stderr, "pka cmd submittion failed\n");

        /* get result using polling */
        while (cur_command_cnt > 0) {
            uint64_t start = rte_rdtsc();
            ret = pka_get_result(handle, results);
            uint64_t end = rte_rdtsc();

            uint64_t diff = end - start;
            if (diff < pka_get_result_min)
                pka_get_result_min = diff;
            if (diff > pka_get_result_max)
                pka_get_result_max = diff;
            pka_get_result_sum += diff;
            pka_get_result_cnt++;

            if (unlikely(ret == FAILURE))
                pka_get_result_fail_cnt++;
            else
                pka_get_result_success_cnt++;

            if (ret != SUCCESS) {
                break;
            } else {
                if (results->status != 0) {
                    fprintf(stderr, "PKA HW Operation Failed! Status: %d\n",
                            results->status);
                    cur_command_cnt--;
                    continue;
                }
#if DBG_MODE
                print_operand("result 1 = ", &results->results[0], "\n\n");
                print_operand("result 2 = ", &results->results[1], "\n\n");
#endif /* DBG_MODE */

#if CHECK_CORRECTNESS && !(RAND_OPERAND_0 || RAND_OPERAND_1)
                int answer_idx = *(int *)results->user_data;

                /* check correctness */
                if (results->opcode == CC_ECDSA_GENERATE) {
                    if (memcmp(results->results[0].buf_ptr,
                               answer[answer_idx]->r.buf_ptr,
                               answer[answer_idx]->r.actual_len) != 0) {

                        fprintf(stderr, "ECDSA mismatch on r!\n");

                        fprintf(stderr,
                                "resutls actual len=%u, answer len=%u\n",
                                results->results[0].actual_len,
                                answer[answer_idx]->r.actual_len);

                        print_operand("PKA X = ", &results->results[0], "\n");
                        print_operand("Expected X = ", &answer[answer_idx]->r,
                                      "\n");
                        exit(0);
                    }

                    if (memcmp(results->results[1].buf_ptr,
                               answer[answer_idx]->s.buf_ptr,
                               answer[answer_idx]->s.actual_len) != 0) {

                        fprintf(stderr, "ECDSA mismatch on s!\n");

                        fprintf(stderr,
                                "resutls actual len=%u, answer len=%u\n",
                                results->results[1].actual_len,
                                answer[answer_idx]->s.actual_len);

                        print_operand("PKA Y = ", &results->results[1], "\n");
                        print_operand("Expected Y = ", &answer[answer_idx]->s,
                                      "\n");
                        exit(0);
                    }
                } else if (results->opcode == CC_MONT_ECDH_MULTIPLY) {
                    if (results->results[0].actual_len !=
                            remote_shared_secret_po[answer_idx]->actual_len ||
                        memcmp(
                            results->results[0].buf_ptr,
                            remote_shared_secret_po[answer_idx]->buf_ptr,
                            remote_shared_secret_po[answer_idx]->actual_len) !=
                            0) {

                        fprintf(stderr, "ECDH mismatch on X coordinate!\n");
                        print_operand(
                            "PKA shared secret = ", &results->results[0], "\n");
                        print_operand("Expected shared secret = ",
                                      remote_shared_secret_po[answer_idx],
                                      "\n");
                        exit(0);
                    }
                } else {
                    fprintf(stderr,
                            "Unknown opcode result for correctness check: %d\n",
                            results->opcode);
                    exit(0);
                }
#endif /* CHECK_CORRECTNESS && (!RAND_OPERAND_0 && !RAND_OPERAND_1) */

                cur_command_cnt--;

                for (int i = 0; i < results->result_cnt; i++) {
                    memcpy_results[rand() % MAX_OUTSTANDING_CMD_NUM]
                        ->results[i]
                        .buf_len = results->results[i].buf_len;

                    memcpy_results[rand() % MAX_OUTSTANDING_CMD_NUM]
                        ->results[i]
                        .actual_len = results->results[i].actual_len;

                    memcpy(memcpy_results[rand() % MAX_OUTSTANDING_CMD_NUM]
                               ->results[i]
                               .buf_ptr,
                           results->results[i].buf_ptr,
                           results->results[i].buf_len);
                }

                atomic_thread_fence(memory_order_release);

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
        }

        if (worker_id == 0) {
            clock_gettime(CLOCK_MONOTONIC, &now);
            long diff = (now.tv_sec - last_print.tv_sec) * 1000000000 +
                        (now.tv_nsec - last_print.tv_nsec);

            if (diff > 1000000000) {
                PrintStatistics(diff);
                clock_gettime(CLOCK_MONOTONIC, &last_print);

                double elapsed_sec = (now.tv_nsec - start_ts.tv_nsec) / 1e9 +
                                     (now.tv_sec - start_ts.tv_sec);

                printf("pka_get_result min=%lu, max=%lu, avg=%lu\n"
                       "pka_get_result cnt per sec=%lu, total cnt=%lu\n"
                       "pka_get_result fail cnt=%lu, success cnt=%lu\n",
                       pka_get_result_min, pka_get_result_max,
                       (pka_get_result_sum / pka_get_result_cnt),
                       (unsigned long)(pka_get_result_cnt / elapsed_sec),
                       pka_get_result_cnt, pka_get_result_fail_cnt,
                       pka_get_result_success_cnt);
            }
        }
    }

    if (worker_id == 0) {
        test_end_time = pka_cpu_cycles();
        clock_gettime(CLOCK_MONOTONIC, &end_ts);

        int cpu_frequency = pka_cpu_hz_max();
        printf("total latency: %.6f secs for %d TLS13 PKA ops\n",
               (double)(1000000000ULL * (test_end_time - test_start_time) /
                        cpu_frequency) /
                   1e9,
               cmd_cnt_per_thread * thread_num);
        printf("following to Linux timer, %f secs spent for %d TLS13 sess\n",
               (float)(end_ts.tv_nsec - start_ts.tv_nsec) / 1e9 +
                   (float)(end_ts.tv_sec - start_ts.tv_sec),
               cmd_cnt_per_thread * thread_num);
    }

    free(user_data);
    free_results(results);
    pka_term_local(handle);

    return NULL;
}
#endif /* !TEST_RSA */

void *
RANDworker(void *arg)
{
    pka_handle_t handle;

    int worker_id = *(int *)arg;
    int max_cmd_cnt = cmd_cnt_per_thread;
    int cnt = 0;
    int cur_command_cnt = 0;
    int idx;
    int ret = 1;
    uint64_t test_start_time = 0, test_end_time = 0;

    struct timespec last_print, now;
    clock_gettime(CLOCK_MONOTONIC, &last_print);

    /* wait for all worker ready */
    pka_barrier_wait(&thread_start_barrier);

    handle = pka_init_local(instance);
    int big_endian = pka_get_rings_byte_order(handle);
    if (worker_id == 0) {
        Get_X25519_key_pair(handle, big_endian);
    }

    /* wait for all worker ready */
    pka_barrier_wait(&thread_start_barrier);

    /* decrypt start */
    if (worker_id == 0) {
        test_start_time = pka_cpu_cycles();
        clock_gettime(CLOCK_MONOTONIC, &start_ts);
    }

    while (cnt < max_cmd_cnt || cur_command_cnt > 0) {
        /* send decryption request to PKA HW */
        idx = cnt % outstanding_cmd_num;

#if !PKA_RNG
        rand_non_zero_integer_wo_syscall_32bytes(handle,
                                                 ec_priv_key_x25519_0[idx]);
#else  /* PKA_RNG */
        ret =
            pka_get_rand_bytes(handle, ec_priv_key_x25519_0[idx]->buf_ptr, 32);
#endif /* PKA_RNG */

        cnt++;
        cur_command_cnt++;

        if (!ret)
            fprintf(stderr, "pka_get_rand_bytes failed\n");

        cmd_cnt[worker_id]++;

        if (worker_id == 0) {
            clock_gettime(CLOCK_MONOTONIC, &now);
            long diff = (now.tv_sec - last_print.tv_sec) * 1000000000 +
                        (now.tv_nsec - last_print.tv_nsec);

            if (diff > 1000000000) {
                PrintStatistics(diff);
                clock_gettime(CLOCK_MONOTONIC, &last_print);
            }
        }
    }

    if (worker_id == 0) {
        test_end_time = pka_cpu_cycles();
        clock_gettime(CLOCK_MONOTONIC, &end_ts);

        int cpu_frequency = pka_cpu_hz_max();
        printf("total latency: %.6f secs for generating %d rand ops\n",
               (double)(1000000000ULL * (test_end_time - test_start_time) /
                        cpu_frequency) /
                   1e9,
               cmd_cnt_per_thread * thread_num);
        printf("following to Linux timer, %f secs spent for %d rand ops\n",
               (float)(end_ts.tv_nsec - start_ts.tv_nsec) / 1e9 +
                   (float)(end_ts.tv_sec - start_ts.tv_sec),
               cmd_cnt_per_thread * thread_num);
    }

    pka_term_local(handle);

    return NULL;
}

void *
Producer(void *arg)
{
    UNUSED(arg);

    uint64_t cnt = 0;

    struct timespec last_print;
    clock_gettime(CLOCK_MONOTONIC, &last_print);

    int *user_data = malloc(1048576 * sizeof(int));

    for (int i = 0; i < 1048576; i++) {
        user_data[i] = i;
    }

    ck_ring_init(&submit_pka_ring, MAX_OUTSTANDING_CMD_NUM * 2);

    /* wait for all worker ready */
    pka_barrier_wait(&thread_start_barrier);
    pka_barrier_wait(&thread_start_barrier);

    while (1) {
        if (ck_ring_size(&submit_pka_ring) >=
            (unsigned int)outstanding_cmd_num) {
            continue;
        } else {
            ck_ring_enqueue_spsc(&submit_pka_ring, submit_pka_ring_buffer,
                                 (void *)&user_data[cnt % 1048576]);
        }
        cnt++;
    }

    free(user_data);

    return NULL;
}

void *
Consumer(void *arg)
{
    pka_handle_t handle;
    pka_results_t *results;

    int worker_id = *(int *)arg;
    int max_cmd_cnt = cmd_cnt_per_thread;
    int cnt = 0;
    int cur_command_cnt = 0;
    int idx, ret;
    uint64_t test_start_time = 0, test_end_time = 0;

    struct timespec last_print, now;
    clock_gettime(CLOCK_MONOTONIC, &last_print);

    int *user_data = calloc(1, sizeof(int));

    /* wait for all worker ready */
    pka_barrier_wait(&thread_start_barrier);

    handle = pka_init_local(instance);
    int big_endian = pka_get_rings_byte_order(handle);
    fprintf(stderr, "Consumer worker_id=%d big_endian=%d\n", worker_id,
            big_endian);

    Get_ECDSA_key_pair(handle, big_endian);
    Get_X25519_key_pair(handle, big_endian);

    /* wait for all worker ready */
    pka_barrier_wait(&thread_start_barrier);

#if DBG_MODE
    fprintf(stderr, "PKA Rings Byte Order: %s-endian\n",
            big_endian ? "Big" : "Little");
#endif /* DBG_MODE */

    results = malloc_results(MAX_RESULT_CNT, MAX_BYTE_LEN + 8);

#if DBG_MODE
    printf("\n\n------------------multiply----------------------\n");
    print_operand("curve.p = ", &P256_curve->p, "\n");
    print_operand("curve.a = ", &P256_curve->a, "\n");
    print_operand("curve.b = ", &P256_curve->b, "\n");
    print_operand("K2.x = ", &ec_pub_key_2->x, "\n");
    print_operand("K2.y = ", &ec_pub_key_2->y, "\n");
    print_operand("k1 = ", ec_priv_key, "\n");
    print_operand("operand_ecdh = ", operand_ecdh[cnt % 100], "\n\n");
#endif /* DBG_MODE */

    /* decrypt start */
    test_start_time = pka_cpu_cycles();
    clock_gettime(CLOCK_MONOTONIC, &start_ts);

    int pka_status = SUCCESS;

    while (cnt < max_cmd_cnt || cur_command_cnt > 0) {
        while (cnt < max_cmd_cnt && cur_command_cnt < outstanding_cmd_num) {
            /* send decryption request to PKA HW */
            idx = cnt % outstanding_cmd_num;

#if DBG_MODE
            if (!X25519_curve->p.buf_ptr || !X25519_curve->a.buf_ptr ||
                !X25519_curve->b.buf_ptr) {
                fprintf(stderr, "Invalid curve!\n");
                exit(0);
            }

            if (!remote_ec_pub_key[idx]->x.buf_ptr ||
                !remote_ec_pub_key[idx]->y.buf_ptr ||
                !ec_priv_key[idx]->buf_ptr) {
                fprintf(stderr, "Invalid EC operands!\n");
                exit(0);
            }
#endif /* DBG_MODE */

            int ret = ck_ring_dequeue_spsc(
                &submit_pka_ring, submit_pka_ring_buffer, (void **)&user_data);

            if (ret < 0)
                break;

            if (!(cnt % 3)) {
                /* ECDSA sign */
#if RAND_OPERAND_0
#if !PKA_RNG
                rand_non_zero_integer_wo_syscall_32bytes(handle, hash[idx]);
#else  /* PKA_RNG */
                pka_get_rand_bytes(handle, hash[idx]->buf_ptr, 32);
#endif /* PKA_RNG */
#endif /* RAND_OPERAND_0 */

#if RAND_OPERAND_1
#if !PKA_RNG
                rand_non_zero_integer_wo_syscall_32bytes(handle, k[idx]);
#else  /* PKA_RNG */
                pka_get_rand_bytes(handle, k[idx]->buf_ptr, 32);
#endif /* PKA_RNG */
#endif /* RAND_OPERAND_1 */

                if ((pka_status = pka_ecdsa_signature_generate(
                         handle, &user_data[rand() % 1048576], P256_curve,
                         P256_base_pt, P256_base_pt_order, ec_priv_key[idx],
                         hash[idx], k[idx])) < 0) {
                    fprintf(stderr,
                            "pka_ecdsa_signature_generate failed: status=%d\n",
                            pka_status);
                    exit(0);
                }
            } else if (!((cnt + 1) % 3)) {
                /* X25519 ECDHE */
#if RAND_OPERAND_0
#if !PKA_RNG
                rand_non_zero_integer_wo_syscall(
                    handle, ec_priv_key_x25519_0[idx], C255_base_pt_order);
#else  /* PKA_RNG */
                // pka_get_rand_bytes(handle,
                // 				   ec_priv_key_x25519_0[idx]->buf_ptr,
                // 				   operand_byte_len(C255_base_pt_order));
                rand_non_zero_integer_w_pka_hwrng_and_clamping(
                    handle, ec_priv_key_x25519_0[idx], C255_base_pt_order);
#endif /* PKA_RNG */
#endif /* RAND_OPERAND_0 */
                if ((pka_status = pka_mont_ecdh_mult(
                         handle, &user_data[rand() % 1048576], X25519_curve,
                         remote_ec_pub_key_x25519[idx],
                         ec_priv_key_x25519_0[idx])) < 0) {
                    fprintf(stderr, "pka_mont_ecdh_mult failed: status=%d\n",
                            pka_status);
                    exit(0);
                }
            } else {
                /* X25519 shared secret calc. */
#if RAND_OPERAND_1
#if !PKA_RNG
                rand_non_zero_integer_wo_syscall(
                    handle, ec_priv_key_x25519_1[idx], C255_base_pt_order);
#else  /* PKA_RNG */
                pka_get_rand_bytes(handle, ec_priv_key_x25519_1[idx]->buf_ptr,
                                   32);
#endif /* PKA_RNG */
#endif /* RAND_OPERAND_1 */

                if ((pka_status = pka_mont_ecdh_mult(
                         handle, &user_data[rand() % 1048576], X25519_curve,
                         remote_ec_pub_key_x25519[idx],
                         ec_priv_key_x25519_1[idx])) < 0) {
                    fprintf(stderr, "pka_mont_ecdh_mult failed: status=%d\n",
                            pka_status);
                    exit(0);
                }
            }

            cnt++;
            cur_command_cnt++;
        }

        if (pka_status == FAILURE)
            fprintf(stderr, "pka cmd submittion failed\n");

        /* get result using polling */
        while (cur_command_cnt > 0) {
            uint64_t start = rte_rdtsc();
            ret = pka_get_result(handle, results);
            uint64_t end = rte_rdtsc();

            uint64_t diff = end - start;
            if (diff < pka_get_result_min)
                pka_get_result_min = diff;
            if (diff > pka_get_result_max)
                pka_get_result_max = diff;
            pka_get_result_sum += diff;
            pka_get_result_cnt++;

            if (unlikely(ret == FAILURE))
                pka_get_result_fail_cnt++;
            else
                pka_get_result_success_cnt++;

            if (ret != SUCCESS) {
                break;
            } else {
                if (results->status != 0) {
                    fprintf(stderr, "PKA HW Operation Failed! Status: %d\n",
                            results->status);
                    cur_command_cnt--;
                    continue;
                }
#if DBG_MODE
                print_operand("result 1 = ", &results->results[0], "\n\n");
                print_operand("result 2 = ", &results->results[1], "\n\n");
#endif /* DBG_MODE */

#if CHECK_CORRECTNESS && !(RAND_OPERAND_0 || RAND_OPERAND_1)
                int answer_idx = *(int *)results->user_data;

                /* check correctness */
                if (results->opcode == CC_ECDSA_GENERATE) {
                    if (memcmp(results->results[0].buf_ptr,
                               answer[answer_idx]->r.buf_ptr,
                               answer[answer_idx]->r.actual_len) != 0) {

                        fprintf(stderr, "ECDSA mismatch on r!\n");

                        fprintf(stderr,
                                "resutls actual len=%u, answer len=%u\n",
                                results->results[0].actual_len,
                                answer[answer_idx]->r.actual_len);

                        print_operand("PKA X = ", &results->results[0], "\n");
                        print_operand("Expected X = ", &answer[answer_idx]->r,
                                      "\n");
                        exit(0);
                    }

                    if (memcmp(results->results[1].buf_ptr,
                               answer[answer_idx]->s.buf_ptr,
                               answer[answer_idx]->s.actual_len) != 0) {

                        fprintf(stderr, "ECDSA mismatch on s!\n");

                        fprintf(stderr,
                                "resutls actual len=%u, answer len=%u\n",
                                results->results[1].actual_len,
                                answer[answer_idx]->s.actual_len);

                        print_operand("PKA Y = ", &results->results[1], "\n");
                        print_operand("Expected Y = ", &answer[answer_idx]->s,
                                      "\n");
                        exit(0);
                    }
                } else if (results->opcode == CC_MONT_ECDH_MULTIPLY) {
                    if (results->results[0].actual_len !=
                            remote_shared_secret_po[answer_idx]->actual_len ||
                        memcmp(
                            results->results[0].buf_ptr,
                            remote_shared_secret_po[answer_idx]->buf_ptr,
                            remote_shared_secret_po[answer_idx]->actual_len) !=
                            0) {

                        fprintf(stderr, "ECDH mismatch on X coordinate!\n");
                        print_operand(
                            "PKA shared secret = ", &results->results[0], "\n");
                        print_operand("Expected shared secret = ",
                                      remote_shared_secret_po[answer_idx],
                                      "\n");
                        exit(0);
                    }
                } else {
                    fprintf(stderr,
                            "Unknown opcode result for correctness check: %d\n",
                            results->opcode);
                    exit(0);
                }
#endif /* CHECK_CORRECTNESS && (!RAND_OPERAND_0 && !RAND_OPERAND_1) */

                cur_command_cnt--;
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
        }

        clock_gettime(CLOCK_MONOTONIC, &now);
        long diff = (now.tv_sec - last_print.tv_sec) * 1000000000 +
                    (now.tv_nsec - last_print.tv_nsec);

        if (diff > 1000000000) {
            PrintStatistics(diff);
            clock_gettime(CLOCK_MONOTONIC, &last_print);

            double elapsed_sec = (now.tv_nsec - start_ts.tv_nsec) / 1e9 +
                                 (now.tv_sec - start_ts.tv_sec);

            printf("pka_get_result min=%lu, max=%lu, avg=%lu\n"
                   "pka_get_result cnt per sec=%lu, total cnt=%lu\n"
                   "pka_get_result fail cnt=%lu, success cnt=%lu\n",
                   pka_get_result_min, pka_get_result_max,
                   (pka_get_result_sum / pka_get_result_cnt),
                   (unsigned long)(pka_get_result_cnt / elapsed_sec),
                   pka_get_result_cnt, pka_get_result_fail_cnt,
                   pka_get_result_success_cnt);
        }
    }

    test_end_time = pka_cpu_cycles();
    clock_gettime(CLOCK_MONOTONIC, &end_ts);

    int cpu_frequency = pka_cpu_hz_max();
    printf("total latency: %.6f secs for %d TLS13 PKA ops\n",
           (double)(1000000000ULL * (test_end_time - test_start_time) /
                    cpu_frequency) /
               1e9,
           cmd_cnt_per_thread * thread_num);
    printf("following to Linux timer, %f secs spent for %d TLS13 sess\n",
           (float)(end_ts.tv_nsec - start_ts.tv_nsec) / 1e9 +
               (float)(end_ts.tv_sec - start_ts.tv_sec),
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
    int tid[MAX_THREAD_NUM];
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
    while ((i = getopt(argc, argv, "m:t:r:o:n:")) >= 0) {
        switch (i) {
        case 'm':
            operation_mode = atoi(optarg);
            if (operation_mode < RSA_DECRYPTION || operation_mode > SPSC) {
                usage();
                exit(1);
            }
            break;
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
                fprintf(stderr, "Error: 0 < ring_num <= %d\n",
                        PKA_MAX_RING_CNT);
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
                fprintf(stderr,
                        "Error:MAX_OUTSTANDING_CMD_NUM >= max_outstanding\n");
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

    /* extract private/public key pair from certificate */
    Get_RSA_key_pair("digital_certificates/cert_rsa_2048.pem");
    // Get_RSA_key_pair("digital_certificates/cert_rsa_3072.pem");

    /* Global PKA initialization. This function must be called once per instance
     * before calling any other PKA API functions.
     */
    int pka_sync_mode;

    if (thread_num == 1)
        pka_sync_mode = PKA_F_SYNC_MODE_DISABLE;
    else
        pka_sync_mode = PKA_F_SYNC_MODE_ENABLE;

    instance = pka_init_global(
        "pka_benchmark_app", PKA_F_PROCESS_MODE_SINGLE | pka_sync_mode,
        ring_num, PKA_MAX_QUEUE_CNT, CMD_QUEUE_SIZE, RSLT_QUEUE_SIZE);

    if (instance == PKA_INSTANCE_INVALID) {
        perror("pka_init_global");
        exit(0);
    }

    /* -------------------------------------------------------------------- */
    /* create threads */
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu < 1)
        ncpu = 1;

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
        tid[i] = i;
        cmd_cnt[i] = 0;
        if (operation_mode == RSA_DECRYPTION) {
            int rc = pthread_create(&p_thread[i], &attr[i], RSAworker,
                                    (void *)&tid[i]);
            if (rc != 0) {
                fprintf(
                    stderr,
                    "Error: RSA worker pthread_create failed: %s (rc = %d)\n",
                    strerror(rc), rc);
                exit(0);
            }
        } else if (operation_mode == P256) {
            int rc = pthread_create(&p_thread[i], &attr[i], P256worker,
                                    (void *)&tid[i]);
            if (rc != 0) {
                fprintf(
                    stderr,
                    "Error: P256 worker pthread_create failed: %s (rc = %d)\n",
                    strerror(rc), rc);
                exit(0);
            }
        } else if (operation_mode == X25519) {
            int rc = pthread_create(&p_thread[i], &attr[i], X25519worker,
                                    (void *)&tid[i]);
            if (rc != 0) {
                fprintf(stderr,
                        "Error: X25519 worker pthread_create failed: %s (rc = "
                        "%d)\n",
                        strerror(rc), rc);
                exit(0);
            }
        } else if (operation_mode == ECDSA_SIG_GEN) {
            int rc = pthread_create(&p_thread[i], &attr[i], ECDSAworker,
                                    (void *)&tid[i]);
            if (rc != 0) {
                fprintf(
                    stderr,
                    "Error: ECDSA worker pthread_create failed: %s (rc = %d)\n",
                    strerror(rc), rc);
                exit(0);
            }
        } else if (operation_mode == TLS13_ASYM) {
            is_tls13_benchmark = 1;
            int rc = pthread_create(&p_thread[i], &attr[i], TLS13worker,
                                    (void *)&tid[i]);
            if (rc != 0) {
                fprintf(
                    stderr,
                    "Error: TLS13 worker pthread_create failed: %s (rc = %d)\n",
                    strerror(rc), rc);
                exit(0);
            }
        }
#if !TEST_RSA
        else if (operation_mode == TLS13_ASYM_HKDF) {
            is_tls13_benchmark = 1;
            int rc = pthread_create(&p_thread[i], &attr[i], TLS13HKDFworker,
                                    (void *)&tid[i]);
            if (rc != 0) {
                fprintf(
                    stderr,
                    "Error: TLS13 worker pthread_create failed: %s (rc = %d)\n",
                    strerror(rc), rc);
                exit(0);
            }
        }
#endif /* !TEST_RSA */
        else if (operation_mode == RAND) {
            int rc = pthread_create(&p_thread[i], &attr[i], RANDworker,
                                    (void *)&tid[i]);
            if (rc != 0) {
                fprintf(
                    stderr,
                    "Error: RAND worker pthread_create failed: %s (rc = %d)\n",
                    strerror(rc), rc);
                exit(0);
            }
        } else if (operation_mode != SPSC) {
            fprintf(stderr, "Error: invalid operation mode\n");
            exit(0);
        }
    }

    if (operation_mode == SPSC) {
        fprintf(stderr,
                "Starting SPSC benchmark (thread_num will be ignored)\n");

        is_tls13_benchmark = 1;
        int rc = pthread_create(&p_thread[0], &attr[0], Producer, NULL);
        if (rc != 0) {
            fprintf(stderr,
                    "Error: Producer pthread_create failed: %s (rc = %d)\n",
                    strerror(rc), rc);
            exit(0);
        }

        rc = pthread_create(&p_thread[1], &attr[1], Consumer, (void *)&tid[i]);
        if (rc != 0) {
            fprintf(stderr,
                    "Error: Consumer pthread_create failed: %s (rc = %d)\n",
                    strerror(rc), rc);
            exit(0);
        }
    }

    /* wait threads */
    for (i = 0; i < thread_num; i++) {
        pthread_join(p_thread[i], NULL);
        CPU_FREE(cpusetp[i]);
    }

    /* free all operands */
    if (p) {
        free_operand(p);
        free_operand(q);
        free_operand(d_p);
        free_operand(d_q);
        free_operand(qinv);
    }
    if (rsa_encrypt_key) {
        free_operand(rsa_encrypt_key);
        free_operand(rsa_decrypt_key);
        free_operand(rsa_modulus);
    }

    free(ec_priv_key);
    if (operation_mode == P256) {
        free(ec_pub_key_ep);
    } else if (operation_mode == X25519) {
        free(ec_pub_key_po);
    } else if (operation_mode == ECDSA_SIG_GEN) {
        free(ec_pub_key_ep);
    }
    free(remote_ec_priv_key);
    if (operation_mode == P256) {
        free(remote_ec_pub_key_ep);
    } else if (operation_mode == X25519) {
        free(remote_ec_pub_key_po);
    } else if (operation_mode == ECDSA_SIG_GEN) {
        free(remote_ec_pub_key_ep);
    }
    if (operation_mode == P256) {
        free(remote_shared_secret_ep);
    } else if (operation_mode == X25519) {
        free(remote_shared_secret_po);
    } else if (operation_mode == ECDSA_SIG_GEN) {
        free(remote_shared_secret_ep);
    }

    free_operand(rsa_ciphertext);

    // Release the given handle and PK instance. Note that these calls will free
    // rings related to the PK instance and will mark them as available again
    pka_term_global(instance);

    return 0;
}
