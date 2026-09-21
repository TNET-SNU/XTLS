#define _POSIX_C_SOURCE 199309L
#define _GNU_SOURCE

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <rte_atomic.h>
#include <time.h>

#include "ring.h"
#include "ssl_crypto.h"
#include "ssloff.h"

#define RAND_MAX_LOCAL (1073741823lu * 4lu + 3lu)

extern EVP_MD *sha1;
extern EVP_MD *sha256;
extern EVP_MD *sha384;
#if VERBOSE_PKA_OP
extern int num_key_gen[MAX_CPUS];
extern int num_calc_shared_secret[MAX_CPUS];
extern int num_signature_cert[MAX_CPUS];
#endif /* VERBOSE_PKA_OP */
#if VERBOSE_CONN_LAT
extern int num_key_gen[MAX_CPUS];
extern int num_gen_key[MAX_CPUS];
extern int num_ss_cal[MAX_CPUS];
extern int num_cal_ss[MAX_CPUS];
extern int num_ee_c_cv_gen[MAX_CPUS];
extern int num_gen_cv[MAX_CPUS];
extern int num_app_key_cal[MAX_CPUS];
extern int num_cal_app_key[MAX_CPUS];
extern int num_meta_tx[MAX_CPUS];
extern int num_meta_rx[MAX_CPUS];

extern uint64_t sum_syn_key_gen_lat[MAX_CPUS]; /* SYN - ECDHE key gen req. */
extern uint64_t max_syn_key_gen_lat[MAX_CPUS];
extern uint64_t sum_key_gen_gen_key_lat[MAX_CPUS]; /* key gen latency */
extern uint64_t max_key_gen_gen_key_lat[MAX_CPUS];
extern uint64_t sum_gen_key_ss_cal_lat[MAX_CPUS]; /* key gened - ss cal req. */
extern uint64_t max_gen_key_ss_cal_lat[MAX_CPUS];
extern uint64_t sum_ss_cal_cal_ss_lat[MAX_CPUS]; /* ss cal latency */
extern uint64_t max_ss_cal_cal_ss_lat[MAX_CPUS];
extern uint64_t
    sum_cal_ss_ee_c_cv_gen_lat[MAX_CPUS]; /* ss caled - c sig req. */
extern uint64_t max_cal_ss_ee_c_cv_gen_lat[MAX_CPUS];
extern uint64_t sum_ee_c_cv_gen_gen_cv_lat[MAX_CPUS]; /* c sig latency */
extern uint64_t max_ee_c_cv_gen_gen_cv_lat[MAX_CPUS];
extern uint64_t
    sum_gen_cv_app_key_cal_lat[MAX_CPUS]; /* cv gened - app key cal before */
extern uint64_t max_gen_cv_app_key_cal_lat[MAX_CPUS];
extern uint64_t
    sum_app_key_cal_cal_app_key_lat[MAX_CPUS]; /* app key cal latency */
extern uint64_t max_app_key_cal_cal_app_key_lat[MAX_CPUS];
extern uint64_t
    sum_cal_app_key_meta_tx_lat[MAX_CPUS]; /* app key cal - meta tx */
extern uint64_t max_cal_app_key_meta_tx_lat[MAX_CPUS];
extern uint64_t sum_meta_tx_meta_rx_lat[MAX_CPUS]; /* meta tx/rx latency */
extern uint64_t max_meta_tx_meta_rx_lat[MAX_CPUS];
extern uint64_t
    sum_app_data_lat[MAX_CPUS]; /* server record sent - session fin */
extern uint64_t max_app_data_lat[MAX_CPUS];
#endif /* VERBOSE_CONN_LAT */
/*--------------------------- FUNCTION PROTOTYPE ----------------------------*/
cipher_suite_t
select_cipher(uint16_t length, cipher_suite_t *cipher_suites);

void
init_record(record_t *record, const sequence_num_t seq, const int is_received_);

record_t *
new_recv_record(ssl_session_t *sess);

record_t *
new_send_record(ssl_session_t *sess);

int
store_handshake(ssl_session_t *sess, record_t *record);

void
delete_record(ssl_session_t *sess, record_t *record);

void
delete_op(ssl_crypto_op_t *op);

int
process_new_record(ssl_session_t *sess, uint8_t *buf, uint16_t len);

void
push_read_record(ssl_session_t *sess, record_t *record);

void
unpack_header(record_t *record);

int
decrypt_record(ssl_session_t *sess, record_t *record);

int
submit_pka_request(thread_context_t *ctx, ssl_crypto_op_t *op);

int
generate_ecdhe_key_pair(ssl_session_t *sess, record_t *record);

int
calculate_shared_secret(ssl_session_t *sess, record_t *record);

int
signature_certificate(ssl_session_t *sess);

int
handle_submitted_pka(thread_context_t *ctx);

int
handle_completed_pka(thread_context_t *ctx);

int
get_processed_crypto(ssl_session_t *sess);

int
verify_mac(ssl_session_t *sess, record_t *record);

int
unpack_record(record_t *record);

void
unpack_extensions(uint16_t extensions_length, uint8_t *pf, uint16_t offset,
                  uint16_t end, client_hello_t *pch, record_t *record);

int
unpack_handshake(record_t *record);

int
unpack_change_cipher_spec(void);

int
unpack_alert(record_t *record);

int
unpack_application_data(record_t *record);

int
process_read_record(ssl_session_t *sess, record_t *record);

int
handle_read_record(ssl_session_t *sess, record_t *record);

int
handle_handshake(ssl_session_t *sess, record_t *record);

int
handle_change_cipher_spec(ssl_session_t *sess, record_t *record);

int
handle_alert(ssl_session_t *sess, record_t *record);

int
handle_application_data(ssl_session_t *sess, record_t *record);

int
send_server_hello(ssl_session_t *sess, record_t *record);

int
send_encrypted_extensions(ssl_session_t *sess);

int
send_certificate(ssl_session_t *sess);

int
send_certificate_verify(ssl_session_t *sess);

int
send_server_finished(ssl_session_t *sess);

int
send_handshake(ssl_session_t *sess, record_t *record, uint8_t msg_type,
               int length, int last);

int
send_handshake_tls13(ssl_session_t *sess, record_t *record, uint8_t msg_type,
                     int length, int send_type);

int
send_pending_records(ssl_session_t *sess);

int
send_record(ssl_session_t *sess, record_t *record, uint8_t record_type,
            int length, int send_type);

int
pack_record(record_t *record);

int
pack_handshake(record_t *record, int offset);

int
pack_change_cipher_spec(record_t *record, int offset);

int
pack_application_data(record_t *record, int offset);

int
attach_mac(ssl_session_t *sess, record_t *record);

int
encrypt_record(ssl_session_t *sess, record_t *record);

int
handle_after_rsa_crypto(ssl_session_t *sess, ssl_crypto_op_t *op);

int
handle_after_private_decrypt(ssl_session_t *sess, record_t *record,
                             ssl_crypto_op_t *op);

int
handle_after_aes_crypto(ssl_session_t *sess, ssl_crypto_op_t *op);

int
handle_after_aes_cbc_encrypt(ssl_session_t *sess, record_t *record,
                             ssl_crypto_op_t *op);

int
handle_after_aes_cbc_decrypt(ssl_session_t *sess, record_t *record,
                             ssl_crypto_op_t *op);

int
handle_after_aes_gcm_encrypt(ssl_session_t *sess, record_t *record,
                             ssl_crypto_op_t *op);

int
handle_after_aes_gcm_decrypt(ssl_session_t *sess, record_t *record,
                             ssl_crypto_op_t *op);

int
handle_after_ecdhe_key_gen(ssl_session_t *sess, record_t *record,
                           ssl_crypto_op_t *op);

int
handle_after_ecdhe_shared_secret_calc(ssl_session_t *sess, record_t *record,
                                      ssl_crypto_op_t *op);

int
handle_after_ecdsa_signature(ssl_session_t *sess, record_t *record,
                             ssl_crypto_op_t *op);

int
handle_app_keys_calculation(ssl_session_t *sess);

int
handle_verify_data_calculation(ssl_session_t *sess);

int
handle_after_mac_crypto(ssl_session_t *sess, ssl_crypto_op_t *op);

int
handle_mac(ssl_session_t *sess, record_t *record, ssl_crypto_op_t *op);

#if VERBOSE_STATE
/*---------------------------------------------------------------------------*/

static const char state_str_null_state[20] = "NULL_STATE";
static const char state_str_to_pack_header[20] = "TO_PACK_HEADER";
static const char state_str_to_pack_content[20] = "TO_PACK_CONTENT";
static const char state_str_to_append_mac[20] = "TO_APPEND_MAC";
static const char state_str_to_encrypt[20] = "TO_ENCRYPT";
static const char state_str_write_ready[20] = "WRITE_READY";
static const char state_str_to_unpack_header[20] = "TO_UNPACK_HEADER";
static const char state_str_to_unpack_content[20] = "TO_UNPACK_CONTENT";
static const char state_str_to_verify_mac[20] = "TO_VERIFY_MAC";
static const char state_str_to_decrypt[20] = "TO_DECRYPT";
static const char state_str_read_ready[20] = "READ_READY";
static const char state_str_error[20] = "INVALID_STATE";

static const char *
state_to_string(int state)
{
    switch (state) {
    case NULL_STATE:
        return state_str_null_state;
    case TO_PACK_HEADER:
        return state_str_to_pack_header;
    case TO_PACK_CONTENT:
        return state_str_to_pack_content;
    case TO_APPEND_MAC:
        return state_str_to_append_mac;
    case TO_ENCRYPT:
        return state_str_to_encrypt;
    case WRITE_READY:
        return state_str_write_ready;
    case TO_UNPACK_HEADER:
        return state_str_to_unpack_header;
    case TO_UNPACK_CONTENT:
        return state_str_to_unpack_content;
    case TO_VERIFY_MAC:
        return state_str_to_verify_mac;
    case TO_DECRYPT:
        return state_str_to_decrypt;
    case READ_READY:
        return state_str_read_ready;

    default:
        return state_str_error;
    }

    return state_str_error;
}
#endif /* VERBOSE_STATE */
/*----------------------------- FUNCTION PTR TAB ----------------------------*/
typedef int (*crypto_func_t)(ssl_session_t *sess, record_t *record,
                             ssl_crypto_op_t *op);

crypto_func_t handle_after[3][3] = {
    [ENCRYPT] =
        {
            [TLS_AES_CBC] = handle_after_aes_cbc_encrypt,
            [TLS_AES_GCM] = handle_after_aes_gcm_encrypt,
        },
    [DECRYPT] =
        {
            [TLS_RSA] = handle_after_private_decrypt,
            [TLS_AES_CBC] = handle_after_aes_cbc_decrypt,
            [TLS_AES_GCM] = handle_after_aes_gcm_decrypt,
        },
    [TLS_1_3_ECDSA_ECDHE] = {
        [KEY_GEN] = handle_after_ecdhe_key_gen,
        [SHARED_SECRET_CALC] = handle_after_ecdhe_shared_secret_calc,
        [ECDSA_SIGNATURE] = handle_after_ecdsa_signature,
    }};
/*---------------------------- HELPER FUNCTION ------------------------------*/
void
set_u32(uint24_t *a, const uint32_t *b)
{
    const uint8_t *y = (const uint8_t *)b;
    a->u8[0] = y[2];
    a->u8[1] = y[1];
    a->u8[2] = y[0];
}

uint32_t
get_u32(uint24_t a)
{
    uint32_t x;
    x = a.u8[0];
    x = x << 8;
    x |= a.u8[1];
    x = x << 8;
    x |= a.u8[2];

    return x;
}

pka_results_t *
malloc_results(uint32_t result_cnt, uint32_t buf_len)
{
    pka_results_t *results;
    pka_operand_t *result_ptr;
    uint8_t result_idx, i;

    PKA_ASSERT(result_cnt <= MAX_RESULT_CNT);

    results = malloc(sizeof(pka_results_t));

    if (results == NULL) {
        fprintf(stderr, "Error: malloc for results failed\n");
        return NULL;
    }

    memset(results, 0, sizeof(pka_results_t));

    for (result_idx = 0; result_idx < result_cnt; result_idx++) {
        result_ptr = &results->results[result_idx];
        if ((result_ptr->buf_ptr = malloc(buf_len)) == NULL) {
            fprintf(stderr, "Error: malloc for buf_ptr failed\n");
            for (i = 0; i < result_idx; i++)
                free(results->results[i].buf_ptr);
            return NULL;
        }
        memset(result_ptr->buf_ptr, 0, buf_len);
        result_ptr->buf_len = buf_len;
        result_ptr->actual_len = 0;
    }

    results->result_cnt = result_cnt;

    return results;
}

void
free_results_buf(pka_results_t *results)
{
    pka_operand_t *result_ptr;
    uint8_t result_idx;

    for (result_idx = 0; result_idx < 2; result_idx++) {
        result_ptr = &results->results[result_idx];
        if (result_ptr->buf_ptr)
            free(result_ptr->buf_ptr);
        result_ptr->buf_ptr = NULL;
        result_ptr->buf_len = 0;
        result_ptr->actual_len = 0;
    }
}

void
free_results(pka_results_t *results)
{
    assert(results != NULL);
    free_results_buf(results);
    free(results);
}

void
clear_results(pka_results_t *results)
{
    pka_operand_t *result_ptr;
    uint8_t result_idx;

    assert(results);

    for (result_idx = 0; result_idx < 2; result_idx++) {
        result_ptr = &results->results[result_idx];
        if (result_ptr->buf_ptr) {
            memset(result_ptr->buf_ptr, 0, result_ptr->buf_len);
            result_ptr->actual_len = 0;
        }
    }

    results->user_data = NULL;
    results->opcode = 0;
    results->result_cnt = 0;
    results->status = 0;
    results->compare_result = 0;
}

void
init_random(ssl_session_t *sess, uint8_t *random, unsigned size)
{
    unsigned *ra = (unsigned *)random;
    unsigned i, j;
    uint64_t rand_seed = sess->rand_seed;

    rand_seed = rand_seed * 1103515245 + 12345;

    for (i = 0; i < size / sizeof(uint32_t); i++) {
        rand_seed = rand_seed * 1103515245lu + 12345lu;
        ra[i] =
            (unsigned)((rand_seed / (RAND_MAX_LOCAL * 21u)) % RAND_MAX_LOCAL);
    }

    for (j = 0; j + i * sizeof(uint32_t) < size; j++) {
        rand_seed = rand_seed * 1103515245lu + 12345lu;
        random[i * sizeof(uint32_t) + j] = (uint8_t)rand_seed;
    }
}

void
remove_pending_pka_op(ssl_session_t *sess)
{
    ssl_crypto_op_t *op = sess->pending_pka_op;

    if (unlikely(op != NULL)) {
#if VERBOSE_SSL
        fprintf(stderr, "[Remove Pending RSA OP] hit,                         \
            remove pending RSA op before clearing session\n");
#endif /* VERBOSE_SSL */

        op->pka_flag = FALSE;

        if (op->data)
            delete_record(sess, (record_t *)(op->data));

        delete_op(op);

        sess->pending_pka_op = NULL;
        sess->ctx->cur_crypto_cnt--;
    }

    ssl_crypto_op_t *op_1 = sess->pending_pka_op_1;

    if (unlikely(op_1 != NULL)) {
#if VERBOSE_SSL
        fprintf(stderr, "[Remove Pending RSA OP] hit,                         \
            remove pending RSA op before clearing session\n");
#endif /* VERBOSE_SSL */

        op_1->pka_flag = FALSE;

        delete_op(op_1);

        sess->pending_pka_op_1 = NULL;
        sess->ctx->cur_crypto_cnt--;
    }
}

ssl_crypto_op_t *
new_ssl_crypto_op(ssl_session_t *sess)
{
    ssl_crypto_op_t *target;
    thread_context_t *ctx = sess->ctx;

    target = TAILQ_FIRST(&ctx->op_pool);
    if (unlikely(!target)) {
        fprintf(
            stderr,
            "[new_ssl_crypto_op] Not enough op, and this must not happen.\n");
        exit(EXIT_FAILURE);
    }

    TAILQ_REMOVE(&ctx->op_pool, target, op_pool_link);
    ctx->free_op_cnt--;
    ctx->using_op_cnt++;

    return target;
}

cipher_suite_t
select_cipher(uint16_t length, cipher_suite_t *cipher_suites)
{
    cipher_suite_t cipher = TLS_NULL_WITH_NULL_NULL;
    uint32_t i;

    for (i = 0; i < length / sizeof(cipher_suite_t); i++) {
        if (likely(COMPARE_CIPHER(cipher_suites[i], TLS_AES_256_GCM_SHA384)))
            return TLS_AES_256_GCM_SHA384;
        if (COMPARE_CIPHER(cipher_suites[i], TLS_RSA_WITH_AES_256_GCM_SHA384))
            return TLS_RSA_WITH_AES_256_GCM_SHA384;
        if (COMPARE_CIPHER(cipher_suites[i], TLS_RSA_WITH_AES_256_CBC_SHA))
            return TLS_RSA_WITH_AES_256_CBC_SHA;
    }

    return cipher;
}

supported_group_t
select_supported_group(uint16_t length, uint16_t *supported_groups)
{
    supported_group_t supported_group = SUPPORTED_GROUP_UNKNOWN;
    supported_group_t *target = (supported_group_t *)supported_groups;
    uint32_t i;

    for (i = 0; i < length / sizeof(supported_group_t); i++) {
        if (COMPARE_SUPPORTED_GROUP(target[i], X25519))
            return X25519;
    }

    return supported_group;
}

signature_algorithm_t
select_signature_algorithm(uint16_t length, uint16_t *signature_algorithms)
{
    signature_algorithm_t signature_algorithm = SIGNATURE_UNKNOWN;
    signature_algorithm_t *target =
        (signature_algorithm_t *)signature_algorithms;
    uint32_t i;

    for (i = 0; i < length / sizeof(signature_algorithm_t); i++) {
        if (COMPARE_SIG_ALGO(target[i], ECDSA_SECP256r1_SHA256))
            return ECDSA_SECP256r1_SHA256;
    }

    return signature_algorithm;
}

void
init_record(record_t *record, const sequence_num_t seq, const int is_received_)
{
    record->data = record->buf + sizeof(uint64_t);
    record->decrypted = record->mac_in + sizeof(uint64_t);
    record->next_iv = NULL;
    record->current_len = 0;
    record->length = 0;
    record->seq_num = seq;
    record->is_encrypted = 0;

    memset(&record->plain_text, 0, sizeof(plain_text_t));
    memset(&record->cipher_text, 0, sizeof(cipher_text_t));
    memset(&record->fragment, 0, sizeof(record->fragment));

    record->is_reset = false;
    record->is_received = is_received_;
    if (record->is_received)
        record->state = TO_UNPACK_HEADER;
    else
        record->state = TO_PACK_HEADER;

#if VERBOSE_STATE
    fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
            ((ssl_session_t *)record->sess)->parent->session_id, record->id,
            state_to_string(NULL_STATE), state_to_string(record->state));
#endif /* VERBOSE_STATE */
}

record_t *
new_recv_record(ssl_session_t *sess)
{
    record_t *record = NULL;
    thread_context_t *ctx = sess->ctx;

    sess->num_current_records++;

    record = TAILQ_FIRST(&ctx->record_pool);

    if (unlikely(!record)) {
        fprintf(stderr, "Not enough record, and this must not happen.\n");
        exit(EXIT_FAILURE);
    }

    TAILQ_REMOVE(&ctx->record_pool, record, record_pool_link);
    ctx->free_record_cnt--;
    ctx->using_record_cnt++;

    record->sess = sess;

    init_record(record, 0, true);

    record->id = sess->next_record_id;
    sess->next_record_id++;

#if VERBOSE_SSL || VERBOSE_STATE
    fprintf(stderr, "\nnew_recv_record: Session %d: %d\n",
            sess->parent->session_id, record->id);
#endif /* VERBOSE_SSL */

    return record;
}

record_t *
new_send_record(ssl_session_t *sess)
{
    record_t *record = NULL;
    thread_context_t *ctx = sess->ctx;

    sess->num_current_records++;

    record = TAILQ_FIRST(&ctx->record_pool);
    if (unlikely(!record)) {
        fprintf(stderr, "Not enough record, and this must not happen.\n");
        exit(EXIT_FAILURE);
    }

    TAILQ_REMOVE(&ctx->record_pool, record, record_pool_link);
    ctx->free_record_cnt--;
    ctx->using_record_cnt++;

    record->sess = sess;

    init_record(record, sess->send_seq_num_, false);

    record->id = sess->next_record_id;
    sess->next_record_id++;

#if VERBOSE_SSL || VERBOSE_STATE
    fprintf(stderr, "\nnew_send_record: Session %d: %d\n",
            sess->parent->session_id, record->id);
#endif /* VERBOSE_SSL */

    return record;
}

int
store_handshake(ssl_session_t *sess, record_t *record)
{
    if (unlikely(record->fragment.handshake.msg_type <=
                 sess->handshake_state)) {
        return -1;
    }

    if (record->plain_text.record_type == APPLICATION_DATA) {
        memcpy(sess->handshake_msgs + sess->handshake_msgs_len,
               record->plain_text.fragment,
               record->plain_text.length - 1); /* exclude record type */
        sess->handshake_msgs_len += record->plain_text.length - 1;
    } else {
        memcpy(sess->handshake_msgs + sess->handshake_msgs_len,
               record->plain_text.fragment, record->plain_text.length);

        sess->handshake_msgs_len += record->plain_text.length;
    }

#if VERBOSE_CHUNK
    fprintf(stderr, "\nSTORE HANDSHAKE! new: %u, total : %u, type : %d\n",
            record->plain_text.length, sess->handshake_msgs_len,
            record->fragment.handshake.msg_type);
    fprintf(stderr, "fragment:\n");
    {
        unsigned z;
        for (z = 0; z < record->plain_text.length; z++)
            fprintf(stderr, "%02X%c",
                    *((uint8_t *)(record->plain_text.fragment) + z),
                    ((z + 1) % 16) ? ' ' : '\n');
    }
    fprintf(stderr, "\n");
#endif /* VERBOSE_CHUNK */

    assert(sess->handshake_msgs_len < MAX_HANDSHAKE_LENGTH);

    return sess->handshake_msgs_len;
}

void
delete_record(ssl_session_t *sess, record_t *record)
{
    thread_context_t *ctx = record->ctx;

    memset(record, 0, sizeof(record_t));
    record->ctx = ctx;
    TAILQ_INSERT_TAIL(&ctx->record_pool, record, record_pool_link);
    ctx->free_record_cnt++;
    ctx->using_record_cnt--;

    sess->num_current_records--;

#if VERBOSE_SSL || VERBOSE_STATE
    fprintf(stderr, "\nDelete Session %d, Record: %d\n",
            sess->parent->session_id, record->id);
#endif /* VERBOSE_SSL */
}

void
delete_op(ssl_crypto_op_t *op)
{
    thread_context_t *ctx = op->ctx;

    memset(op, 0, sizeof(ssl_crypto_op_t));
    op->ctx = ctx;
#if PKA_TWICE
    op->cnt = 2;
#endif /* PKA_TWICE */
    TAILQ_INSERT_TAIL(&ctx->op_pool, op, op_pool_link);
    ctx->free_op_cnt++;
    ctx->using_op_cnt--;
}
/*------------------------------ PROCESSING ---------------------------------*/
int
process_ssl_packet(tcp_connection_t *conn, uint8_t *payload,
                   uint16_t payload_len)
{
    ssl_session_t *sess = conn->ssl_session;
    if (unlikely(!payload || !payload_len))
        return -1;

#if VERBOSE_SSL
    fprintf(stderr, "\n--------------< SSL Packet >--------------\n");
#endif /* VERBOSE_SSL */

    return process_new_record(sess, payload, payload_len);
}

int
process_new_record(ssl_session_t *sess, uint8_t *pkt_buf, uint16_t pkt_len)
{
    size_t processed_len = 0;
    size_t copy_len = 0;
    record_t *crr = sess->current_read_record;
    uint16_t record_len = 0;

#if VERBOSE_SSL
    fprintf(stderr, "\n[Process New Record]\n");
    fprintf(stderr, "cur crypto cnt: %d\n", sess->ctx->cur_crypto_cnt);
#endif /* VERBOSE_SSL */

    while (processed_len < pkt_len) {
        if (crr == NULL) {
            uint8_t *record_hdr;

            if (pkt_len - processed_len < RECORD_HEADER_SIZE)
                break;

            crr = sess->current_read_record = new_recv_record(sess);

            record_hdr = pkt_buf + processed_len;

            record_len = ntohs(*(uint16_t *)(record_hdr + 3));

#if VERBOSE_SSL
            uint8_t record_type;
            record_type = *record_hdr;
            fprintf(stderr,
                    "\nNew RECORD Session %d: "
                    "%d, processed: %lu, record type: %u, len: %u\n",
                    sess->parent->session_id, crr->id, processed_len,
                    record_type, record_len);
            {
                unsigned z;
                for (z = 0; z < 64; z++)
                    fprintf(stderr, "%02X%c", record_hdr[z],
                            ((z + 1) % 16) ? ' ' : '\n');
            }
#endif /* VERBOSE_SSL */

            assert(record_len < MAX_RECORD_SIZE);
            crr->length = record_len + RECORD_HEADER_SIZE;
        }

#if ZERO_COPY_RECV
        /* Selectively copy packet between TCP-TLS (No partially copy) */
        if (crr->current_len > 0 || crr->length > pkt_len - processed_len ||
            // sess->waiting_crypto ||
            /*
             * It works with this logic: record free == buf free
             * So, currently, it can't handle multiple records in one packet.
             * That's the reason of checking SERVER_HELLO_DONE.
             */
            sess->handshake_state == SERVER_HELLO_DONE) {

            copy_len =
                MIN(crr->length - crr->current_len, pkt_len - processed_len);
            memcpy(crr->data + crr->current_len, pkt_buf + processed_len,
                   copy_len);
            crr->current_len += copy_len;
            processed_len += copy_len;
        } else {
            crr->data = pkt_buf + processed_len;
            crr->current_len += crr->length;
            processed_len += crr->length;
        }
#else  /* !ZERO_COPY_RECV */
        copy_len = MIN(crr->length - crr->current_len, pkt_len - processed_len);
        memcpy(crr->data + crr->current_len, pkt_buf + processed_len, copy_len);
        crr->current_len += copy_len;
        processed_len += copy_len;
#endif /* !ZERO_COPY_RECV */

#if VERBOSE_SSL
        fprintf(stderr,
                "crr->length: %lu, crr->current_len: %lu, "
                "processed_len: %lu\n",
                crr->length, crr->current_len, processed_len);
#endif /* VERBOSE_SSL */

        if (crr->current_len == crr->length) {
#if MODIFY_FLAG
            if (sess->waiting_crypto)
                push_read_record(sess, crr);
            else
                process_read_record(sess, crr);
#else  /* !MODIFY_FLAG */
            push_read_record(sess, crr);
#endif /* !MODIFY_FLAG */

            sess->current_read_record = NULL;
            crr = NULL;
        }
    }

    /* We need next packet */
    if (crr != NULL) {
        return -1;
    }

    return processed_len;
}

void
push_read_record(ssl_session_t *sess, record_t *record)
{
    TAILQ_INSERT_TAIL(&sess->recv_q, record, recv_q_link);
    sess->recv_q_cnt++;
}

void
unpack_header(record_t *record)
{
    uint8_t *data = record->data;
    plain_text_t *plain_text = &record->plain_text;
    cipher_text_t *cipher_text = &record->cipher_text;

    assert(record->state == TO_UNPACK_HEADER);

#if VERBOSE_SSL
    fprintf(stderr, "\n[Unpack Header]\n");
#endif /* VERBOSE_SSL */

#if VERBOSE_STATE
    fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
            ((ssl_session_t *)record->sess)->parent->session_id, record->id,
            state_to_string(TO_UNPACK_HEADER), state_to_string(record->state));
#endif /* VERBOSE_STATE */

    if (likely(data[0] == HANDSHAKE || data[0] == CHANGE_CIPHER_SPEC ||
               data[0] == ALERT || data[0] == APPLICATION_DATA)) {
        cipher_text->record_type = data[0];
        cipher_text->version.major = data[1];
        cipher_text->version.minor = data[2];
        cipher_text->length = ntohs(*(uint16_t *)(data + 3));

        plain_text->record_type = data[0];
        plain_text->version.major = data[1];
        plain_text->version.minor = data[2];
        plain_text->length = ntohs(*(uint16_t *)(data + 3));
    } else {
        plain_text->record_type = HANDSHAKE;
        plain_text->version.major = 0x02;
        plain_text->version.minor = 0x00;
        plain_text->length = record->length - 2;
    }

    record->state = TO_DECRYPT;
}

int
decrypt_record(ssl_session_t *sess, record_t *record)
{
    security_params_t *read_sp = &sess->read_sp;

    assert(record->state == TO_DECRYPT);

#if VERBOSE_SSL
    fprintf(stderr, "[Decrypt Record]\n");
#endif /* VERBOSE_SSL */

    record->seq_num = sess->recv_seq_num_;
    // sess->recv_seq_num_++;

    record->is_encrypted = TRUE;

    ssl_crypto_op_t *op = new_ssl_crypto_op(sess);

    if (unlikely(!op))
        return -1;

    uint8_t nonce[read_sp->fixed_iv_length + read_sp->record_iv_length];
    uint8_t additional_data[RECORD_HEADER_SIZE];
    generic_aead_cipher_t *aead_cipher =
        &record->cipher_text.fragment.aead_cipher;
    sequence_num_t seq_num;

    aead_cipher->content = record->data + RECORD_HEADER_SIZE;
    record->cipher_text.length -= GCM_TAG_SIZE;

#if VERBOSE_AES
    fprintf(stderr,
            "[decrypt record] decrypt with gcm !!!!!!!!!!!!!!!!!!!!!!!\n");
    fprintf(stderr, "RECORD DATA:\n");
    uint16_t z;
    for (z = 0; z < record->length; z++)
        fprintf(stderr, "%02X%c", record->data[z], ((z + 1) % 16) ? ' ' : '\n');

    fprintf(stderr, "\nImplicit part iv (client_write_iv):\n");
    for (z = 0; z < read_sp->fixed_iv_length; z++)
        fprintf(stderr, "%02X%c", sess->client_write_IV[z],
                ((z + 1) % 16) ? ' ' : '\n');
    fprintf(stderr, "\n");

    fprintf(stderr, "Explicit part iv: \n");
    for (z = 0; z < read_sp->record_iv_length; z++)
        fprintf(stderr, "%02X%c", aead_cipher->nonce_explicit[z],
                ((z + 1) % 16) ? ' ' : '\n');
    fprintf(stderr, "\n");
#endif /* VERBOSE_AES */

    seq_num = bswap_64(record->seq_num);

    /* Make nonce */
    memcpy(nonce, sess->tls13_ctx.client_handshake_iv, 12);
    for (int i = 0; i < 8; i++) {
        nonce[12 - 8 + i] ^= ((uint8_t *)&seq_num)[i];
    }

    /* Make AAD */
    seq_num = bswap_64(record->seq_num);
    memcpy(additional_data, record->data, RECORD_HEADER_SIZE);

    op->in = aead_cipher->content;
    op->out = record->decrypted + RECORD_HEADER_SIZE;

    memcpy(record->decrypted, record->data, RECORD_HEADER_SIZE);

    op->in_len = record->cipher_text.length;
    op->iv = nonce;
    op->iv_len = read_sp->fixed_iv_length + read_sp->record_iv_length;
    op->aad = additional_data;
    op->aad_len = RECORD_HEADER_SIZE;
    op->key = sess->tls13_ctx.client_handshake_key;
    op->key_len = read_sp->enc_key_size;

    op->opcode.u32 = TLS_OPCODE_AES_GCM_256_DECRYPT;
    op->data = (void *)record;

    if (unlikely(execute_aes_crypto(sess->ctx->symmetric_crypto_ctx, op) < 0)) {
        delete_op(op);
        delete_record(sess, record); /* delete record */

        return -1;
    }

    *((uint16_t *)(record->decrypted + 3)) = htons(record->cipher_text.length);

#if VERBOSE_AES
    fprintf(stderr, "\n[decrypt_record] Decrypted Data:\n");
    for (z = 0; z < record->cipher_text.length + RECORD_HEADER_SIZE; z++)
        fprintf(stderr, "%02X%c", record->decrypted[z],
                ((z + 1) % 16) ? ' ' : '\n');
#endif /* VERBOSE_AES */

    return handle_after_aes_crypto(sess, op);
}

int
submit_pka_request(thread_context_t *ctx, ssl_crypto_op_t *op)
{
#if VERBOSE_RTE_RING_DQ
    uint64_t start = rte_rdtsc();
#endif /* VERBOSE_RTE_RING_DQ */

    // int ret = rte_ring_enqueue(ctx->submit_pka_ring, op);
    int ret = sj_ring_enqueue(ctx->submit_pka_ring, op);

#if VERBOSE_RTE_RING_DQ
    uint64_t end = rte_rdtsc();

    uint64_t diff = end - start;
    if (diff < ring_eq_min)
        ring_eq_min = diff;
    if (diff > ring_eq_max)
        ring_eq_max = diff;
    ring_eq_sum += diff;
    ring_eq_cnt++;
    if (unlikely(ret < 0))
        ring_eq_fail_cnt++;
    else
        ring_eq_success_cnt++;
#endif /* VERBOSE_RTE_RING_DQ */

    if (unlikely(ret < 0)) {
        delete_op(op);

        return -1;
    }

    return 0;
}

int
generate_ecdhe_key_pair(ssl_session_t *sess, record_t *record)
{
    assert(sess != NULL);
    assert(record != NULL);

#if VERBOSE_SSL
    fprintf(stderr, "[ECDHE Key Pair Generation]\n");
#endif /* VERBOSE_SSL */

    ssl_crypto_op_t *op = new_ssl_crypto_op(sess);

    if (unlikely(!op))
        return -1;

    op->sess = sess;
    op->data = (void *)record;
    op->opcode.u32 = TLS_OPCODE_ECDHE_KEY_GENERATION;

    if (unlikely(submit_pka_request(sess->ctx, op) < 0))
        return -1;

#if PKA_TWICE
    if (unlikely(submit_pka_request(sess->ctx, op) < 0))
        return -1;
#endif /* PKA_TWICE */

    sess->waiting_crypto = TRUE;
    op->pka_flag = TRUE;
    sess->pending_pka_op = op;

    return 0;
}

int
calculate_shared_secret(ssl_session_t *sess, record_t *record)
{
    assert(sess != NULL);
    assert(record != NULL);

#if VERBOSE_SSL
    fprintf(stderr, "[calculate shared secret]\n");
#endif /* VERBOSE_SSL */

    client_hello_t *pch = &(record->fragment.handshake.body.client_hello);

    ssl_crypto_op_t *op = new_ssl_crypto_op(sess);

    if (unlikely(!op))
        return -1;

    op->sess = sess;
    op->data = NULL;
    op->opcode.u32 = TLS_OPCODE_ECDHE_SHARED_SECRET_CALC;
    string_to_operand(pch->extensions.key_share.client_pub_key,
                      sess->shared_secret_operand,
                      X25519_KEY_LEN, /* assume X25519 */
                      1);
    op->pka_in = sess->shared_secret_operand;
    op->pka_in_1 = sess->ecdhe_priv_key;

    if (unlikely(submit_pka_request(sess->ctx, op) < 0))
        return -1;

#if PKA_TWICE
    if (unlikely(submit_pka_request(sess->ctx, op) < 0))
        return -1;
#endif /* PKA_TWICE */

    sess->waiting_crypto = TRUE;
    op->pka_flag = TRUE;
    sess->pending_pka_op = op;

    return 0;
}

int
signature_certificate(ssl_session_t *sess)
{
    assert(sess != NULL);

#if VERBOSE_SSL
    fprintf(stderr, "[signature server certificate]\n");
#endif /* VERBOSE_SSL */

    uint8_t certificate_hash[MAX_HASH_SIZE];
    uint8_t transcript_hash[32];
    uint8_t temp[MAX_HASH_SIZE];
    int offset = 0;

    /* Concat 64 space chars */
    memset(certificate_hash, 0x20, 64);
    offset += 64;

    /* Concat fixed string */
    const char *fixed_string = "TLS 1.3, server CertificateVerify";
    size_t fixed_str_len = strlen(fixed_string);

    memcpy(certificate_hash + offset, fixed_string, fixed_str_len);
    offset += fixed_str_len;

    /* Concat null char */
    certificate_hash[offset++] = 0x00;

#if VERBOSE_SIG
    SHA384(sess->handshake_msgs, sess->handshake_msgs_len, temp);

    fprintf(stderr, "handshake msgs len: %u\n", sess->handshake_msgs_len);
    fprintf(stderr, "handshake msgs:\n");
    {
        unsigned z;
        for (z = 0; z < sess->handshake_msgs_len; z++)
            fprintf(stderr, "%02X%c", sess->handshake_msgs[z],
                    ((z + 1) % 16) ? ' ' : '\n');
    }
    fprintf(stderr, "\n");

    fprintf(stderr, "temp (handshake hash):\n");
    {
        unsigned z;
        for (z = 0; z < 48; z++)
            fprintf(stderr, "%02X%c", temp[z], ((z + 1) % 16) ? ' ' : '\n');
    }
#endif /* VERBOSE_SIG */

    /* Concat handshake transcript hash (assume AES256-GCM-SHA384) */
    // if (sess->handshake_msgs_len != 868) {
    //     fprintf(stderr, "Warning: handshake msgs len is %u, not 868\n"
    //                     "client ip: 0x%08x, client port: %u\n",
    //                     sess->handshake_msgs_len,
    //                     htonl(sess->parent->client_ip),
    //                     htons(sess->parent->client_port));
    // }

    SHA384(sess->handshake_msgs, sess->handshake_msgs_len,
           &certificate_hash[offset]);
    offset += 48;

#if VERBOSE_SIG
    fprintf(stderr, "handshake hash:\n");
    {
        unsigned z;
        for (z = 0; z < 48; z++)
            fprintf(stderr, "%02X%c",
                    certificate_hash[64 + 1 + fixed_str_len + z],
                    ((z + 1) % 16) ? ' ' : '\n');
    }
    fprintf(stderr, "\n");
#endif /* VERBOSE_SIG */

    /* Make transcript hash (assume P256 cert) */
    SHA256(certificate_hash, offset, transcript_hash);

    memcpy(sess->tls13_ctx.certificate_hash, certificate_hash, offset);

    sess->tls13_ctx.certificate_hash_len = offset;

#if VERBOSE_SIG
    fprintf(stderr, "certificate_hash total len: %d\n", offset);
    fprintf(stderr, "certificate_hash to be signed:\n");
    {
        unsigned z;
        for (z = 0; z < offset; z++)
            fprintf(stderr, "%02X%c", certificate_hash[z],
                    ((z + 1) % 16) ? ' ' : '\n');
    }
    fprintf(stderr, "\n");

    fprintf(stderr, "transcript hash total len: 32\n");
    fprintf(stderr, "transcript_hash to be signed:\n");
    {
        unsigned z;
        for (z = 0; z < 32; z++)
            fprintf(stderr, "%02X%c", transcript_hash[z],
                    ((z + 1) % 16) ? ' ' : '\n');
    }
    fprintf(stderr, "\n");
#endif /* VERBOSE_SIG */

    ssl_crypto_op_t *op = new_ssl_crypto_op(sess);

    if (unlikely(!op))
        return -1;

    op->sess = sess;
    op->data = NULL;
    op->opcode.u32 = TLS_OPCODE_ECDSA_SIGNATURE;
    string_to_operand(transcript_hash, sess->ecdsa_transcript_hash,
                      32, /* assume P256 cert */
                      0);
    sess->ecdsa_transcript_hash->big_endian = 0;
    op->pka_in = ctx_example.pka->ecdsa.priv_key;
    op->pka_in_1 = sess->ecdsa_transcript_hash;

    /* TODO: deterministic nonce & remove rand_operand (calloc) */
    // uint32_t n_bit_len = operand_bit_len(ecc_info->P256_base_pt_order);
    // op->pka_in_2 = rand_operand(pka_handle,
    //                             n_bit_len,
    //                             0);
    string_to_operand(transcript_hash, sess->ecdsa_k, 32, /* assume P256 cert */
                      0);

    op->pka_in_2 = sess->ecdsa_k;

    if (unlikely(submit_pka_request(sess->ctx, op) < 0))
        return -1;

#if PKA_TWICE
    if (unlikely(submit_pka_request(sess->ctx, op) < 0))
        return -1;
#endif /* PKA_TWICE */

    sess->waiting_crypto = TRUE;
    op->pka_flag = TRUE;
    sess->pending_pka_op = op;

#if VERBOSE_CONN_LAT
    clock_gettime(CLOCK_MONOTONIC, &sess->ee_c_cv_gen_time);
    uint64_t cal_ss_ee_c_cv_gen_lat =
        (sess->ee_c_cv_gen_time.tv_sec - sess->cal_ss_time.tv_sec) *
            1000000000L +
        (sess->ee_c_cv_gen_time.tv_nsec - sess->cal_ss_time.tv_nsec);

    if (cal_ss_ee_c_cv_gen_lat > max_cal_ss_ee_c_cv_gen_lat[sess->coreid]) {
        max_cal_ss_ee_c_cv_gen_lat[sess->coreid] = cal_ss_ee_c_cv_gen_lat;
    }

    sum_cal_ss_ee_c_cv_gen_lat[sess->coreid] += cal_ss_ee_c_cv_gen_lat;
    num_ee_c_cv_gen[sess->coreid]++;
#endif /* VERBOSE_CONN_LAT */

    return 0;
}

int
handle_submitted_pka(thread_context_t *ctx)
{
    int processed_cnt = 0;

    for (int core_id = 1; core_id < rte_lcore_count(); core_id++) {
        while (ctx_array[core_id]->cur_crypto_cnt < MAX_OUTSTANDING_PKA_REQ) {
            ssl_crypto_op_t *op;
            int ret = 0;

#if VERBOSE_RTE_RING_DQ
            uint64_t start = rte_rdtsc();
#endif /* VERBOSE_RTE_RING_DQ */

            // ret = rte_ring_dequeue(ctx_array[core_id]->submit_pka_ring, (void
            // **)&op);
            ret = sj_ring_dequeue(ctx_array[core_id]->submit_pka_ring,
                                  (void **)&op);

#if VERBOSE_RTE_RING_DQ
            uint64_t end = rte_rdtsc();

            uint64_t diff = end - start;
            if (diff < ring_dq_min)
                ring_dq_min = diff;
            if (diff > ring_dq_max)
                ring_dq_max = diff;
            ring_dq_sum += diff;
            ring_dq_cnt++;
            if (unlikely(ret < 0))
                ring_dq_fail_cnt++;
            else
                ring_dq_success_cnt++;
#endif /* VERBOSE_RTE_RING_DQ */

            if (ret < 0)
                break;

            switch (op->opcode.u32) {
            case TLS_OPCODE_ECDHE_KEY_GENERATION:
                ret = execute_ecdhe_key_generation(op);
                break;
            case TLS_OPCODE_ECDHE_SHARED_SECRET_CALC:
                ret = execute_ecdhe_shared_secret_calculation(op);
                break;
            case TLS_OPCODE_ECDSA_SIGNATURE:
                ret = execute_ecdsa_signature(op);
                break;

            default:
                fprintf(stderr, "Error: Unsupported PKA opcode: %u\n",
                        op->opcode.u32);
                exit(EXIT_FAILURE);
            }

            if (unlikely(ret < 0)) {
                delete_op(op);
                continue;
            }

            op->pka_flag = TRUE;
            op->sess->pending_pka_op = op;
            ctx_array[core_id]->cur_crypto_cnt++;

            processed_cnt++;
        }
    }

    return processed_cnt;
}

int
handle_completed_pka(thread_context_t *ctx)
{
    int processed_cnt = 0;

    int ret = 0;
    thread_context_t *ctx_of_pka_result;
    ssl_session_t *sess;
    record_t *record;

    for (int core_id = 1; core_id < rte_lcore_count(); core_id++) {
        while (ctx_array[core_id]->cur_crypto_cnt > 0) {
#if VERBOSE_PKA_GET_RESULT
            uint64_t start = rte_rdtsc();
#endif /* VERBOSE_PKA_GET_RESULT */

            ret = pka_get_result(*(ctx->handle), ctx->pka_result);

#if VERBOSE_PKA_GET_RESULT
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
#endif /* VERBOSE_PKA_GET_RESULT */

            if (unlikely(ret == FAILURE))
                return processed_cnt;

            if (unlikely(ctx->pka_result->status != 0)) {
                fprintf(stderr, "PKA Result Status: %d\n",
                        ctx->pka_result->status);
                exit(EXIT_FAILURE);
            }

            sess = (ssl_session_t *)((ssl_crypto_op_t *)(ctx->pka_result
                                                             ->user_data))
                       ->sess;

            sess->pka_op = (ssl_crypto_op_t *)(ctx->pka_result->user_data);

            if (unlikely(!sess->pka_op)) {
                DEBUG_PRINT("[process crypto] op is null..\n");
                exit(EXIT_FAILURE);
            }

            /* it may be already rotten */
            if (unlikely(sess->pka_op->pka_flag == FALSE))
                continue;

            record = (record_t *)(sess->pka_op->data);

            if (unlikely(sess->handshake_state == HELLO_REQUEST && !record)) {
                DEBUG_PRINT("[process crypto] record is null..\n");
                exit(EXIT_FAILURE);
            }

            sess->pka_results->opcode = ctx->pka_result->opcode;
            sess->pka_results->result_cnt = ctx->pka_result->result_cnt;

            for (int i = 0; i < ctx->pka_result->result_cnt; i++) {
                sess->pka_results->results[i].buf_len =
                    ctx->pka_result->results[i].buf_len;

                sess->pka_results->results[i].actual_len =
                    ctx->pka_result->results[i].actual_len;

                memcpy(sess->pka_results->results[i].buf_ptr,
                       ctx->pka_result->results[i].buf_ptr,
                       ctx->pka_result->results[i].buf_len);
            }

            // rte_wmb(); /* wow! */
            rte_atomic_thread_fence(rte_memory_order_release);

            sess->ctx->cur_crypto_cnt--;
            sess->ctx->completed_crypto_cnt++;
            __atomic_store_n(&sess->completed_crypto, TRUE, __ATOMIC_RELEASE);

            processed_cnt++;
        }

        if (ret == FAILURE) {
            break;
        }
    }

    return processed_cnt;
}

int
get_processed_crypto(ssl_session_t *sess)
{
    if (!sess->completed_crypto)
        return 0;

    // rte_rmb(); /* wow! */
    rte_atomic_thread_fence(rte_memory_order_acquire);

    int ret, need_read_record;
    ssl_crypto_op_t *op = sess->pka_op;
    record_t *record = (record_t *)(op->data);
    crypto_func_t func;

    switch (sess->handshake_state) {
    case HELLO_REQUEST: {
#if VERBOSE_KEY
        fprintf(stderr, "[get process crypto] TLS 1.3 ECDHE key gen done\n");
#endif /* VERBOSE_KEY */

        func = handle_after[TLS_1_3_ECDSA_ECDHE][KEY_GEN];
        sess->pending_pka_op = NULL;
        need_read_record = TRUE;

#if VERBOSE_CONN_LAT
        clock_gettime(CLOCK_MONOTONIC, &sess->gen_key_time);
        uint64_t key_gen_gen_key_lat =
            (sess->gen_key_time.tv_sec - sess->key_gen_time.tv_sec) *
                1000000000L +
            (sess->gen_key_time.tv_nsec - sess->key_gen_time.tv_nsec);

        if (key_gen_gen_key_lat > max_key_gen_gen_key_lat[sess->coreid]) {
            max_key_gen_gen_key_lat[sess->coreid] = key_gen_gen_key_lat;
        }

        sum_key_gen_gen_key_lat[sess->coreid] += key_gen_gen_key_lat;
        num_gen_key[sess->coreid]++;
#endif /* VERBOSE_CONN_LAT */
        break;
    }
    case SERVER_HELLO: {
#if VERBOSE_KEY
        fprintf(stderr, "[get process crypto] "
                        "TLS 1.3 ECDHE shared secret calculation\n");
#endif /* VERBOSE_KEY */

        func = handle_after[TLS_1_3_ECDSA_ECDHE][SHARED_SECRET_CALC];
        sess->pending_pka_op = NULL;
        need_read_record = FALSE;

#if VERBOSE_CONN_LAT
        clock_gettime(CLOCK_MONOTONIC, &sess->cal_ss_time);
        uint64_t ss_cal_cal_ss_lat =
            (sess->cal_ss_time.tv_sec - sess->ss_cal_time.tv_sec) *
                1000000000L +
            (sess->cal_ss_time.tv_nsec - sess->ss_cal_time.tv_nsec);

        if (ss_cal_cal_ss_lat > max_ss_cal_cal_ss_lat[sess->coreid]) {
            max_ss_cal_cal_ss_lat[sess->coreid] = ss_cal_cal_ss_lat;
        }

        sum_ss_cal_cal_ss_lat[sess->coreid] += ss_cal_cal_ss_lat;
        num_cal_ss[sess->coreid]++;
#endif /* VERBOSE_CONN_LAT */
        break;
    }
    case CERTIFICATE: {
#if VERBOSE_SIG
        fprintf(stderr, "[get process crypto] "
                        "TLS 1.3 ECDSA signature done\n");
#endif /* VERBOSE_SIG */

        func = handle_after[TLS_1_3_ECDSA_ECDHE][ECDSA_SIGNATURE];
        sess->pending_pka_op = NULL;
        need_read_record = FALSE;

#if VERBOSE_CONN_LAT
        clock_gettime(CLOCK_MONOTONIC, &sess->gen_cv_time);
        uint64_t ee_c_cv_gen_gen_cv_lat =
            (sess->gen_cv_time.tv_sec - sess->ee_c_cv_gen_time.tv_sec) *
                1000000000L +
            (sess->gen_cv_time.tv_nsec - sess->ee_c_cv_gen_time.tv_nsec);

        if (ee_c_cv_gen_gen_cv_lat > max_ee_c_cv_gen_gen_cv_lat[sess->coreid]) {
            max_ee_c_cv_gen_gen_cv_lat[sess->coreid] = ee_c_cv_gen_gen_cv_lat;
        }

        sum_ee_c_cv_gen_gen_cv_lat[sess->coreid] += ee_c_cv_gen_gen_cv_lat;
        num_gen_cv[sess->coreid]++;
#endif /* VERBOSE_CONN_LAT */
        break;
    }

    default: {
        fprintf(stderr,
                "Error: Unsupported TLS 1.3 PKA "
                "operation at state %d\n",
                sess->handshake_state);
        fprintf(stderr, "opcode: %u\n", op->opcode.u32);
        exit(EXIT_FAILURE);
        break;
    }
    }

    if (unlikely(func(sess, record, op) < 0))
        return -1;

    if (need_read_record) {
        if (unlikely(handle_read_record(sess, record) < 0))
            return -1;
    }

    sess->waiting_crypto = FALSE;
    sess->completed_crypto = FALSE;

#if PKA_TWICE
    if (!(--op->cnt))
#endif /* PKA_TWICE */

        delete_op(op);
}

int
verify_mac(ssl_session_t *sess, record_t *record)
{
    unsigned pad_len;
    security_params_t *read_sp = &sess->read_sp;
    generic_block_cipher_t *block_cipher =
        &record->cipher_text.fragment.block_cipher;

#if VERBOSE_SSL
    fprintf(stderr, "[verify mac]\n");
#endif /* VERBOSE_SSL */

    ssl_crypto_op_t *op = new_ssl_crypto_op(sess);
    if (unlikely(!op))
        return -1;

    op->in = record->mac_in;
    sequence_num_t seq_num = bswap_64(record->seq_num);
    op->opcode.u32 = TLS_OPCODE_HMAC_SHA1_HASH;

#if VERBOSE_MAC
    fprintf(stderr, "\nDecrypt MAC\n");
#endif /* VERBOSE_MAC */

    if (likely(record->is_received)) {
        op->key = sess->client_write_MAC_secret;
        op->key_len = read_sp->mac_key_size;
        op->out_len = read_sp->mac_key_size;

        uint8_t *end = record->decrypted + RECORD_HEADER_SIZE +
                       record->cipher_text.length - 1;

        pad_len = *end;

        if (pad_len != *(end - 1) || pad_len > record->cipher_text.length)
            pad_len = 0;

        op->in_len = record->cipher_text.length + sizeof(record->seq_num) +
                     RECORD_HEADER_SIZE - read_sp->mac_key_size - pad_len - 1;

        block_cipher->padding_length = pad_len;
        block_cipher->padding = end - pad_len;
        block_cipher->mac = block_cipher->padding - read_sp->mac_key_size;
        block_cipher->content = record->decrypted + RECORD_HEADER_SIZE;

        record->cipher_text.length -= (read_sp->mac_key_size + pad_len + 1);
        *((uint16_t *)(record->decrypted + 3)) =
            htons(record->cipher_text.length);
    } else {
        fprintf(stderr, "[verify mac] ???\n");
        exit(EXIT_FAILURE);
    }

    memcpy(op->in, &seq_num, sizeof(seq_num));
    op->out = record->mac_buf;
    op->data = (void *)record;

    if (unlikely(execute_mac_crypto(op) < 0)) {
        delete_op(op);

        return -1;
    }

#if VERBOSE_MAC
    fprintf(stderr, "\nmac key:\n");
    {
        for (unsigned z = 0; z < op->key_len; z++)
            fprintf(stderr, "%02X%c", op->key[z], ((z + 1) % 16) ? ' ' : '\n');
    }

    fprintf(stderr, "\nmac_in:\n");
    {
        for (unsigned z = 0; z < op->in_len; z++)
            fprintf(stderr, "%02X%c", op->in[z], ((z + 1) % 16) ? ' ' : '\n');
    }

    fprintf(stderr, "\nmac_out:\n");
    {
        for (unsigned z = 0; z < op->out_len; z++)
            fprintf(stderr, "%02X%c", op->out[z], ((z + 1) % 16) ? ' ' : '\n');
    }
#endif /* VERBOSE_MAC */

    return handle_after_mac_crypto(sess, op);
}

int
unpack_record(record_t *record)
{
    uint8_t *decrypted = record->decrypted;
    uint8_t *data = record->data;
    plain_text_t *plain_text = &record->plain_text;
    uint8_t record_type;

    assert(unlikely(record != NULL));
    assert(unlikely(record->state == TO_UNPACK_CONTENT));

#if VERBOSE_SSL
    fprintf(stderr, "[Unpack Record]\n");
#endif /* VERBOSE_SSL */

#if VERBOSE_STATE
    fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
            ((ssl_session_t *)record->sess)->parent->session_id, record->id,
            state_to_string(TO_UNPACK_CONTENT), state_to_string(record->state));
#endif /* VERBOSE_STATE */

    if (likely(plain_text->version.major == 0x03)) {
        if (unlikely(decrypted != data))
            plain_text->length = record->cipher_text.length;

        plain_text->fragment = decrypted + RECORD_HEADER_SIZE;
    } else /* drop unappropriate pkt */
        return -1;

    record_type = plain_text->record_type;

    int ret = -1;
    switch (record_type) {
    case HANDSHAKE:
        ret = unpack_handshake(record);
        break;
    case CHANGE_CIPHER_SPEC:
        ret = unpack_change_cipher_spec();
        break;
    case ALERT:
        ret = unpack_alert(record);
        break;
    case APPLICATION_DATA:
        ret = unpack_application_data(record);
        break;

    default:
        assert(0);
    }

    record->state = READ_READY;

    return ret;
}

void
unpack_extensions(uint16_t extensions_length, uint8_t *pf, uint16_t offset,
                  uint16_t end, client_hello_t *pch, record_t *record)
{
    if (extensions_length > 0) {
        while (offset < end) {
            uint16_t extension_type = ntohs(*(uint16_t *)(pf + offset));
            offset += sizeof(uint16_t);

            uint16_t extension_length = ntohs(*(uint16_t *)(pf + offset));
            offset += sizeof(uint16_t);

            switch (extension_type) {
            case EC_POINT_FORMATS: {
#if DEBUG_TLS_1_3
                fprintf(stderr, "EC_POINT_FORMATS Extension length: %u\n",
                        extension_length);
#endif /* DEBUG_TLS_1_3 */
                offset += extension_length;
                break;
            }
            case SUPPORTED_GROUPS: { /* essential */
                uint16_t curves_list_length = ntohs(*(uint16_t *)(pf + offset));
                pch->extensions.supported_groups.curves_list_length =
                    curves_list_length;
                offset += sizeof(uint16_t);

                pch->extensions.supported_groups.curves_list =
                    (uint16_t *)(pf + offset);
                offset += curves_list_length;
#if DEBUG_TLS_1_3
                fprintf(stderr, "Supported Groups Extension: ");
                for (int i = 0; i < curves_list_length / sizeof(uint16_t);
                     i++) {
                    fprintf(
                        stderr, "0x%04x ",
                        htons(pch->extensions.supported_groups.curves_list[i]));
                }
                fprintf(stderr, "\n");
#endif /* DEBUG_TLS_1_3 */
                break;
            }
            case SESSION_TICKET: {
#if DEBUG_TLS_1_3
                fprintf(stderr, "SESSION_TICKET Extension length: %u\n",
                        extension_length);
#endif /* DEBUG_TLS_1_3 */
                offset += extension_length;
                break;
            }
            case ALPN: {
#if DEBUG_TLS_1_3
                fprintf(stderr, "ALPN Extension length: %u\n",
                        extension_length);
#endif /* DEBUG_TLS_1_3 */
                offset += extension_length;
                break;
            }
            case ENCRYPT_THEN_MAC: {
#if DEBUG_TLS_1_3
                fprintf(stderr, "ENCRYPT_THEN_MAC Extension length: %u\n",
                        extension_length);
#endif /* DEBUG_TLS_1_3 */
                offset += extension_length;
                break;
            }
            case EXTENDED_MASTER_SECRET: {
#if DEBUG_TLS_1_3
                fprintf(stderr, "EXTENDED_MASTER_SECRET Extension length: %u\n",
                        extension_length);
#endif /* DEBUG_TLS_1_3 */
                offset += extension_length;
                break;
            }
            case SIGNATURE_ALGORITHMS: { /* essential */
                uint16_t signature_algorithm_list_length =
                    ntohs(*(uint16_t *)(pf + offset));
                pch->extensions.signature_algorithms
                    .signature_algorithm_list_length =
                    signature_algorithm_list_length;
                offset += sizeof(uint16_t);

                pch->extensions.signature_algorithms.signature_algorithm_list =
                    (uint16_t *)(pf + offset);
                offset += signature_algorithm_list_length;
#if DEBUG_TLS_1_3
                fprintf(stderr, "Signature Algorithms Extension: ");
                for (int i = 0;
                     i < signature_algorithm_list_length / sizeof(uint16_t);
                     i++) {
                    fprintf(stderr, "0x%04x ",
                            htons(pch->extensions.signature_algorithms
                                      .signature_algorithm_list[i]));
                }
                fprintf(stderr, "\n");
#endif /* DEBUG_TLS_1_3 */
                break;
            }
            case SUPPORTED_VERSIONS: { /* essential */
                uint8_t versions_length = *(uint8_t *)(pf + offset);
                pch->extensions.supported_versions.versions_length =
                    versions_length;
                offset += sizeof(uint8_t);

                pch->extensions.supported_versions.versions =
                    (protocol_version_t *)(pf + offset);
                offset += versions_length;

#if DEBUG_TLS_1_3
                fprintf(stderr, "Supported Versions Extension: ");
                for (int i = 0; i < versions_length; i++) {
                    fprintf(
                        stderr, "%02x ",
                        pch->extensions.supported_versions.versions[i].major);
                    fprintf(
                        stderr, "%02x ",
                        pch->extensions.supported_versions.versions[i].minor);
                }
                fprintf(stderr, "\n");
#endif /* DEBUG_TLS_1_3 */
                break;
            }
            case PSK_KEY_EXCHANGE_MODES: {
                offset += extension_length;
#if DEBUG_TLS_1_3
                fprintf(stderr, "PSK Key Exchange Modes Extension length: %u\n",
                        extension_length);
#endif /* DEBUG_TLS_1_3 */
                break;
            }
            case KEY_SHARE: { /* essential */
                uint16_t key_share_length = ntohs(*(uint16_t *)(pf + offset));
                pch->extensions.key_share.key_share_length = key_share_length;
                offset += sizeof(uint16_t);

                pch->extensions.key_share.curve_type =
                    ntohs(*(uint16_t *)(pf + offset));
                offset += sizeof(uint16_t);

                pch->extensions.key_share.pub_key_length =
                    ntohs(*(uint16_t *)(pf + offset));
                offset += sizeof(uint16_t);

                pch->extensions.key_share.client_pub_key =
                    (uint8_t *)(pf + offset);
                offset += pch->extensions.key_share.pub_key_length;
#if DEBUG_TLS_1_3
                fprintf(stderr, "Client pub key: \n");
                for (int i = 0; i < pch->extensions.key_share.pub_key_length;
                     i++) {
                    fprintf(stderr, "%02x ",
                            pch->extensions.key_share.client_pub_key[i]);
                    if ((i + 1) % 16 == 0)
                        fprintf(stderr, "\n");
                }
                fprintf(stderr, "\n");
#endif /* DEBUG_TLS_1_3 */
                break;
            }
            default:
                fprintf(stderr, "Unknown Extension Type: %u\n", extension_type);
                break;
            }
        }
    }
}

int
unpack_handshake(record_t *record)
{
    plain_text_t *plain_text = &record->plain_text;
    uint8_t *pf = plain_text->fragment;
    uint8_t *hl = record->fragment.handshake.length.u8;
    int offset = HANDSHAKE_HEADER_SIZE;
    int end = plain_text->length;
    client_hello_t *pch = &record->fragment.handshake.body.client_hello;
    client_key_exchange_t *pcke =
        &record->fragment.handshake.body.client_key_exchange;
    finished_t *pcf = &record->fragment.handshake.body.client_finished;

#if VERBOSE_SSL
    fprintf(stderr, "[Unpack Handshake]\n");
#endif /* VERBOSE_SSL */

    record->fragment.handshake.msg_type = pf[0];
    memcpy(hl, pf + 1, HANDSHAKE_HEADER_SIZE - 1);

    switch (record->fragment.handshake.msg_type) {
    case CLIENT_HELLO: {
#if VERBOSE_SSL
        fprintf(stderr, "Client Hello!\n");
#endif /* VERBOSE_SSL */

        if (likely(plain_text->version.major == 0x03 &&
                   plain_text->version.minor == 0x01)) {

            pch->version = *(protocol_version_t *)(pf + offset);
            offset += sizeof(protocol_version_t);

            memcpy(&pch->random, pf + offset, sizeof(pch->random));
            offset += sizeof(pch->random);

            pch->session_id_length = pf[offset];
            offset += sizeof(uint8_t);

            if (likely(pch->session_id_length > 0)) {
                memcpy(&pch->session_id, pf + offset, pch->session_id_length);
                offset += pch->session_id_length;
            }

            pch->cipher_suite_length = ntohs(*(uint16_t *)(pf + offset));
            offset += sizeof(uint16_t);

            if (likely(pch->cipher_suite_length > 0)) {
                pch->cipher_suites = (cipher_suite_t *)(pf + offset);
                offset += pch->cipher_suite_length;
            }

            pch->compression_method_length = pf[offset];
            offset += sizeof(uint8_t);

            if (likely(pch->compression_method_length > 0)) {
                pch->compression_methods =
                    (compression_method_t *)(pf + offset);
                offset += pch->compression_method_length *
                          sizeof(compression_method_t);
            }

            if (likely(offset < end)) {
                pch->extensions_length = ntohs(*(uint16_t *)(pf + offset));
                offset += sizeof(uint16_t);

                unpack_extensions(pch->extensions_length, pf, offset, end, pch,
                                  record);

                record->sess->id_ = pch->session_id;

                if (generate_ecdhe_key_pair(record->sess, record) < 0)
                    return -1;
                else
                    return 0;

                return 0;
            }
        } else {
            fprintf(stderr, "This version does not supported\n");
        }

#if VERBOSE_SSL
        fprintf(stderr, "Client Version: %u.%u,\n", pch->version.major,
                pch->version.minor);
        fprintf(stderr, "Session ID Length: %u,\n", pch->session_id_length);
        fprintf(stderr, "Cipher Length: %x,\n", pch->cipher_suite_length);
        fprintf(stderr, "Compression Length: %x,\n",
                pch->compression_method_length);
        // fprintf(stderr, "off: %u, off_value: %u\n\n",
        //                 off, *(pf + off));
#endif /* VERBOSE_SSL */

        break;
    }
    case CLIENT_KEY_EXCHANGE: {
#if VERBOSE_SSL
        fprintf(stderr, "Client Key Exchange!\n");
#endif /* VERBOSE_SSL */

        /* Assume RSA */ /* TODO: ECDHE (TLS 1.3) */
        assert(pcke->key.rsa.encrypted_premaster_secret == NULL);

        if (end > offset) {
            pcke->key.rsa.encrypted_premaster_secret = pf + offset;
            offset += (end - offset);
        }

        break;
    }
    case CLIENT_FINISHED: {
#if VERBOSE_SSL
        fprintf(stderr, "\nClient FINISHED!\n");
#endif /* VERBOSE_SSL */

        memcpy(&pcf->verify_data, pf + offset, sizeof(pcf->verify_data));
        offset += sizeof(pcf->verify_data);
        break;
    }
    case HELLO_REQUEST:
    case CERTIFICATE:
    case SERVER_HELLO:
    case SERVER_KEY_EXCHANGE:
    case CERTIFICATE_REQUEST:
    case SERVER_HELLO_DONE:
    case CERTIFICATE_VERIFY:
        fprintf(stderr, "Not Supported Handshake Message\n");
        break;

    default:
        fprintf(stderr, "No matching Type of Handshake: %d\n",
                record->fragment.handshake.msg_type);
        fprintf(stderr, "handshake msgs len: %d\n",
                record->sess->handshake_msgs_len);

        return -1;

        assert(offset == end);

        return 0;
    }
}

int
unpack_change_cipher_spec(void)
{
#if VERBOSE_SSL
    fprintf(stderr, "[unpack change cipher spec]\n");
#endif /* VERBOSE_SSL */

    return 0;
}

int
unpack_alert(record_t *record)
{
    if (unlikely(!record))
        return -1;
    record->fragment.alert.level = *(record->decrypted + RECORD_HEADER_SIZE);
    record->fragment.alert.description =
        *(record->decrypted + RECORD_HEADER_SIZE + 1);

    return 0;
}

int
unpack_application_data(record_t *record)
{
#if VERBOSE_SSL
    fprintf(stderr, "[unpack application data]\n");
#endif /* VERBOSE_SSL */

    plain_text_t *plain_text = &record->plain_text;
    uint8_t *pf = plain_text->fragment;
    uint8_t *hl = record->fragment.handshake.length.u8;
    int offset = HANDSHAKE_HEADER_SIZE;
    int end = plain_text->length;

    finished_tls13_t *pcf =
        &record->fragment.handshake.body.client_finished_tls13;

    uint8_t msg_type = pf[end - 1];

    if (unlikely(!record))
        return -1;

    memcpy(hl, pf + 1, HANDSHAKE_HEADER_SIZE - 1);

    switch (msg_type) {
    case HANDSHAKE: {
        memcpy(&pcf->verify_data, pf + offset, sizeof(pcf->verify_data));
        offset += sizeof(pcf->verify_data);
#if VERBOSE_DATA
        fprintf(stderr, "verify data:\n");
        {
            unsigned z;
            for (z = 0; z < sizeof(pcf->verify_data); z++)
                fprintf(stderr, "%02X%c", pcf->verify_data[z],
                        ((z + 1) % 16) ? ' ' : '\n');
        }
        fprintf(stderr, "\n");
#endif /* VERBOSE_DATA */

        break;
    }

    default:
        if (msg_type) { /* msg_type == 0: due to undecrypted cccs/cf/app_data
                           after STATE_ACTIVE */
            fprintf(stderr,
                    "No matching Type of Application Data: %d\n"
                    "client: 0x%08x:%u",
                    msg_type, htonl(record->sess->parent->client_ip),
                    htons(record->sess->parent->client_port));
        }
        return -1;
    }

    return 0;
}

int
process_session_read(ssl_session_t *sess)
{
    int processed_record = 0;
    record_t *target;

    assert(sess->recv_q_cnt >= 0);

    while (sess->recv_q_cnt > 0 && !sess->waiting_crypto) {
        target = TAILQ_FIRST(&sess->recv_q);

        TAILQ_REMOVE(&sess->recv_q, target, recv_q_link);
        sess->recv_q_cnt--;

        process_read_record(sess, target);
        processed_record++;
    }

    return processed_record;
}

int
process_read_record(ssl_session_t *sess, record_t *record)
{
    assert(record != NULL);

    if (sess->handshake_state >= CLIENT_HELLO) {
        /* Retransmitted CHs */
        if (record->data[0] == HANDSHAKE) {
            if (sess->handshake_state == CERTIFICATE_VERIFY &&
                sess->tls13_ctx.cert_signatured) {
                send_key_meta(sess->coreid, sess->parent->portid + 1,
                              sess->parent);
                sess->num_of_retransmitted_meta_pkt++;
            }

            if (sess->handshake_state == FINISHED &&
                sess->tls13_ctx.cert_signatured) {
                int ret = -1;

                while (ret < 0) {
                    ret = send_tcp_packet(sess->parent, sess->server_records,
                                          sess->server_records_len,
                                          TCP_FLAG_ACK, 0);

                    if (unlikely(ret < 0))
                        fprintf(
                            stderr, "\nSending Payload failed, len: %d\n",
                            sess->ctx->dpc->wmbufs[sess->parent->portid].len);
                }
            }

            sess->num_of_retransmitted_ch++;

            // if (sess->num_of_retransmitted_ch > 5) {
            //     fprintf(stderr, "Warning: too many retransmitted Client Hello
            //     packets (%d)\n"
            //                     "num of retransmitted meta packets: %u\n"
            //                     "tls 13: %s\n"
            //                     "client ip: %u.%u.%u.%u\n"
            //                     "client port: %u\n"
            //                     "handshake_state: 0x%02x\n"
            //                     "handshake key gened: %s\n"
            //                     "cert_signatured: %s\n"
            //                     "mig_fin_recved: %s\n",
            //                     sess->num_of_retransmitted_ch,
            //                     sess->num_of_retransmitted_meta_pkt,
            //                     sess->parent->client_ip & 0xFF,
            //                     (sess->parent->client_ip >> 8) & 0xFF,
            //                     (sess->parent->client_ip >> 16) & 0xFF,
            //                     (sess->parent->client_ip >> 24) & 0xFF,
            //                     htons(sess->parent->client_port),
            //                     sess->handshake_state,
            //                     sess->tls13_ctx.handshake_key_calculated ?
            //                     "true" : "false",
            //                     sess->tls13_ctx.cert_signatured ? "true" :
            //                     "false", sess->parent->recv_mig_fin ? "true"
            //                     : "false"
            //                     );
            // }

            delete_record(sess, record);

            return 0;
        }
    }

#if VERBOSE_SSL
    fprintf(stderr, "[PROCESS READ RECORD]\n");
#endif /* VERBOSE_SSL */

#if VERBOSE_CHUNK
    fprintf(stderr, "\nNew READ RECORD\n");
    {
        unsigned z;
        for (z = 0; z < record->length; z++)
            fprintf(stderr, "%02X%c", record->data[z],
                    ((z + 1) % 16) ? ' ' : '\n');
    }
#endif /* VERBOSE_CHUNK */

    unpack_header(record);

    if (unlikely(sess->read_sp.bulk_cipher_algorithm != NO_CIPHER)) {

        if (sess->state < STATE_ACTIVE) {
            if (unlikely(decrypt_record(sess, record) < 0)) {
                delete_record(sess, record);
                return -1;
            }
        }

        if (sess->read_sp.cipher_type != AEAD) { /* for CF */
            if (unlikely(verify_mac(sess, record) < 0)) {
                fprintf(stderr, "[process read record] verify mac failed\n");
                delete_record(sess, record);
                return -1;
            }
        }
    } else /* Others (CH, CKE, CCCS)*/
        record->decrypted = record->data;

    record->state = TO_UNPACK_CONTENT;

    if (unlikely(unpack_record(record) < 0))
        return -1;

    /* Do Server key pair generation */
    if (unlikely(record->plain_text.record_type == HANDSHAKE &&
                 record->fragment.handshake.msg_type == CLIENT_HELLO)) {
#if VERBOSE_CONN_LAT
        clock_gettime(CLOCK_MONOTONIC, &sess->key_gen_time);
        uint64_t syn_key_gen_lat =
            (sess->key_gen_time.tv_sec - sess->parent->conn_start_time.tv_sec) *
                1000000000L +
            (sess->key_gen_time.tv_nsec -
             sess->parent->conn_start_time.tv_nsec);

        if (syn_key_gen_lat > max_syn_key_gen_lat[sess->coreid]) {
            max_syn_key_gen_lat[sess->coreid] = syn_key_gen_lat;
        }

        sum_syn_key_gen_lat[sess->coreid] += syn_key_gen_lat;
        num_key_gen[sess->coreid]++;
#endif /* VERBOSE_CONN_LAT */

        return 0;
    }

    return handle_read_record(sess, record);
}

int
handle_read_record(ssl_session_t *sess, record_t *record)
{
    int ret = -1;

    if (!record) {
        fprintf(stderr, "recore is null - client ip: %d, client port: %u\n",
                htonl(sess->parent->client_ip),
                htons(sess->parent->client_port));
    }
    assert(record != NULL);

#if VERBOSE_SSL
    fprintf(stderr, "[Handle Read Record]\n");
#endif /* VERBOSE_SSL */

    assert(record->state == READ_READY);

    switch (record->plain_text.record_type) {
    case HANDSHAKE:
        ret = handle_handshake(sess, record);
        break;
    case CHANGE_CIPHER_SPEC:
        ret = handle_change_cipher_spec(sess, record);
        break;
    case ALERT:
        ret = handle_alert(sess, record);
        break;
    case APPLICATION_DATA:
        ret = handle_application_data(sess, record);
        break;

    default:
        fprintf(stderr, "Unmatched Record Type\n");
        break;
    }

    return ret;
}

int
handle_handshake(ssl_session_t *sess, record_t *record)
{
    cipher_suite_t cipher = TLS_NULL_WITH_NULL_NULL;
    supported_group_t curve = SUPPORTED_GROUP_UNKNOWN;
    signature_algorithm_t signature_algorithm = SIGNATURE_UNKNOWN;
    client_pub_key_t client_pub_key = {
        0,
    };
    client_hello_t *client_hello;
    premaster_secret_t *pms;
    security_params_t *pending_sp = &sess->pending_sp;
    security_params_t *write_sp = &sess->write_sp;
    uint8_t *vd;

    int random_size =
        sizeof(pending_sp->client_random) + sizeof(pending_sp->server_random);
    uint8_t randoms[random_size];
    const EVP_MD *(*hash_func)(void);
    unsigned z;

#if VERBOSE_SSL
    fprintf(stderr, "[Handle Handshake] type: %d, len: %d\n",
            record->fragment.handshake.msg_type, record->plain_text.length);
#endif /* VERBOSE_SSL */

    if (unlikely(store_handshake(sess, record) < 0)) {
#if VERBOSE_SSL
        fprintf(stderr, "handshake retransmission\n");
#endif /* VERBOSE_SSL */
    }

    switch (record->fragment.handshake.msg_type) {
    case CLIENT_HELLO: {
        if (sess->handshake_state >= CLIENT_HELLO)
            goto handshake_record_finish;

        sess->state = STATE_HANDSHAKE;

        sess->handshake_state = CLIENT_HELLO;

        client_hello = &(record->fragment.handshake.body.client_hello);

        /* set cipher */
        cipher = select_cipher(client_hello->cipher_suite_length,
                               client_hello->cipher_suites);
        pending_sp->cipher = cipher;

        /* set supported groups */
        curve = select_supported_group(
            client_hello->extensions.supported_groups.curves_list_length,
            client_hello->extensions.supported_groups.curves_list);
        pending_sp->curve = curve;

        /* set signature algorithm */
        signature_algorithm = select_signature_algorithm(
            client_hello->extensions.signature_algorithms
                .signature_algorithm_list_length,
            client_hello->extensions.signature_algorithms
                .signature_algorithm_list);
        pending_sp->signature_algorithm = signature_algorithm;

        /* set client public key */
        memcpy(&client_pub_key,
               client_hello->extensions.key_share.client_pub_key,
               sizeof(client_pub_key_t));
        pending_sp->client_pub_key = client_pub_key;

        if (COMPARE_CIPHER(cipher, TLS_AES_256_GCM_SHA384)) {
            pending_sp->entity = SERVER;
            pending_sp->prf_algorithm = PRF_SHA384;
            pending_sp->bulk_cipher_algorithm = AES;
            pending_sp->cipher_type = AEAD;
            pending_sp->enc_key_size = 32;
            pending_sp->fixed_iv_length = 12; /* length of nonce */
            pending_sp->compression_algorithm = NO_COMP;

            memcpy(pending_sp->client_random, &(client_hello->random),
                   sizeof(pending_sp->client_random));

            uint32_t now = time(NULL);
            memcpy(pending_sp->server_random, &now, sizeof(uint32_t));
            init_random(sess, (pending_sp->server_random) + sizeof(uint32_t),
                        sizeof(pending_sp->server_random) - sizeof(uint32_t));
        } else {
            fprintf(stderr, "Unsupported Cipher\n");
        }

        sess->version = client_hello->version;

#if VERBOSE_SSL
        fprintf(stderr, "CLIENT HELLO RECEIVED\n\n");
        fprintf(stderr, "Prepare SERVER HELLO\n");
#endif /* VERBOSE_SSL */

        /* send server hello */
        send_server_hello(sess, record);
        sess->handshake_state = SERVER_HELLO;

        /* calculate shared secret in PKA */
        calculate_shared_secret(sess, record);
#if VERBOSE_CONN_LAT
        clock_gettime(CLOCK_MONOTONIC, &sess->ss_cal_time);
        uint64_t gen_key_ss_cal_lat =
            (sess->ss_cal_time.tv_sec - sess->gen_key_time.tv_sec) *
                1000000000L +
            (sess->ss_cal_time.tv_nsec - sess->gen_key_time.tv_nsec);

        if (gen_key_ss_cal_lat > max_gen_key_ss_cal_lat[sess->coreid]) {
            max_gen_key_ss_cal_lat[sess->coreid] = gen_key_ss_cal_lat;
        }

        sum_gen_key_ss_cal_lat[sess->coreid] += gen_key_ss_cal_lat;
        num_ss_cal[sess->coreid]++;
#endif /* VERBOSE_CONN_LAT */

        /* set write_sp */
        memcpy(write_sp, pending_sp, sizeof(*pending_sp));
        sess->send_seq_num_ = 0;

        break;
    }

    default:
        fprintf(stderr, "Unmatched handshake, %d\n",
                record->fragment.handshake.msg_type);
        delete_record(sess, record); /* delete record */
        abort_session(record->sess);
        return -1;
    }

handshake_record_finish:
    delete_record(sess, record); /* delete record */
    record = NULL;

    return 0;
}

int
handle_change_cipher_spec(ssl_session_t *sess, record_t *record)
{
#if VERBOSE_SSL
    fprintf(stderr, "[Handle CHANGE_CIPHER_SPEC]\n\n");
#endif /* VERBOSE_SSL */

    if (sess->handshake_state != FINISHED &&
        sess->handshake_state >= CLIENT_CIPHER_SPEC)
        goto cipher_spec_record_finish;

    sess->handshake_state = CLIENT_CIPHER_SPEC;
    sess->recv_seq_num_ = 0;
    sess->client_write_IV_seq_num = 0;
    memcpy(&sess->read_sp, &sess->pending_sp, sizeof(sess->read_sp));

cipher_spec_record_finish:
    delete_record(sess, record); /* delete record */
    record = NULL;
    return 0;
}

int
handle_alert(ssl_session_t *sess, record_t *record)
{
    unsigned char level = record->fragment.alert.level;
    unsigned char description = record->fragment.alert.description;

    const char FATAL = 2;
    const char CLOSE_NOTIFY = 0;

    fprintf(
        stderr,
        "[core %d] Alert received from client ip: 0x%08x, client port: %u\n",
        sess->ctx->coreid, htonl(sess->parent->client_ip),
        htons(sess->parent->client_port));

    /* for debugging - start */
    fprintf(stderr, "certificate_hash total len: %d\n",
            sess->tls13_ctx.certificate_hash_len);
    fprintf(stderr, "certificate_hash to be signed:\n");
    {
        unsigned z;
        for (z = 0; z < sess->tls13_ctx.certificate_hash_len; z++)
            fprintf(stderr, "%02X%c", sess->tls13_ctx.certificate_hash[z],
                    ((z + 1) % 16) ? ' ' : '\n');
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "signature to be verified:\n");
    {
        unsigned z;
        for (z = 0; z < sess->tls13_ctx.cert_signature_len; z++)
            fprintf(stderr, "%02X%c", sess->tls13_ctx.cert_signature[z],
                    ((z + 1) % 16) ? ' ' : '\n');
    }
    fprintf(stderr, "\n");
    /* for debugging - end */

    delete_record(sess, record); /* delete record */

    /* serve simplified respond */
    if (level == FATAL || description == CLOSE_NOTIFY)
        abort_session(sess);

    return 0;
}

// int
// forward_app_data(ssl_session_t* sess, record_t* record)
// {
//     uint8_t* encrypted_record = &record->data[0];
//     uint16_t record_len = ((uint16_t)record->data[3] << 8) |
//     ((uint16_t)record->data[4]) + 5; int ret; uint8_t* buf; struct
//     rte_ether_hdr* ethh; struct rte_ipv4_hdr* iph; struct rte_tcp_hdr* tcph;
//     tcp_connection_t* conn = sess->parent;

//     fprintf(stderr, "forward_app_data\n");
//     hex_dump(encrypted_record, record_len);

//     buf = get_wptr(conn->coreid, conn->portid + 1, TOTAL_HEADER_LEN +
//     record_len, 1, TCP_HEADER_LEN);

//     assert(buf != NULL);

//     ethh = (struct rte_ether_hdr *)buf;

//     memcpy(ethh->dst_addr.addr_bytes, conn->server_mac, 6);
//     memcpy(ethh->src_addr.addr_bytes, conn->client_mac, 6);

//     ethh->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

//     iph = (struct rte_ipv4_hdr *)(ethh + 1);
//     iph->version_ihl = 0x45;
//     iph->type_of_service = 0x00;
//     iph->total_length = htons(IP_HEADER_LEN + TCP_HEADER_LEN + record_len);
//     iph->packet_id = htons(conn->ip_id++);
//     iph->fragment_offset = htons(0x4000);
//     iph->time_to_live = 0x40;
//     iph->next_proto_id = IPPROTO_TCP;
//     iph->src_addr = conn->client_ip;
//     iph->dst_addr = conn->server_ip;

//     tcph = (struct rte_tcp_hdr *)(iph + 1);

//     tcph->src_port = conn->client_port;
//     tcph->dst_port = conn->server_port;
//     tcph->tcp_flags = TCP_FLAG_PSH | TCP_FLAG_ACK;

//     /* Now the tcp connection should be always "TCP_SESSION_RECEIVED" */
//     tcph->recv_ack = htonl(conn->last_recv_ack);
//     tcph->sent_seq = htonl(conn->last_recv_seq);

//     tcph->data_off = (TCP_HEADER_LEN >> 2) << 4;

//     memcpy((uint8_t *)tcph + TCP_HEADER_LEN, encrypted_record, record_len);

//     tcph->rx_win = htons(8192);

//     return 0;
// }

int
handle_application_data(ssl_session_t *sess, record_t *record)
{
#if VERBOSE_DATA
    unsigned char *data = record->fragment.application_data.data;
    unsigned data_len = record->plain_text.length;
    unsigned z;

    fprintf(stderr, "\nAPP DATA LEN: %u\n", data_len);
    for (z = 0; z < data_len; z++)
        fprintf(stderr, "%c", data[z]);
#endif /* VERBOSE_DATA */

#if !ONLOAD
    sess->ctx->cur_stat.completes++;
#endif /* !ONLOAD */

    plain_text_t *plain_text = &record->plain_text;
    uint8_t *pf = plain_text->fragment;
    int end = plain_text->length;

    finished_tls13_t *pcf =
        &record->fragment.handshake.body.client_finished_tls13;

    uint8_t msg_type = pf[end - 1];

    switch (msg_type) {
    case APPLICATION_DATA:
        break;
    case HANDSHAKE: {
        if (sess->handshake_state >= FINISHED)
            goto appdata_record_finish;

        sess->handshake_state = FINISHED;
        sess->state = STATE_ACTIVE;
        sess->parent->onload = TRUE;

        /* Verify client vd */
        if (memcmp(sess->tls13_ctx.calculated_vd, pcf->verify_data,
                   sizeof(pcf->verify_data)) != 0) {
            fprintf(stderr, "Wrong Handshake Data!!\n");
            remove_hws(sess->parent);
            abort_session(sess);
            return -1;
        }

#if VERBOSE_SSL
        /* Verified */
        fprintf(stderr, "\nCorrect Verify Data!!\n");
#endif /* VERBOSE_SSL */

        int ret = send_tcp_packet(sess->parent, NULL, 0, TCP_FLAG_ACK, 0);

        if (unlikely(ret < 0)) {
            fprintf(stderr, "Sending ACK Failed.\n");
            exit(EXIT_FAILURE);
        }

        break;
    }

    default:
        fprintf(stderr, "Unmatched application data msg_type, %d\n", msg_type);
        delete_record(sess, record); /* delete record */
        return -1;
    }

appdata_record_finish:
    delete_record(sess, record); /* delete record */

    return 0;
}

int
send_server_hello(ssl_session_t *sess, record_t *record)
{
    client_hello_t *pch = &record->fragment.handshake.body.client_hello;

    record_t *server_hello = new_send_record(sess);
    int length = 0;
    server_hello_t *psh = &server_hello->fragment.handshake.body.server_hello;
    int ret;

    security_params_t *sp;
    sp = &sess->pending_sp;

#if VERBOSE_SSL
    fprintf(stderr, "[send server hello]\n");
#endif /* VERBOSE_SSL */

    psh->version = sess->version;
    length += sizeof(psh->version);

    memcpy(&psh->random, sp->server_random, sizeof(sp->server_random));
    length += sizeof(psh->random);

    psh->session_id_length = sizeof(session_id_t);
    length += sizeof(psh->session_id_length);

    memcpy(&psh->session_id, &sess->id_, sizeof(session_id_t));
    length += sizeof(psh->session_id);

    psh->cipher_suite = sp->cipher;
    length += sizeof(psh->cipher_suite);

    psh->compression_method.cm = NO_COMP;
    length += sizeof(psh->compression_method);

    psh->extensions_length = 2 + /* extension type */
                             2 + /* extension length */
                             2 + /* supported versions */
                             2 + /* extension type */
                             2 + /* extension length */
                             36; /* key share */
    length += sizeof(psh->extensions_length);

    psh->extensions.supported_versions.extension_type =
        htons(SUPPORTED_VERSIONS);
    length += sizeof(psh->extensions.supported_versions.extension_type);
    psh->extensions.supported_versions.extension_length =
        htons(0x0002); /* assume TLS 1.3 */
    length += sizeof(psh->extensions.supported_versions.extension_length);
    psh->extensions.supported_versions.version.major = 0x03;
    psh->extensions.supported_versions.version.minor = 0x04;
    length += sizeof(psh->extensions.supported_versions.version);

    psh->extensions.key_share.extension_type = htons(KEY_SHARE);
    length += sizeof(psh->extensions.key_share.extension_type);
    psh->extensions.key_share.extension_length =
        htons(0x0024); /* assume X25519 */
    length += sizeof(psh->extensions.key_share.extension_length);
    psh->extensions.key_share.curve_type = htons(curve_type_X25519);
    length += sizeof(psh->extensions.key_share.curve_type);
    psh->extensions.key_share.pub_key_length =
        htons(0x0020); /* assume X25519 */
    length += sizeof(psh->extensions.key_share.pub_key_length);
    uint8_t server_pub_key[X25519_KEY_LEN]; /* assume X25519 */
    operand_to_string(sess->ecdhe_pub_key, server_pub_key,
                      X25519_KEY_LEN); /* assume X25519 */
    /* restore little endian of server pub key */
    byte_swap_copy(psh->extensions.key_share.server_pub_key, server_pub_key,
                   X25519_KEY_LEN);

#if VERBOSE_KEY
    fprintf(stderr, "sent pub key:\n");
    for (unsigned z = 0; z < X25519_KEY_LEN; z++)
        fprintf(stderr, "%02X%c", server_pub_key[z],
                ((z + 1) % 16) ? ' ' : '\n');
#endif /* VERBOSE_KEY */

    length += X25519_KEY_LEN; /* assume X25519 */

    ret =
        send_handshake(sess, server_hello, SERVER_HELLO, length, PKT_TYPE_NONE);

    if (unlikely(ret < 0)) {
        fprintf(stderr, "send_handshake for server_hello_tls13 failed\n");
        exit(EXIT_FAILURE);
    }

    return ret;
}

int
send_encrypted_extensions(ssl_session_t *sess)
{
#if VERBOSE_SSL
    fprintf(stderr, "[send encrypted extensions]\n");
#endif /* VERBOSE_SSL */

    record_t *encrypted_extensions = new_send_record(sess);
    int length = 0;
    server_encrypted_extensions_t *psee =
        &encrypted_extensions->fragment.handshake.body
             .server_encrypted_extensions;
    int ret;

    psee->extensions_length = 0;
    length += sizeof(psee->extensions_length);

    ret = send_handshake_tls13(sess, encrypted_extensions, ENCRYPTED_EXTENSIONS,
                               length, PKT_TYPE_NONE);

    if (unlikely(ret < 0)) {
        fprintf(stderr,
                "send_handshake for encrypted_extensions_tls13 failed\n");
        exit(EXIT_FAILURE);
    }

    return ret;
}

int
send_certificate(ssl_session_t *sess)
{
#if VERBOSE_SSL
    fprintf(stderr, "[send certificate]\n");
#endif /* VERBOSE_SSL */

    record_t *certificates = new_send_record(sess);
    int length = 0;
    certificate_list_tls13_t *pcert =
        &certificates->fragment.handshake.body.certificate_tls13;
    int ret;

    pcert->certificates = sess->ctx->certificates;
    pcert->certificates->certificate = sess->ctx->ssl_context->certificate;
    length += sess->ctx->ssl_context->certificate_length;

    set_u32(&pcert->certificates->length, (uint32_t *)&length);
    length += sizeof(pcert->certificates[0].length);

    pcert->cert_extensions_length = 0;
    length += sizeof(pcert->cert_extensions_length);

    set_u32(&pcert->certificates_length, (uint32_t *)&length);
    length += sizeof(pcert->certificates_length);

    pcert->request_context_length = 0;
    length += sizeof(pcert->request_context_length);

    ret = send_handshake_tls13(sess, certificates, CERTIFICATE, length,
                               PKT_TYPE_NONE);

    if (unlikely(ret < 0)) {
        fprintf(stderr, "send_handshake for certificate_tls13 failed\n");
        exit(EXIT_FAILURE);
    }

    return ret;
}

int
send_certificate_verify(ssl_session_t *sess)
{
    record_t *certificate_verify = new_send_record(sess);
    int length = 0;
    int ret;

    cert_verify_tls13_t *pcv =
        &certificate_verify->fragment.handshake.body.certificate_verify;

    pcv->signature_algorithm = sess->write_sp.signature_algorithm;
    length += sizeof(pcv->signature_algorithm);

    pcv->signature_length = sess->tls13_ctx.cert_signature_len;
    length += sizeof(pcv->signature_length);

    pcv->cert_signature = sess->tls13_ctx.cert_signature;
    length += sess->tls13_ctx.cert_signature_len;

    ret = send_handshake_tls13(sess, certificate_verify, CERTIFICATE_VERIFY,
                               length, PKT_TYPE_NONE);

    if (unlikely(ret < 0)) {
        fprintf(stderr, "send_handshake for certificate_verify_tls13 failed\n");
        exit(EXIT_FAILURE);
    }

    return ret;
}

int
send_server_finished(ssl_session_t *sess)
{
    record_t *server_finished = new_send_record(sess);
    int length = 0;
    unsigned int out_len;
    int ret;
    uint8_t finished_key[48];
    uint8_t finished_hash[48];

    if (unlikely(
            hkdf_expand_label(sess->ctx->t_hmac_ctx, finished_key,
                              HASH_SIZE_SHA384, sess->tls13_ctx.server_secret,
                              HASH_SIZE_SHA384, "finished", strlen("finished"),
                              (unsigned char *)"", 0, sha384) == 0)) {
        fprintf(stderr, "hkdf_expand_label for finished_key failed\n");
        exit(EXIT_FAILURE);
    }

    SHA384(sess->handshake_msgs, sess->handshake_msgs_len, finished_hash);

    HMAC_Init_ex(sess->ctx->t_hmac_ctx, finished_key, sizeof(finished_key),
                 sha384, NULL);
    HMAC_Update(sess->ctx->t_hmac_ctx, finished_hash, HASH_SIZE_SHA384);
    HMAC_Final(sess->ctx->t_hmac_ctx,
               server_finished->fragment.handshake.body.server_finished_tls13
                   .verify_data,
               &out_len);

    length += HASH_SIZE_SHA384;

    ret = send_handshake_tls13(sess, server_finished, FINISHED, length,
                               PKT_TYPE_NONE);

    if (unlikely(ret < 0)) {
        fprintf(stderr, "send_handshake for server_finished_tls13 failed\n");
        exit(EXIT_FAILURE);
    }

    return ret;
}

void
send_remain_server_records(ssl_session_t *sess)
{
    if (sess->handshake_state == SERVER_HELLO && /* pseudo handshake state */
        sess->tls13_ctx.handshake_key_calculated) {
        send_encrypted_extensions(sess);
        sess->handshake_state = ENCRYPTED_EXTENSIONS;
        send_certificate(sess);
        sess->handshake_state = CERTIFICATE;
        signature_certificate(sess);

        return;
    }

    if (sess->handshake_state == CERTIFICATE && /* pseudo handshake state */
        sess->tls13_ctx.cert_signatured) {
        send_certificate_verify(sess);
        sess->handshake_state = CERTIFICATE_VERIFY;
        send_server_finished(sess);
        handle_app_keys_calculation(sess);
        handle_verify_data_calculation(sess);
        send_key_meta(sess->coreid, sess->parent->portid + 1,
                      sess->parent); /* correct implementation */

        return;
    }

    if (sess->handshake_state ==
            CERTIFICATE_VERIFY &&     /* correct implementation */
        sess->parent->recv_mig_fin) { /* pseudo handshake state */
        send_pending_records(sess);

        sess->handshake_state = FINISHED;

        return;
    }
}

int
send_handshake(ssl_session_t *sess, record_t *record, uint8_t msg_type,
               int length, int send_type)
{
#if VERBOSE_SSL
    fprintf(stderr, "[SEND HANDSHAKE]\n");
#endif /* VERBOSE_SSL */

    set_u32(&record->fragment.handshake.length, (uint32_t *)&length);
    length += sizeof(record->fragment.handshake.length);
    record->fragment.handshake.msg_type = msg_type;
    length += sizeof(record->fragment.handshake.msg_type);

    return send_record(sess, record, HANDSHAKE, length, send_type);
}

int
send_handshake_tls13(ssl_session_t *sess, record_t *record, uint8_t msg_type,
                     int length, int send_type)
{
#if VERBOSE_SSL
    fprintf(stderr, "[SEND HANDSHAKE]\n");
#endif /* VERBOSE_SSL */

    set_u32(&record->fragment.handshake.length, (uint32_t *)&length);
    length += sizeof(record->fragment.handshake.length);
    record->fragment.handshake.msg_type = msg_type;
    length += sizeof(record->fragment.handshake.msg_type);

    return send_record(sess, record, APPLICATION_DATA, length, send_type);
}

int
send_pending_records(ssl_session_t *sess)
{
    int ret = -1;

    while (ret < 0) {
#if OFFLOAD_AES_GCM
        if (send_type == PKT_TYPE_OFFL_TLS_AES) {
            ret = send_tcp_packet(sess->parent, sess->send_buffer,
                                  sess->send_buffer_offset, TCP_FLAG_ACK,
                                  TCP_OFFL_TSO | TCP_OFFL_TLS_AES);
        } else {
            ret = send_tcp_packet(sess->parent, sess->send_buffer,
                                  sess->send_buffer_offset, TCP_FLAG_ACK, 0);
        }
#else  /* OFFLOAD_AES_GCM */
        ret = send_tcp_packet(sess->parent, sess->send_buffer,
                              sess->send_buffer_offset, TCP_FLAG_ACK, 0);
#endif /* !OFFLOAD_AES_GCM */

        if (unlikely(ret < 0))
            fprintf(stderr, "\nSending Payload failed, len: %d\n",
                    sess->ctx->dpc->wmbufs[sess->parent->portid].len);
    }

    memcpy(sess->server_records, sess->send_buffer, sess->send_buffer_offset);
    sess->server_records_len = sess->send_buffer_offset;

    memset(&sess->send_buffer, 0, sizeof(sess->send_buffer));
    sess->send_buffer_offset = 0;

    return 0;
}

int
send_record(ssl_session_t *sess, record_t *record, uint8_t record_type,
            int length, int send_type)
{
    int ret = -1;
    int copy_len = 0;
    assert(record != NULL);

#if VERBOSE_SSL
    fprintf(stderr, "[SEND RECORD]\n");
#endif /* VERBOSE_SSL */

    record->plain_text.length = length;
    length += sizeof(record->plain_text.length);
    record->plain_text.record_type = record_type;
    length += sizeof(record->plain_text.record_type);
    record->plain_text.version = sess->version;
    length += sizeof(record->plain_text.version);

    record->length = length;

    if (unlikely(pack_record(record) < 0)) {
        fprintf(stderr, "pack_record failed\n");
        return -1;
    }

    if (record->plain_text.record_type == HANDSHAKE ||
        record->plain_text.record_type == APPLICATION_DATA) {
        if (unlikely(store_handshake(sess, record) < 0)) {
#if VERBOSE_SSL
            fprintf(stderr, "handshake retransmission\n");
#endif /* VERBOSE_SSL */
        }
    }

    if (unlikely(sess->write_sp.bulk_cipher_algorithm != NO_CIPHER)) {
        if (sess->pending_sp.cipher_type != AEAD) {
            ret = attach_mac(sess, record);
            if (unlikely(ret < 0))
                return -1;
        }

#if OFFLOAD_AES_GCM
        /* ToDo: insert information on AES offload into mbuf? */

        /* It only consider handshake packet,
           so please rethink when processing app data here */
        if (send_type == PKT_TYPE_OFFL_TLS_AES &&
            sess->pending_sp.cipher_type == AEAD) {
            int add_len = sess->write_sp.record_iv_length + GCM_TAG_SIZE;
            record->data = record->decrypted;
            record->data -= sess->write_sp.record_iv_length;
            memcpy(record->data, record->decrypted, RECORD_HEADER_SIZE);
            record->data[4] += add_len;
            memset(record->data + RECORD_HEADER_SIZE, 0,
                   sess->write_sp.record_iv_length);
            record->length += add_len;
            record->state = WRITE_READY;
        } else {
            record->state = TO_ENCRYPT;
            if (encrypt_record(sess, record) < 0) {
                return -1;
            }
        }
#else  /* !OFFLOAD_AES_GCM */
        record->state = TO_ENCRYPT;

        if (unlikely(encrypt_record(sess, record) < 0)) {
            fprintf(stderr, "encrypt_record failed\n");
            return -1;
        }
#endif /* !OFFLOAD_AES_GCM */
    } else {
        record->data = record->decrypted;
        record->state = WRITE_READY;
    }

#if VERBOSE_CHUNK
    fprintf(stderr, "\nSending Payload\n");
    {
        unsigned z;
        for (z = 0; z < record->length; z++)
            fprintf(stderr, "%02X%c", *((uint8_t *)record->data + z),
                    ((z + 1) % 16) ? ' ' : '\n');
    }
    fprintf(stderr, "\n");
#endif /* VERBOSE_SSL */

    memcpy(sess->send_buffer + sess->send_buffer_offset, record->data,
           record->length);
    sess->send_buffer_offset += record->length;
    copy_len = record->length;

    if (send_type)
        ret = send_pending_records(sess);

    delete_record(sess, record);

    return copy_len;
}

int
pack_record(record_t *record)
{
    uint8_t *decrypted = record->decrypted;
    ;
    plain_text_t *plain_text = &record->plain_text;
    int offset = 0;

    assert(record->state == TO_PACK_HEADER);
    record->state = TO_APPEND_MAC;

#if VERBOSE_STATE
    fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
            ((ssl_session_t *)record->sess)->parent->session_id, record->id,
            state_to_string(TO_PACK_HEADER), state_to_string(record->state));
#endif /* VERBOSE_STATE */

#if VERBOSE_SSL
    fprintf(stderr, "[PACK RECORD]\n");
#endif /* VERBOSE_SSL */

    decrypted[0] = plain_text->record_type;
    offset += sizeof(plain_text->record_type);

    memcpy(decrypted + offset, &plain_text->version,
           sizeof(plain_text->version));
    offset += sizeof(plain_text->version);

    *(uint16_t *)(decrypted + offset) = htons(plain_text->length);
    offset += sizeof(uint16_t);

    int ret = -1;

    switch (plain_text->record_type) {
    case HANDSHAKE:
        ret = pack_handshake(record, offset);
        break;
    case CHANGE_CIPHER_SPEC:
        ret = pack_change_cipher_spec(record, offset);
        break;
    case ALERT:
        fprintf(stderr, "Alert Record Packing Not Implemented.\n");
        break;
    case APPLICATION_DATA:
        ret = pack_application_data(record, offset);
        break;

    default:
        fprintf(stderr, "Unmatched Record Type: %d\n", plain_text->record_type);
        assert(0);
    }

    return ret;
}

int
pack_handshake(record_t *record, int offset)
{
    uint8_t *decrypted = record->decrypted;
    handshake_t *phs = &record->fragment.handshake;

    record->plain_text.fragment = decrypted + offset;

#if VERBOSE_SSL
    fprintf(stderr, "[PACK HANDSHAKE]\n");
#endif /* VERBOSE_SSL */

    decrypted[offset++] = phs->msg_type;
    memcpy(decrypted + offset, &phs->length, sizeof(phs->length));
    offset += sizeof(phs->length);

    switch (phs->msg_type) {
    case HELLO_REQUEST:
    case CLIENT_HELLO:
        assert(0);
        break;
    case SERVER_HELLO: {
        server_hello_t *psh = &phs->body.server_hello;

        memcpy(decrypted + offset, &psh->version, sizeof(psh->version));
        offset += sizeof(psh->version);

        memcpy(decrypted + offset, &psh->random, sizeof(psh->random));
        offset += sizeof(psh->random);

        *(uint8_t *)(decrypted + offset) = psh->session_id_length;
        offset += sizeof(uint8_t);

        memcpy(decrypted + offset, &psh->session_id, sizeof(psh->session_id));
        offset += sizeof(psh->session_id);

        *(cipher_suite_t *)(decrypted + offset) = psh->cipher_suite;
        offset += sizeof(psh->cipher_suite);

        *(compression_method_t *)(decrypted + offset) = psh->compression_method;
        offset += sizeof(psh->compression_method);

        *(uint16_t *)(decrypted + offset) = htons(psh->extensions_length);
        offset += sizeof(psh->extensions_length);

        *(server_supported_versions_t *)(decrypted + offset) =
            psh->extensions.supported_versions;
        offset += sizeof(psh->extensions.supported_versions);

        *(server_key_share_t *)(decrypted + offset) = psh->extensions.key_share;
        ;
        offset += sizeof(psh->extensions.key_share);

        break;
    }
    case CERTIFICATE: {
        certificate_list_t *pc = &phs->body.certificate;

        memcpy(decrypted + offset, &pc->certificates_length,
               sizeof(pc->certificates_length));
        offset += sizeof(pc->certificates_length);

        int remain_cert_len = get_u32(pc->certificates_length);

        certificate_t *cert;
        cert = pc->certificates;
        while (remain_cert_len > 0) {
            memcpy(decrypted + offset, &cert->length, sizeof(cert->length));
            offset += sizeof(cert->length);
            remain_cert_len -= sizeof(cert->length);

            memcpy(decrypted + offset, cert->certificate,
                   get_u32(cert->length));
            offset += get_u32(cert->length);
            remain_cert_len -= get_u32(cert->length);

            cert =
                (certificate_t *)(((uint8_t *)pc->certificates) +
                                  sizeof(cert->length) + get_u32(cert->length));
        }
        break;
    }
    case SERVER_HELLO_DONE: {
        break;
    }
    case CLIENT_FINISHED:
    case SERVER_FINISHED: {
        finished_t *pf = &phs->body.server_finished;
        memcpy(decrypted + offset, pf->verify_data, sizeof(pf->verify_data));
        offset += sizeof(pf->verify_data);
        break;
    }
    case SERVER_KEY_EXCHANGE:
    case CERTIFICATE_REQUEST:
    case CERTIFICATE_VERIFY:
    case CLIENT_KEY_EXCHANGE:
        fprintf(stderr, "Unsupported Handshake.\n");
        delete_record(record->sess, record);
        abort_session(record->sess);
        return -1;

    default:
        fprintf(stderr, "Unmatched Handshake.\n");
        delete_record(record->sess, record);
        abort_session(record->sess);
        return -1;
    }

    return offset;
}

int
pack_change_cipher_spec(record_t *record, int offset)
{
#if VERBOSE_SSL
    fprintf(stderr, "[PACK CHANGE CIPHER SPEC]\n");
#endif /* VERBOSE_SSL */

    memcpy(record->decrypted + offset, &record->fragment,
           sizeof(change_cipher_spec_t));
    offset += sizeof(change_cipher_spec_t);
    return 0;
}

int
pack_application_data(record_t *record, int offset)
{
    uint8_t *decrypted = record->decrypted;
    handshake_t *phs = &record->fragment.handshake;

    record->plain_text.fragment = decrypted + offset; /* ? */

    decrypted[offset++] = phs->msg_type;
    memcpy(decrypted + offset, &phs->length, sizeof(phs->length));
    offset += sizeof(phs->length);

    switch (phs->msg_type) {
    case ENCRYPTED_EXTENSIONS: {
        server_encrypted_extensions_t *psee =
            &phs->body.server_encrypted_extensions;

        uint16_t ext_len = htons(psee->extensions_length);
        memcpy(decrypted + offset, &ext_len, sizeof(ext_len));
        offset += sizeof(ext_len);

        decrypted[offset++] = HANDSHAKE;
        record->plain_text.length++;
        record->length++;

        *(uint16_t *)(decrypted + 3) = htons(record->plain_text.length);

        return offset;
    }
    case CERTIFICATE: {
        certificate_list_tls13_t *pc = &phs->body.certificate_tls13;

        memcpy(decrypted + offset, &pc->request_context_length,
               sizeof(pc->request_context_length));
        offset += sizeof(pc->request_context_length);

        memcpy(decrypted + offset, &pc->certificates_length,
               sizeof(pc->certificates_length));
        offset += sizeof(pc->certificates_length);

        int remain_cert_len = get_u32(pc->certificates_length);

        certificate_t *cert = pc->certificates;
        while (remain_cert_len > 0) {
            memcpy(decrypted + offset, &cert->length, sizeof(cert->length));
            offset += sizeof(cert->length);
            remain_cert_len -= sizeof(cert->length);

            memcpy(decrypted + offset, cert->certificate,
                   get_u32(cert->length));
            offset += get_u32(cert->length);
            remain_cert_len -= get_u32(cert->length);

            memcpy(decrypted + offset, &pc->cert_extensions_length,
                   sizeof(pc->cert_extensions_length));
            offset += sizeof(pc->cert_extensions_length);
            remain_cert_len -= sizeof(pc->cert_extensions_length);

            cert =
                (certificate_t *)(((uint8_t *)pc->certificates) +
                                  sizeof(cert->length) + get_u32(cert->length));
        }

        decrypted[offset++] = HANDSHAKE;
        record->plain_text.length++;
        record->length++;

        *(uint16_t *)(decrypted + 3) = htons(record->plain_text.length);

        return offset;
    }
    case CERTIFICATE_VERIFY: {
        cert_verify_tls13_t *pcv = &phs->body.certificate_verify;

        memcpy(decrypted + offset, &pcv->signature_algorithm,
               sizeof(signature_algorithm_t));
        offset += sizeof(signature_algorithm_t);

        uint16_t sig_len = htons(pcv->signature_length);
        memcpy(decrypted + offset, &sig_len, sizeof(sig_len));
        offset += sizeof(sig_len);

        memcpy(decrypted + offset, pcv->cert_signature,
               record->sess->tls13_ctx.cert_signature_len);
        offset += record->sess->tls13_ctx.cert_signature_len;

        decrypted[offset++] = HANDSHAKE;
        record->plain_text.length++;
        record->length++;

        *(uint16_t *)(decrypted + 3) = htons(record->plain_text.length);

        return offset;
    }
    case FINISHED: {
        finished_tls13_t *psf = &phs->body.server_finished_tls13;

        memcpy(decrypted + offset, psf->verify_data, HASH_SIZE_SHA384);
        offset += HASH_SIZE_SHA384;

        decrypted[offset++] = HANDSHAKE;
        record->plain_text.length++;
        record->length++;

        *(uint16_t *)(decrypted + 3) = htons(record->plain_text.length);

        return offset;
    }

    default:
        fprintf(stderr, "Unmatched Handshake.\n");
        delete_record(record->sess, record);
        abort_session(record->sess);
        return -1;
    }
}

int
attach_mac(ssl_session_t *sess, record_t *record)
{
    security_params_t *write_sp = &sess->write_sp;
    generic_block_cipher_t *block_cipher =
        &record->cipher_text.fragment.block_cipher;

#if VERBOSE_SSL
    fprintf(stderr, "[attach mac]\n");
#endif /* VERBOSE_SSL */

    ssl_crypto_op_t *op = new_ssl_crypto_op(sess);
    if (unlikely(!op))
        return -1;

    op->in = record->mac_in;
    sequence_num_t seq_num = bswap_64(record->seq_num);
    op->opcode.u32 = TLS_OPCODE_HMAC_SHA1_HASH;
#if VERBOSE_MAC
    fprintf(stderr, "\nDecrypt MAC\n");
#endif /* VERBOSE_MAC */
    if (unlikely(record->is_received)) {
        fprintf(stderr, "[attach_mac]???\n");
        exit(EXIT_FAILURE);
    } else {
        op->key = sess->server_write_MAC_secret;
        op->key_len = write_sp->mac_key_size;
        op->out_len = write_sp->mac_key_size;
        op->in_len = record->plain_text.length + sizeof(record->seq_num) +
                     RECORD_HEADER_SIZE;

        block_cipher->content = record->decrypted + RECORD_HEADER_SIZE;
        record->cipher_text.length = record->plain_text.length;
    }

    memcpy(op->in, &seq_num, sizeof(seq_num));
    op->out = record->mac_buf;
    op->data = (void *)record;

    if (unlikely(execute_mac_crypto(op) < 0)) {
        delete_op(op);

        return -1;
    }

#if VERBOSE_MAC
    fprintf(stderr, "\nmac key:\n");
    {
        for (unsigned z = 0; z < op->key_len; z++)
            fprintf(stderr, "%02X%c", op->key[z], ((z + 1) % 16) ? ' ' : '\n');
    }

    fprintf(stderr, "\nmac_in:\n");
    {
        for (unsigned z = 0; z < op->in_len; z++)
            fprintf(stderr, "%02X%c", op->in[z], ((z + 1) % 16) ? ' ' : '\n');
    }

    fprintf(stderr, "\nmac_out:\n");
    {
        for (unsigned z = 0; z < op->out_len; z++)
            fprintf(stderr, "%02X%c", op->out[z], ((z + 1) % 16) ? ' ' : '\n');
    }
#endif /* VERBOSE_MAC */

    return handle_after_mac_crypto(sess, op);
}

int
encrypt_record(ssl_session_t *sess, record_t *record)
{
    security_params_t *write_sp = &sess->write_sp;
    ssl_crypto_op_t *op = new_ssl_crypto_op(sess);

    if (unlikely(!op))
        return -1;

    if (unlikely(sess->server_write_IV_seq_num != record->seq_num)) {
        fprintf(stderr, "Something wrong with sequence number!\n");
        return -1;
    }

#if VERBOSE_SSL
    fprintf(stderr, "[encrypt Record]\n");
#endif /* VERBOSE_SSL */

    uint8_t nonce[write_sp->fixed_iv_length + write_sp->record_iv_length];
    uint8_t additional_data[RECORD_HEADER_SIZE];
    generic_aead_cipher_t *aead_cipher =
        &record->cipher_text.fragment.aead_cipher;
    sequence_num_t seq_num;

    seq_num = bswap_64(sess->send_seq_num_);

    /* Make nonce */
    memcpy(nonce, sess->tls13_ctx.server_handshake_iv, 12);
    for (int i = 0; i < 8; i++) {
        nonce[12 - 8 + i] ^= ((uint8_t *)&seq_num)[i];
    }

    /* Calculate cipher text len */
    record->cipher_text.length = record->plain_text.length + GCM_TAG_SIZE;

    /* Fill aead_cipher content */
    aead_cipher->content = record->decrypted + RECORD_HEADER_SIZE;

    op->in = aead_cipher->content;
    op->out = record->data + RECORD_HEADER_SIZE;

    memcpy(record->data, record->decrypted, RECORD_HEADER_SIZE);
    *(uint16_t *)(record->data + 3) = htons(record->cipher_text.length);

    /* Make AAD */
    memcpy(additional_data, record->data, RECORD_HEADER_SIZE);

    op->in_len = record->plain_text.length;
    op->out_len = record->cipher_text.length;
    op->iv = nonce;
    op->iv_len = write_sp->fixed_iv_length + write_sp->record_iv_length;
    op->aad = additional_data;
    op->aad_len = RECORD_HEADER_SIZE;
    op->key = sess->tls13_ctx.server_handshake_key;
    op->key_len = write_sp->enc_key_size;

    op->opcode.u32 = TLS_OPCODE_AES_GCM_256_ENCRYPT;
    op->data = (void *)record;

    record->length = record->cipher_text.length + RECORD_HEADER_SIZE;

#if VERBOSE_AES
    fprintf(stderr,
            "\n[encrypt record] op->in (aead->content) with length %d:\n",
            op->in_len);
    uint8_t z;
    for (z = 0; z < op->in_len; z++)
        fprintf(stderr, "%02X%c", op->in[z], ((z + 1) % 16) ? ' ' : '\n');

    fprintf(stderr, "\n[encrypt record] op->iv (nonce) with length %d:\n",
            op->iv_len);
    for (z = 0; z < op->iv_len; z++)
        fprintf(stderr, "%02X%c", op->iv[z], ((z + 1) % 16) ? ' ' : '\n');

    fprintf(stderr,
            "\n[encrypt record] op->aad (additional_data) with length %d:\n",
            op->aad_len);
    for (z = 0; z < op->aad_len; z++)
        fprintf(stderr, "%02X%c", op->aad[z], ((z + 1) % 16) ? ' ' : '\n');

    fprintf(
        stderr,
        "\n[encrypt record] op->key (sess->server_write_key) with length %d:\n",
        op->key_len);
    for (z = 0; z < op->key_len; z++)
        fprintf(stderr, "%02X%c", op->key[z], ((z + 1) % 16) ? ' ' : '\n');
#endif /* VERBOSE_AES */

    if (unlikely(execute_aes_crypto(sess->ctx->symmetric_crypto_ctx, op) < 0)) {
        delete_op(op);

        return -1;
    }

#if VERBOSE_AES
    fprintf(stderr, "\n[encrypt record] Encrypted Data with Total Length %lu\n",
            record->length);
    {
        int z;
        for (z = 0; z < 160; z++)
            fprintf(stderr, "%02X%c", record->data[z],
                    ((z + 1) % 16) ? ' ' : '\n');
    }
#endif /* VERBOSE_AES */

    return handle_after_aes_crypto(sess, op);
}

/*--------------------------------- MISC ------------------------------------*/
int
handle_after_rsa_crypto(ssl_session_t *sess, ssl_crypto_op_t *op)
{
    int ret = -1;
    record_t *record = (record_t *)op->data;
    int crypto_type = op->opcode.s.op;
    if (unlikely(!record))
        return -1;

    assert(op->opcode.s.function == TLS_RSA);

#if VERBOSE_SSL
    fprintf(stderr, "Handle after RSA Crypto\n");
#endif /* VERBOSE_SSL */

    if (likely(crypto_type == PRIVATE_DECRYPT)) {
        ret = handle_after_private_decrypt(sess, record, op);
    } else
        assert(0);

    delete_op(op);

    return ret;
}

int
handle_after_private_decrypt(ssl_session_t *sess, record_t *record,
                             ssl_crypto_op_t *op)
{
    UNUSED(sess); /* for fnptr */

    premaster_secret_t *pms =
        &record->fragment.handshake.body.client_key_exchange.pms;

    assert(op->pka_out->result_cnt == 1);
    operand_to_string(&op->pka_out->results[0], (uint8_t *)pms, 48u);

#if VERBOSE_KEY
    fprintf(stderr, "\n[handle after private decrypt] pre-master:\n");
    {
        int z;
        for (z = 0; z < 48; z++)
            fprintf(stderr, "%02X%c", *((uint8_t *)pms + z),
                    ((z + 1) % 16) ? ' ' : '\n');
    }
#endif /* VERBOSE_KEY */

    return 0;
}

int
handle_after_aes_crypto(ssl_session_t *sess, ssl_crypto_op_t *op)
{
    int ret = -1;
    int invalid = 0;
    record_t *record = (record_t *)op->data;
    int crypto_type = op->opcode.s.op;
    int function = op->opcode.s.function;

    if (unlikely(!record))
        return -1;

#if VERBOSE_SSL
    fprintf(stderr, "Handle after AES Crypto\n");
#endif /* VERBOSE_SSL */

    /* error check */
    if (unlikely(crypto_type < ENCRYPT || crypto_type > DECRYPT)) {
        fprintf(stderr,
                "[handle after aes crypto] invalid crypto_type: %d (expected "
                "%d~%d)\n",
                crypto_type, ENCRYPT, DECRYPT);
        invalid = TRUE;
    }

    if (unlikely(function < TLS_AES_CBC || function > TLS_AES_GCM)) {
        fprintf(
            stderr,
            "[handle after aes crypto] invalid function: %d (expected %d~%d)\n",
            function, TLS_AES_CBC, TLS_AES_GCM);
        invalid = TRUE;
    }

    if (unlikely(invalid)) {
        delete_op(op);
        return -1;
    }

    if (crypto_type == ENCRYPT)
        sess->send_seq_num_++;

    crypto_func_t func = handle_after[crypto_type][function];

    ret = func(sess, record, op);

    delete_op(op);

    return ret;
}

int
handle_after_aes_cbc_encrypt(ssl_session_t *sess, record_t *record,
                             ssl_crypto_op_t *op)
{
    assert(record->state == TO_ENCRYPT);
    record->state = WRITE_READY;

#if VERBOSE_STATE
    fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
            ((ssl_session_t *)record->sess)->parent->session_id, record->id,
            state_to_string(TO_ENCRYPT), state_to_string(record->state));
#endif /* VERBOSE_STATE */

    memcpy(sess->server_write_IV,
           op->out + op->out_len - sess->write_sp.fixed_iv_length,
           sess->write_sp.fixed_iv_length);

    sess->server_write_IV_seq_num = record->seq_num + 1;

    return 0;
}

int
handle_after_aes_cbc_decrypt(ssl_session_t *sess, record_t *record,
                             ssl_crypto_op_t *op)
{
    assert(record->state == TO_DECRYPT);
    record->state = TO_VERIFY_MAC;

#if VERBOSE_STATE
    fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
            ((ssl_session_t *)record->sess)->parent->session_id, record->id,
            state_to_string(TO_DECRYPT), state_to_string(record->state));
#endif /* VERBOSE_STATE */

#if VERBOSE_AES
    unsigned z = 0;
    fprintf(stderr,
            "\n[handle after aes cbc decrypt] op->in (original data):\n\n");
    {
        for (z = 0; z < op->in_len; z++)
            fprintf(stderr, "%02X%c", *((uint8_t *)(op->in) + z),
                    ((z + 1) % 16) ? ' ' : '\n');
    }

    fprintf(stderr,
            "\n[handle after aes cbc decrypt] op->out (decrypted data):\n\n");
    {
        for (z = 0; z < op->out_len; z++)
            fprintf(stderr, "%02X%c", *((uint8_t *)(op->out) + z),
                    ((z + 1) % 16) ? ' ' : '\n');
    }
#else  /* VERBOSE_AES */
    UNUSED(op);
#endif /* !VERBOSE_AES */

    sess->client_write_IV_seq_num = record->seq_num + 1;

    return 0;
}

int
handle_after_aes_gcm_encrypt(ssl_session_t *sess, record_t *record,
                             ssl_crypto_op_t *op)
{
    UNUSED(op);

    if (record->state != TO_ENCRYPT) {
        fprintf(stderr,
                "[handle after aes gcm encrypt] wrong record->state: %d!\n",
                record->state);
        return -1;
    }

    record->state = WRITE_READY;

#if VERBOSE_STATE
    fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
            ((ssl_session_t *)record->sess)->parent->session_id, record->id,
            state_to_string(TO_ENCRYPT), state_to_string(record->state));
#endif /* VERBOSE_STATE */

    sess->server_write_IV_seq_num = record->seq_num + 1;

    return 0;
}

int
handle_after_aes_gcm_decrypt(ssl_session_t *sess, record_t *record,
                             ssl_crypto_op_t *op)
{
    assert(record->state == TO_DECRYPT);
    record->state = TO_VERIFY_MAC;

#if VERBOSE_STATE
    fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
            ((ssl_session_t *)record->sess)->parent->session_id, record->id,
            state_to_string(TO_DECRYPT), state_to_string(record->state));
#endif /* VERBOSE_STATE */

#if VERBOSE_AES
    unsigned z = 0;
    fprintf(stderr, "\noriginal data:\n\n");
    {
        for (z = 0; z < op->in_len; z++)
            fprintf(stderr, "%02X%c", *((uint8_t *)(op->in) + z),
                    ((z + 1) % 16) ? ' ' : '\n');
    }

    fprintf(stderr, "\ndecrypted data:\n\n");
    {
        for (z = 0; z < op->out_len; z++)
            fprintf(stderr, "%02X%c", *((uint8_t *)(op->out) + z),
                    ((z + 1) % 16) ? ' ' : '\n');
    }
#else  /* VERBOSE_AES */
    UNUSED(op);
#endif /* !VERBOSE_AES */

    sess->client_write_IV_seq_num = record->seq_num + 1;

    return 0;
}

int
handle_after_ecdhe_key_gen(ssl_session_t *sess, record_t *record,
                           ssl_crypto_op_t *op)
{
    // copy_operand(&op->pka_out->results[0], sess->ecdhe_pub_key);
    copy_operand(&sess->pka_results->results[0], sess->ecdhe_pub_key);

#if VERBOSE_KEY
    fprintf(stderr,
            "\n[handle after ecdhe key gen] ecdhe pub key is generated\n");
    fprintf(stderr, "generated pub key:\n");
    {
        for (unsigned z = 0; z < X25519_KEY_LEN; z++)
            fprintf(stderr, "%02X%c", sess->ecdhe_pub_key->buf_ptr[z],
                    ((z + 1) % 16) ? ' ' : '\n');
    }
#endif /* VERBOSE_KEY */

#if VERBOSE_PKA_OP
    num_key_gen[sess->coreid]++;
#endif /* VERBOSE_PKA_OP */

    return 0;
}

int
handle_after_ecdhe_shared_secret_calc(ssl_session_t *sess, record_t *record,
                                      ssl_crypto_op_t *op)
{
    /* Verified: it works correctly. */
    sess->pending_pka_op = NULL;

    uint8_t shared_secret_be[X25519_KEY_LEN];
    uint8_t shared_secret[X25519_KEY_LEN];
    uint8_t hello_hash[MAX_HASH_SIZE];
    uint8_t early_secret[MAX_HASH_SIZE];
    uint8_t early_secret_salt[48] = {0};
    uint8_t empty_hash[MAX_HASH_SIZE];
    uint8_t derived_secret[MAX_HASH_SIZE];

#if DEBUG_TLS_1_3
    fprintf(stderr, "\n[handle_after_ecdhe_shared_secret_calc] calculating "
                    "shared secret...\n");
#endif /* DEBUG_TLS_1_3 */

    // operand_to_string(&op->pka_out->results[0],
    //                     shared_secret_be,
    //                     X25519_KEY_LEN); /* assume X25519 */
    operand_to_string(&sess->pka_results->results[0], shared_secret_be,
                      X25519_KEY_LEN); /* assume X25519 */
    /* X25519 shared secret is in big-endian, need to convert to little-endian
     */
    byte_swap_copy(shared_secret, shared_secret_be, X25519_KEY_LEN);

    if (COMPARE_CIPHER(sess->pending_sp.cipher, TLS_AES_256_GCM_SHA384)) {
        /* Server Handshake Keys Calc */
        SHA384(sess->handshake_msgs, sess->handshake_msgs_len, hello_hash);

        if (hkdf_extract(sess->ctx->t_hmac_ctx, early_secret, 48,
                         early_secret_salt, 48, early_secret_salt, 48,
                         sha384) == 0) {
            fprintf(stderr, "hkdf_extract failed!\n");
            return -1;
        }

        SHA384(NULL, 0, empty_hash);

        if (hkdf_expand_label(sess->ctx->t_hmac_ctx, derived_secret, 48,
                              early_secret, 48, "derived", strlen("derived"),
                              empty_hash, 48, sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }

        if (hkdf_extract(sess->ctx->t_hmac_ctx,
                         sess->tls13_ctx.handshake_secret, 48, derived_secret,
                         48, shared_secret, 32, sha384) == 0) {
            fprintf(stderr, "hkdf_extract failed!\n");
            return -1;
        }

        if (hkdf_expand_label(
                sess->ctx->t_hmac_ctx, sess->tls13_ctx.client_secret, 48,
                sess->tls13_ctx.handshake_secret, 48, "c hs traffic",
                strlen("c hs traffic"), hello_hash, 48, sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }

        if (hkdf_expand_label(
                sess->ctx->t_hmac_ctx, sess->tls13_ctx.server_secret, 48,
                sess->tls13_ctx.handshake_secret, 48, "s hs traffic",
                strlen("s hs traffic"), hello_hash, 48, sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }

        if (hkdf_expand_label(
                sess->ctx->t_hmac_ctx, sess->tls13_ctx.client_handshake_key, 32,
                sess->tls13_ctx.client_secret, 48, "key", strlen("key"),
                (unsigned char *)"", 0, sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }

        if (hkdf_expand_label(
                sess->ctx->t_hmac_ctx, sess->tls13_ctx.server_handshake_key, 32,
                sess->tls13_ctx.server_secret, 48, "key", strlen("key"),
                (unsigned char *)"", 0, sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }

        if (hkdf_expand_label(
                sess->ctx->t_hmac_ctx, sess->tls13_ctx.client_handshake_iv, 12,
                sess->tls13_ctx.client_secret, 48, "iv", strlen("iv"),
                (unsigned char *)"", 0, sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }

        if (hkdf_expand_label(
                sess->ctx->t_hmac_ctx, sess->tls13_ctx.server_handshake_iv, 12,
                sess->tls13_ctx.server_secret, 48, "iv", strlen("iv"),
                (unsigned char *)"", 0, sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }
    }

#if HKDF_TWICE
    if (COMPARE_CIPHER(sess->pending_sp.cipher, TLS_AES_256_GCM_SHA384)) {
        /* Server Handshake Keys Calc */
        SHA384(sess->handshake_msgs, sess->handshake_msgs_len, hello_hash);

        if (hkdf_extract(early_secret, 48, early_secret_salt, 48,
                         early_secret_salt, 48, sha384) == 0) {
            fprintf(stderr, "hkdf_extract failed!\n");
            return -1;
        }

        SHA384(NULL, 0, empty_hash);

        if (hkdf_expand_label(derived_secret, 48, early_secret, 48, "derived",
                              strlen("derived"), empty_hash, 48, sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }

        if (hkdf_extract(sess->tls13_ctx.handshake_secret, 48, derived_secret,
                         48, shared_secret, 32, sha384) == 0) {
            fprintf(stderr, "hkdf_extract failed!\n");
            return -1;
        }

        if (hkdf_expand_label(sess->tls13_ctx.client_secret, 48,
                              sess->tls13_ctx.handshake_secret, 48,
                              "c hs traffic", strlen("c hs traffic"),
                              hello_hash, 48, sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }

        if (hkdf_expand_label(sess->tls13_ctx.server_secret, 48,
                              sess->tls13_ctx.handshake_secret, 48,
                              "s hs traffic", strlen("s hs traffic"),
                              hello_hash, 48, sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }

        if (hkdf_expand_label(sess->tls13_ctx.client_handshake_key, 32,
                              sess->tls13_ctx.client_secret, 48, "key",
                              strlen("key"), (unsigned char *)"", 0,
                              sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }

        if (hkdf_expand_label(sess->tls13_ctx.server_handshake_key, 32,
                              sess->tls13_ctx.server_secret, 48, "key",
                              strlen("key"), (unsigned char *)"", 0,
                              sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }

        if (hkdf_expand_label(sess->tls13_ctx.client_handshake_iv, 12,
                              sess->tls13_ctx.client_secret, 48, "iv",
                              strlen("iv"), (unsigned char *)"", 0,
                              sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }

        if (hkdf_expand_label(sess->tls13_ctx.server_handshake_iv, 12,
                              sess->tls13_ctx.server_secret, 48, "iv",
                              strlen("iv"), (unsigned char *)"", 0,
                              sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }
    }
#endif /* HKDF_TWICE */

#if VERBOSE_KEY
    fprintf(stderr, "shared secret:\n");
    {
        for (unsigned z = 0; z < 32; z++)
            fprintf(stderr, "%02X%c", shared_secret[z],
                    ((z + 1) % 16) ? ' ' : '\n');
    }

    fprintf(stderr, "hello hash:\n");
    {
        for (unsigned z = 0; z < 48; z++)
            fprintf(stderr, "%02X%c", hello_hash[z],
                    ((z + 1) % 16) ? ' ' : '\n');
    }

    fprintf(stderr, "early secret:\n");
    {
        for (unsigned z = 0; z < 48; z++)
            fprintf(stderr, "%02X%c", early_secret[z],
                    ((z + 1) % 16) ? ' ' : '\n');
    }

    fprintf(stderr, "derived secret:\n");
    {
        for (unsigned z = 0; z < 48; z++)
            fprintf(stderr, "%02X%c", derived_secret[z],
                    ((z + 1) % 16) ? ' ' : '\n');
    }

    fprintf(stderr, "handshake secret:\n");
    {
        for (unsigned z = 0; z < 48; z++)
            fprintf(stderr, "%02X%c", sess->tls13_ctx.handshake_secret[z],
                    ((z + 1) % 16) ? ' ' : '\n');
    }

    fprintf(stderr, "client secret:\n");
    {
        for (unsigned z = 0; z < 48; z++)
            fprintf(stderr, "%02X%c", sess->tls13_ctx.client_secret[z],
                    ((z + 1) % 16) ? ' ' : '\n');
    }

    fprintf(stderr, "server secret:\n");
    {
        for (unsigned z = 0; z < 48; z++)
            fprintf(stderr, "%02X%c", sess->tls13_ctx.server_secret[z],
                    ((z + 1) % 16) ? ' ' : '\n');
    }

    fprintf(stderr, "server handshake key:\n");
    {
        for (unsigned z = 0; z < 32; z++)
            fprintf(stderr, "%02X%c", sess->tls13_ctx.server_handshake_key[z],
                    ((z + 1) % 16) ? ' ' : '\n');
    }

    fprintf(stderr, "server handshake iv:\n");
    {
        for (unsigned z = 0; z < 12; z++)
            fprintf(stderr, "%02X%c", sess->tls13_ctx.server_handshake_iv[z],
                    ((z + 1) % 16) ? ' ' : '\n');
    }
#endif /* VERBOSE_KEY */

    sess->tls13_ctx.handshake_key_calculated = TRUE;

#if DEBUG_TLS_1_3
    fprintf(stderr, "\n[handle_after_ecdhe_shared_secret_calc] shared secret "
                    "is calculated\n");
#endif /* DEBUG_TLS_1_3 */

#if VERBOSE_PKA_OP
    num_calc_shared_secret[sess->coreid]++;
#endif /* VERBOSE_PKA_OP */

    return 0;
}

void
remove_leading_zeros(uint8_t *buf, uint16_t *len)
{
    int offset = 0;
    while (offset < *len && buf[offset] == 0x00)
        offset++;

    if (offset > 0) {
        memmove(buf, buf + offset, *len - offset);
        *len -= offset;
    }
}

int
handle_after_ecdsa_signature(ssl_session_t *sess, record_t *record,
                             ssl_crypto_op_t *op)
{
    sess->pending_pka_op_1 = NULL;

    uint8_t *signature = sess->tls13_ctx.cert_signature;
    uint8_t r_buf_le[128], s_buf_le[128];
    uint8_t r_buf[128], s_buf[128];
    int r_msb = 0, s_msb = 0;
    int offset = 0;
    uint16_t r_len, s_len;

    r_buf[0] = 0x00;
    s_buf[0] = 0x00;

    // operand_to_string(&op->pka_out->results[0], r_buf + 1,
    // op->pka_out->results[0].actual_len);
    // operand_to_string(&op->pka_out->results[1], s_buf + 1,
    // op->pka_out->results[1].actual_len);
    operand_to_string(&sess->pka_results->results[0], r_buf + 1,
                      sess->pka_results->results[0].actual_len);
    operand_to_string(&sess->pka_results->results[1], s_buf + 1,
                      sess->pka_results->results[1].actual_len);

    // r_len = op->pka_out->results[0].actual_len;
    // s_len = op->pka_out->results[1].actual_len;
    r_len = sess->pka_results->results[0].actual_len;
    s_len = sess->pka_results->results[1].actual_len;

    remove_leading_zeros(r_buf + 1, &r_len);
    remove_leading_zeros(s_buf + 1, &s_len);

    /* if the highest bit is 1, prepend a 0x00 */
    if (r_buf[1] & 0x80) {
        r_len++;
        r_msb = TRUE;
    }

    if (s_buf[1] & 0x80) {
        s_len++;
        s_msb = TRUE;
    }

    signature[offset++] = 0x30;                  // ASN.1 SEQUENCE
    signature[offset++] = 2 + r_len + 2 + s_len; // Length

    signature[offset++] = 0x02;  // ASN.1 INTEGER
    signature[offset++] = r_len; // Length

    if (!r_msb)
        memcpy(signature + offset, r_buf + 1, r_len);
    else
        memcpy(signature + offset, r_buf, r_len);
    offset += r_len;

    signature[offset++] = 0x02;  // ASN.1 INTEGER
    signature[offset++] = s_len; // Length

    if (!s_msb)
        memcpy(signature + offset, s_buf + 1, s_len);
    else
        memcpy(signature + offset, s_buf, s_len);
    offset += s_len;

    sess->tls13_ctx.cert_signature_len = offset;

    sess->tls13_ctx.cert_signatured = TRUE;

#if VERBOSE_SIG
    fprintf(stderr, "\n[handle after ecdsa signature] certificate signature is "
                    "generated\n");
    fprintf(stderr, "signature:\n");
    {
        for (unsigned z = 0; z < sess->tls13_ctx.cert_signature_len; z++)
            fprintf(stderr, "%02X%c", signature[z],
                    ((z + 1) % 16) ? ' ' : '\n');
    }
    fprintf(stderr, "\n");
#endif /* VERBOSE_SIG */

#if VERBOSE_PKA_OP
    num_signature_cert[sess->coreid]++;
#endif /* VERBOSE_PKA_OP */

    return 0;
}

int
handle_app_keys_calculation(ssl_session_t *sess)
{
#if VERBOSE_CONN_LAT
    clock_gettime(CLOCK_MONOTONIC, &sess->app_key_cal_time);
    uint64_t gen_cv_app_key_cal_lat =
        (sess->app_key_cal_time.tv_sec - sess->gen_cv_time.tv_sec) *
            1000000000L +
        (sess->app_key_cal_time.tv_nsec - sess->gen_cv_time.tv_nsec);

    if (gen_cv_app_key_cal_lat > max_gen_cv_app_key_cal_lat[sess->coreid]) {
        max_gen_cv_app_key_cal_lat[sess->coreid] = gen_cv_app_key_cal_lat;
    }

    sum_gen_cv_app_key_cal_lat[sess->coreid] += gen_cv_app_key_cal_lat;
    num_app_key_cal[sess->coreid]++;
#endif /* VERBOSE_CONN_LAT */

    uint8_t empty_hash[MAX_HASH_SIZE];
    uint8_t handshake_hash[MAX_HASH_SIZE];
    uint8_t derived_secret[MAX_HASH_SIZE];
    uint8_t empty_salt[48] = {0};
    uint8_t master_secret[MAX_HASH_SIZE];
    uint8_t app_client_secret[MAX_HASH_SIZE];
    uint8_t app_server_secret[MAX_HASH_SIZE];

    if (COMPARE_CIPHER(sess->pending_sp.cipher, TLS_AES_256_GCM_SHA384)) {
        SHA384(NULL, 0, empty_hash);

        SHA384(sess->handshake_msgs, sess->handshake_msgs_len, handshake_hash);

        if (hkdf_expand_label(sess->ctx->t_hmac_ctx, derived_secret, 48,
                              sess->tls13_ctx.handshake_secret, 48, "derived",
                              strlen("derived"), empty_hash, 48, sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }

        if (hkdf_extract(sess->ctx->t_hmac_ctx, master_secret, 48,
                         derived_secret, 48, empty_salt, 48, sha384) == 0) {
            fprintf(stderr, "hkdf_extract failed!\n");
            return -1;
        }

        if (hkdf_expand_label(sess->ctx->t_hmac_ctx, app_client_secret, 48,
                              master_secret, 48, "c ap traffic",
                              strlen("c ap traffic"), handshake_hash, 48,
                              sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }

        if (hkdf_expand_label(sess->ctx->t_hmac_ctx, app_server_secret, 48,
                              master_secret, 48, "s ap traffic",
                              strlen("s ap traffic"), handshake_hash, 48,
                              sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }

        if (hkdf_expand_label(sess->ctx->t_hmac_ctx,
                              sess->tls13_ctx.client_application_key, 32,
                              app_client_secret, 48, "key", strlen("key"),
                              (unsigned char *)"", 0, sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }

        if (hkdf_expand_label(sess->ctx->t_hmac_ctx,
                              sess->tls13_ctx.server_application_key, 32,
                              app_server_secret, 48, "key", strlen("key"),
                              (unsigned char *)"", 0, sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }

        if (hkdf_expand_label(sess->ctx->t_hmac_ctx,
                              sess->tls13_ctx.client_application_iv, 12,
                              app_client_secret, 48, "iv", strlen("iv"),
                              (unsigned char *)"", 0, sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }

        if (hkdf_expand_label(sess->ctx->t_hmac_ctx,
                              sess->tls13_ctx.server_application_iv, 12,
                              app_server_secret, 48, "iv", strlen("iv"),
                              (unsigned char *)"", 0, sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }

#if HKDF_TWICE
        if (hkdf_expand_label(derived_secret, 48,
                              sess->tls13_ctx.handshake_secret, 48, "derived",
                              strlen("derived"), empty_hash, 48, sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }

        if (hkdf_extract(master_secret, 48, derived_secret, 48, empty_salt, 48,
                         sha384) == 0) {
            fprintf(stderr, "hkdf_extract failed!\n");
            return -1;
        }

        if (hkdf_expand_label(app_client_secret, 48, master_secret, 48,
                              "c ap traffic", strlen("c ap traffic"),
                              handshake_hash, 48, sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }

        if (hkdf_expand_label(app_server_secret, 48, master_secret, 48,
                              "s ap traffic", strlen("s ap traffic"),
                              handshake_hash, 48, sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }

        if (hkdf_expand_label(sess->tls13_ctx.client_application_key, 32,
                              app_client_secret, 48, "key", strlen("key"),
                              (unsigned char *)"", 0, sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }

        if (hkdf_expand_label(sess->tls13_ctx.server_application_key, 32,
                              app_server_secret, 48, "key", strlen("key"),
                              (unsigned char *)"", 0, sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }

        if (hkdf_expand_label(sess->tls13_ctx.client_application_iv, 12,
                              app_client_secret, 48, "iv", strlen("iv"),
                              (unsigned char *)"", 0, sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }

        if (hkdf_expand_label(sess->tls13_ctx.server_application_iv, 12,
                              app_server_secret, 48, "iv", strlen("iv"),
                              (unsigned char *)"", 0, sha384) == 0) {
            fprintf(stderr, "hkdf_expand_label failed!\n");
            return -1;
        }
#endif /* HKDF_TWICE */

#if VERBOSE_KEY
        fprintf(stderr, "\n[handle app keys calculation] application keys are "
                        "calculated\n");
        fprintf(stderr, "app client secret:\n");
        {
            for (unsigned z = 0; z < 48; z++)
                fprintf(stderr, "%02X%c", app_client_secret[z],
                        ((z + 1) % 16) ? ' ' : '\n');
        }
        fprintf(stderr, "app server secret:\n");
        {
            for (unsigned z = 0; z < 48; z++)
                fprintf(stderr, "%02X%c", app_server_secret[z],
                        ((z + 1) % 16) ? ' ' : '\n');
        }
        fprintf(stderr, "client application key:\n");
        {
            for (unsigned z = 0; z < 32; z++)
                fprintf(stderr, "%02X%c",
                        sess->tls13_ctx.client_application_key[z],
                        ((z + 1) % 16) ? ' ' : '\n');
        }
        fprintf(stderr, "server application key:\n");
        {
            for (unsigned z = 0; z < 32; z++)
                fprintf(stderr, "%02X%c",
                        sess->tls13_ctx.server_application_key[z],
                        ((z + 1) % 16) ? ' ' : '\n');
        }
        fprintf(stderr, "client application iv:\n");
        {
            for (unsigned z = 0; z < 12; z++)
                fprintf(stderr, "%02X%c",
                        sess->tls13_ctx.client_application_iv[z],
                        ((z + 1) % 16) ? ' ' : '\n');
        }
        fprintf(stderr, "\n");
        fprintf(stderr, "server application iv:\n");
        {
            for (unsigned z = 0; z < 12; z++)
                fprintf(stderr, "%02X%c",
                        sess->tls13_ctx.server_application_iv[z],
                        ((z + 1) % 16) ? ' ' : '\n');
        }
        fprintf(stderr, "\n");
#endif /* VERBOSE_KEY */
    }

#if VERBOSE_CONN_LAT
    clock_gettime(CLOCK_MONOTONIC, &sess->cal_app_key_time);
    uint64_t app_key_cal_cal_app_key_lat =
        (sess->cal_app_key_time.tv_sec - sess->app_key_cal_time.tv_sec) *
            1000000000L +
        (sess->cal_app_key_time.tv_nsec - sess->app_key_cal_time.tv_nsec);

    if (app_key_cal_cal_app_key_lat >
        max_app_key_cal_cal_app_key_lat[sess->coreid]) {
        max_app_key_cal_cal_app_key_lat[sess->coreid] =
            app_key_cal_cal_app_key_lat;
    }

    sum_app_key_cal_cal_app_key_lat[sess->coreid] +=
        app_key_cal_cal_app_key_lat;
    num_cal_app_key[sess->coreid]++;
#endif /* VERBOSE_CONN_LAT */
}

int
handle_verify_data_calculation(ssl_session_t *sess)
{
    uint8_t finished_key[48];
    uint8_t finished_hash[48];
    int out_len;

    if (unlikely(
            hkdf_expand_label(sess->ctx->t_hmac_ctx, finished_key,
                              HASH_SIZE_SHA384, sess->tls13_ctx.client_secret,
                              HASH_SIZE_SHA384, "finished", strlen("finished"),
                              (unsigned char *)"", 0, sha384) == 0)) {
        fprintf(stderr, "hkdf_expand_label for finished_key failed\n");
        exit(EXIT_FAILURE);
    }

    SHA384(sess->handshake_msgs, sess->handshake_msgs_len, finished_hash);

    HMAC_Init_ex(sess->ctx->t_hmac_ctx, finished_key, sizeof(finished_key),
                 sha384, NULL);
    HMAC_Update(sess->ctx->t_hmac_ctx, finished_hash, HASH_SIZE_SHA384);
    HMAC_Final(sess->ctx->t_hmac_ctx, sess->tls13_ctx.calculated_vd, &out_len);
}

int
handle_after_mac_crypto(ssl_session_t *sess, ssl_crypto_op_t *op)
{
    int ret = -1;
    record_t *record = (record_t *)op->data;

    if (unlikely(!record))
        return -1;

    assert(op->opcode.s.function == TLS_HMAC_SHA1);

#if VERBOSE_SSL
    fprintf(stderr, "Handle after MAC Crypto\n");
#endif /* VERBOSE_SSL */

    ret = handle_mac(sess, record, op);

    delete_op(op);

    return ret;
}

int
handle_mac(ssl_session_t *sess, record_t *record, ssl_crypto_op_t *op)
{
    int diff = 0;
    unsigned z = 0;
    generic_block_cipher_t *block_cipher =
        &record->cipher_text.fragment.block_cipher;
    security_params_t *read_sp = &sess->read_sp;

    assert(record->state == TO_APPEND_MAC || record->state == TO_VERIFY_MAC);

    if (record->is_received) {
        uint8_t *recv_mac = block_cipher->mac;

#if VERBOSE_SSL
        fprintf(stderr, "\n[HANDLE MAC] VERIFY MAC\n");
#endif /* VERBOSE_SSL */

#if VERBOSE_MAC
        fprintf(stderr, "\nmac received:\n");
        {
            for (z = 0; z < read_sp->mac_key_size; z++)
                fprintf(stderr, "%02X%c", recv_mac[z],
                        ((z + 1) % 16) ? ' ' : '\n');
        }
#endif /* VERBOSE_MAC */

        /* We should not use memcmp() or break; for preventing timing attack */
        for (z = 0; z < read_sp->mac_key_size; z++)
            diff |= op->out[z] ^ recv_mac[z];

        if (unlikely(diff)) {
            fprintf(stderr, "[HANDLE MAC] mac verify failed!\n");
            delete_record(sess, record);
            abort_session(sess);
            return -1;
        } else {
#if VERBOSE_MAC
            fprintf(stderr, "\nCorrect MAC!!\n");
#endif /* VERBOSE_MAC */

            return 0;
        }

    } else {
#if VERBOSE_SSL
        fprintf(stderr, "\n[HANDLE MAC] APPEND MAC\n");
#endif /* VERBOSE_SSL */

        block_cipher->mac =
            record->decrypted + record->plain_text.length + RECORD_HEADER_SIZE;
        memcpy(block_cipher->mac, op->out, op->out_len);

        record->cipher_text.length += op->out_len;
        record->length += op->out_len;
        *(uint16_t *)(record->decrypted + 3) =
            htons(record->cipher_text.length);

#if VERBOSE_STATE
        fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
                sess->parent->session_id, record->id,
                state_to_string(TO_APPEND_MAC), state_to_string(record->state));
#endif /* VERBOSE_STATE */

        return 0;
    }

    /* can't reach here */
    return -1;
}
