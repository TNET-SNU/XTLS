#define _POSIX_C_SOURCE 199309L
#define _GNU_SOURCE

#include <time.h>

#include "ssloff.h"
#include "ssl_crypto.h"
#include "ring.h"

#define RAND_MAX_LOCAL (1073741823lu*4lu + 3lu)

extern int host_threads_num;

#if VERBOSE_CONN_LAT
extern int num_ch[MAX_CPUS];
extern int num_sh_sc_shd[MAX_CPUS];
extern int num_cke[MAX_CPUS];
extern int num_rsa_decrypt[MAX_CPUS];
extern int num_decrypt_rsa[MAX_CPUS];
extern int num_meta_tx[MAX_CPUS];
extern int num_meta_rx[MAX_CPUS];
extern int num_hws_insert[MAX_CPUS];
extern int num_hws_apply[MAX_CPUS];
extern int num_app_data[MAX_CPUS];

extern uint64_t sum_syn_ch_lat[MAX_CPUS];
extern uint64_t max_syn_ch_lat[MAX_CPUS];
extern uint64_t sum_ch_sh_sc_shd_lat[MAX_CPUS]; /* ch - sh/sc/shd */
extern uint64_t max_ch_sh_sc_shd_lat[MAX_CPUS];
extern uint64_t sum_sh_sc_shd_cke_lat[MAX_CPUS]; /* sh/sc/shd - cke */
extern uint64_t max_sh_sc_shd_cke_lat[MAX_CPUS];
extern uint64_t sum_cke_rsa_decrypt_lat[MAX_CPUS]; /* cke - rsa decrypt req. */
extern uint64_t max_cke_rsa_decrypt_lat[MAX_CPUS];
extern uint64_t sum_rsa_decrypt_decrypt_rsa_lat[MAX_CPUS]; /* rsa decrypt latency */
extern uint64_t max_rsa_decrypt_decrypt_rsa_lat[MAX_CPUS];
extern uint64_t sum_decrypt_rsa_meta_tx_lat[MAX_CPUS]; /* decrypt rsa - meta tx */
extern uint64_t max_decrypt_rsa_meta_tx_lat[MAX_CPUS];
extern uint64_t sum_meta_tx_meta_rx_lat[MAX_CPUS]; /* meta tx/rx */
extern uint64_t max_meta_tx_meta_rx_lat[MAX_CPUS];
extern uint64_t sum_meta_rx_hws_insert_lat[MAX_CPUS]; /* meta rx - hws insert */
extern uint64_t max_meta_rx_hws_insert_lat[MAX_CPUS];
extern uint64_t sum_hws_insert_hws_apply_lat[MAX_CPUS]; /* hws latency */
extern uint64_t max_hws_insert_hws_apply_lat[MAX_CPUS];
extern uint64_t sum_hws_apply_app_data_lat[MAX_CPUS]; /* app data latency */
extern uint64_t max_hws_apply_app_data_lat[MAX_CPUS];

extern uint64_t sum_conn_lat[MAX_CPUS];
extern uint64_t max_conn_lat[MAX_CPUS];
#endif /* VERBOSE_CONN_LAT */
/*--------------------------- FUNCTION PROTOTYPE ----------------------------*/
cipher_suite_t
select_cipher(uint16_t length, cipher_suite_t* cipher_suites);

void
init_record(record_t* record,
            const sequence_num_t seq, const int is_received_);

record_t* 
new_recv_record(ssl_session_t* sess);

record_t* 
new_send_record(ssl_session_t* sess);

int
store_handshake(ssl_session_t* sess, record_t* record);

void
delete_record(ssl_session_t* sess, record_t* record);

void
delete_op(ssl_crypto_op_t* op);

int
process_new_record(ssl_session_t* sess, uint8_t* buf, uint16_t len);

void
push_read_record(ssl_session_t* sess, record_t* record);

void
unpack_header(record_t* record);

int
decrypt_record(ssl_session_t* sess, record_t* record);

int
submit_pka_request(thread_context_t *ctx, ssl_crypto_op_t* op);

int
rsa_decrypt_record(ssl_session_t* sess, record_t* record);

void
handle_submitted_pka(thread_context_t* ctx);

void
handle_completed_pka(thread_context_t* ctx);

int
get_processed_crypto(ssl_session_t *sess);

int
verify_mac(ssl_session_t* sess, record_t* record);

int
unpack_record(record_t* record);

int
unpack_handshake(record_t* record);

int
unpack_change_cipher_spec(void);

int
unpack_alert(record_t* record);

int
unpack_application_data(record_t* record);

int
process_read_record(ssl_session_t* sess, record_t* record);

int
handle_read_record(ssl_session_t* sess, record_t* record);

int
handle_handshake(ssl_session_t* sess, record_t* record);

int
handle_change_cipher_spec(ssl_session_t* sess, record_t* record);

int
handle_alert(ssl_session_t* sess, record_t* record);

int
handle_data(ssl_session_t* sess, record_t* record);

int
send_server_hello(ssl_session_t* sess);

int
send_certificate(ssl_session_t* sess);

int
send_server_hello_done(ssl_session_t* sess);

int
send_change_cipher_spec(ssl_session_t* sess);

int
make_sccs_sf(ssl_session_t* sess);

int
send_server_finish(ssl_session_t* sess);

int
send_handshake(ssl_session_t* sess, record_t* record,
               uint8_t msg_type, int length, int last);

int
send_record(ssl_session_t* sess, record_t* record,
            uint8_t record_type, int length, int send_type);

int
pack_record(record_t* record);

int
pack_handshake(record_t* record, int offset);

int
pack_change_cipher_spec(record_t* record, int offset);

int
attach_mac(ssl_session_t* sess, record_t* record);

int
encrypt_record(ssl_session_t* sess, record_t* record);

int
handle_after_rsa_crypto(ssl_session_t* sess,
						ssl_crypto_op_t* op);

int
handle_after_private_decrypt(ssl_session_t* sess, record_t* record, ssl_crypto_op_t* op);

int
handle_after_aes_crypto(ssl_session_t* sess,
						ssl_crypto_op_t* op);

int
handle_after_aes_cbc_encrypt(ssl_session_t* sess,
                             record_t* record, ssl_crypto_op_t* op);

int
handle_after_aes_cbc_decrypt(ssl_session_t* sess,
                             record_t* record, ssl_crypto_op_t* op);

int
handle_after_aes_gcm_encrypt(ssl_session_t* sess,
                             record_t* record, ssl_crypto_op_t* op);

int
handle_after_aes_gcm_decrypt(ssl_session_t* sess,
                             record_t* record, ssl_crypto_op_t* op);

int
handle_after_mac_crypto(ssl_session_t* sess,
						ssl_crypto_op_t* op);

int
handle_mac(ssl_session_t* sess,
                record_t* record, ssl_crypto_op_t* op);

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

static const char* 
state_to_string(int state)
{
    switch(state) {
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
typedef const EVP_MD* (*hash_func_t)(void);

const hash_func_t prf_hash_table[PRF_MAX] = {
    [PRF_SHA256] = EVP_sha256,
    [PRF_SHA384] = EVP_sha384,
};

typedef int (*crypto_func_t)(ssl_session_t *sess, record_t *record, ssl_crypto_op_t *op);

crypto_func_t handle_after[2][3] = {
    [ENCRYPT] = {
        [TLS_AES_CBC] = handle_after_aes_cbc_encrypt,
        [TLS_AES_GCM] = handle_after_aes_gcm_encrypt,
    },
    [DECRYPT] = {
        [TLS_RSA]     = handle_after_private_decrypt,
        [TLS_AES_CBC] = handle_after_aes_cbc_decrypt,
        [TLS_AES_GCM] = handle_after_aes_gcm_decrypt,
    }
};
/*---------------------------- HELPER FUNCTION ------------------------------*/
void
set_u32(uint24_t* a, const uint32_t* b)
{
    const uint8_t* y = (const uint8_t *)b;
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

/*
 * This function changes string to operand.
 * 
 * @str     The string to convert to operand for RSA
 * @op      The operand which will contain the result
 * @len     The length of string
 * @endian  The endian to be used in conversion
 *          0: Little Endian
 *          1: Big Endian
 */
void
string_to_operand(uint8_t* str, pka_operand_t* op, uint16_t len, int endian)
{
    uint8_t* big_num_ptr;
    int i;

#if VERBOSE_KEY
    unsigned z = 0;
    fprintf(stderr, "\nPKA request data:\n\n");
    {
        for (z = 0; z < len; z++)
            fprintf(stderr, "%02X%c", *((uint8_t *)(str) + z),
                ((z + 1) % 16) ? ' ' : '\n');
    }
#endif /* VERBOSE_KEY */

    assert(op != NULL);
    assert(op->buf_ptr != NULL);

    memset(op->buf_ptr, 0, op->buf_len);

    op->actual_len = len;
    op->is_encrypted = 0;
    op->big_endian = endian;

    if (endian)
        big_num_ptr = &op->buf_ptr[0];
    else
        big_num_ptr = &op->buf_ptr[len - 1];

    for (i = 0; i < len; i++) {
        if (endian)
            *big_num_ptr++ = str[i];
        else
            *big_num_ptr-- = str[i];
    }
}

/*
 * This function changes to operand to string at most max_len.
 *
 * @op      The operand which will be converted to string
 * @str     The pointer which will contain the result
 * @max_len The maximum length of result string
 */
void
operand_to_string(pka_operand_t* op, uint8_t* str, uint16_t max_len)
{
    uint32_t len = MIN(max_len, op->actual_len);
    uint32_t i;
    uint8_t* byte_ptr;

#if VERBOSE_KEY
    unsigned z = 0;
    fprintf(stderr, "\nPKA return data:\n\n");
    {
        for (z = 0; z < len; z++)
            fprintf(stderr, "%02X%c", *((uint8_t *)(op->buf_ptr) + z),
                ((z + 1) % 16) ? ' ' : '\n');
    }
#endif /* VERBOSE_KEY */

    //memset(str, 0, max_len);

    if (op->big_endian) {
        byte_ptr = &op->buf_ptr[0];
        for (i = 0; i < len; i++) {
            str[i] = *byte_ptr++;
        }
    } else {
        byte_ptr = &op->buf_ptr[len - 1];
        for (i = 0; i < len; i++) {
            str[i] = *byte_ptr--;
        }
    }
}

pka_results_t* 
malloc_results(uint32_t result_cnt, uint32_t buf_len)
{
    pka_results_t  * results;
    pka_operand_t  * result_ptr;
    uint8_t         result_idx, i;

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
free_results_buf(pka_results_t* results)
{
    pka_operand_t  * result_ptr;
    uint8_t         result_idx;

    for (result_idx = 0; result_idx < 1; result_idx++) {
        result_ptr = &results->results[result_idx];
        if (result_ptr->buf_ptr)
            free(result_ptr->buf_ptr);
        result_ptr->buf_ptr = NULL;
        result_ptr->buf_len = 0;
        result_ptr->actual_len = 0;
    }
}

void 
free_results(pka_results_t* results)
{
    assert(results != NULL);
    free_results_buf(results);
    free(results);
}

void 
clear_results(pka_results_t* results)
{
    pka_operand_t* result_ptr;
    uint8_t        result_idx;

    assert(results);

    for (result_idx = 0; result_idx < 1; result_idx++) {
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
init_random(ssl_session_t* sess, uint8_t* random, unsigned size)
{
    unsigned* ra = (unsigned *)random;
    unsigned i, j;
    uint64_t rand_seed = sess->rand_seed;

    rand_seed = rand_seed * 1103515245 + 12345;

    for (i = 0; i < size / sizeof(uint32_t); i++) {
        rand_seed = rand_seed * 1103515245lu + 12345lu;
        ra[i] = (unsigned)((rand_seed/(RAND_MAX_LOCAL * 21u)) % RAND_MAX_LOCAL);
    }

    for (j = 0; j + i * sizeof(uint32_t) < size; j++) {
        rand_seed = rand_seed * 1103515245lu + 12345lu;
        random[i * sizeof(uint32_t) + j] = (uint8_t)rand_seed;
    }
}

void
remove_pending_rsa_op(ssl_session_t* sess)
{
    ssl_crypto_op_t* op = sess->pending_rsa_op;

    if (unlikely(op != NULL)) {
#if VERBOSE_SSL
        fprintf(stderr, "[Remove Pending RSA OP] hit,                         \
            remove pending RSA op before clearing session\n");
#endif /* VERBOSE_SSL */

		op->pka_flag = 0;

        delete_record(sess, (record_t *)(op->data));
        delete_op(op);

		sess->pending_rsa_op = NULL;
		sess->ctx->cur_crypto_cnt--;
    }
}

ssl_crypto_op_t*
new_ssl_crypto_op(ssl_session_t* sess)
{
    ssl_crypto_op_t* target;
    thread_context_t* ctx = sess->ctx;

    target = TAILQ_FIRST(&ctx->op_pool);
    if (unlikely(!target)) {
        fprintf(stderr, "[new_ssl_crypto_op] Not enough op, and this must not happen.\n");
        exit(EXIT_FAILURE);
    }

    TAILQ_REMOVE(&ctx->op_pool, target, op_pool_link);
    ctx->free_op_cnt--;
    ctx->using_op_cnt++;

    return target;
}

cipher_suite_t
select_cipher(uint16_t length, cipher_suite_t* cipher_suites)
{
    cipher_suite_t cipher = TLS_NULL_WITH_NULL_NULL;
	uint32_t i;

    for (i = 0; i < length / sizeof(cipher_suite_t); i++) {
		if (COMPARE_CIPHER(cipher_suites[i], TLS_RSA_WITH_AES_256_GCM_SHA384))
            return TLS_RSA_WITH_AES_256_GCM_SHA384;
        if (COMPARE_CIPHER(cipher_suites[i], TLS_RSA_WITH_AES_256_CBC_SHA))
            return TLS_RSA_WITH_AES_256_CBC_SHA;
    }

    return cipher;
}

void
init_record(record_t* record, const sequence_num_t seq, const int is_received_)
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
                    ((ssl_session_t *)record->sess)->parent->session_id,
                    record->id,
                    state_to_string(NULL_STATE),
                    state_to_string(record->state));
#endif /* VERBOSE_STATE */
}

record_t*
new_recv_record(ssl_session_t* sess)
{
    record_t* record = NULL;
    thread_context_t* ctx = sess->ctx;

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
                    sess->parent->session_id,
                    record->id);
#endif /* VERBOSE_SSL */

    return record;
}

record_t*
new_send_record(ssl_session_t* sess)
{
    record_t* record = NULL;
    thread_context_t* ctx = sess->ctx;

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
                    sess->parent->session_id,
                    record->id);
#endif /* VERBOSE_SSL */

    return record;
}

int
store_handshake(ssl_session_t* sess, record_t* record)
{
    if (unlikely(record->fragment.handshake.msg_type 
                        <= sess->handshake_state)) {
        return -1;
    }

    memcpy(sess->handshake_msgs + sess->handshake_msgs_len,
           record->plain_text.fragment,
           record->plain_text.length);

    sess->handshake_msgs_len += record->plain_text.length;

#if VERBOSE_CHUNK
    fprintf(stderr, "\nSTORE HANDSHAKE! new: %u, total : %u, type : %d\n",
                    record->plain_text.length,
                    sess->handshake_msgs_len,
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
delete_record(ssl_session_t* sess, record_t* record)
{
    thread_context_t* ctx = record->ctx;

    memset(record, 0, sizeof(record_t));
    record->ctx = ctx;
    TAILQ_INSERT_TAIL(&ctx->record_pool, record, record_pool_link);
    ctx->free_record_cnt++;
    ctx->using_record_cnt--;

    sess->num_current_records--;

#if VERBOSE_SSL || VERBOSE_STATE
    fprintf(stderr, "\nDelete Session %d, Record: %d\n",
                    sess->parent->session_id,
                    record->id);
#endif /* VERBOSE_SSL */
}

void
delete_op(ssl_crypto_op_t* op)
{
    thread_context_t* ctx = op->ctx;

    memset(op, 0, sizeof(ssl_crypto_op_t));
    op->ctx = ctx;
    TAILQ_INSERT_TAIL(&ctx->op_pool, op, op_pool_link);
    ctx->free_op_cnt++;
    ctx->using_op_cnt--;
}
/*------------------------------ PROCESSING ---------------------------------*/
int
process_ssl_packet(tcp_connection_t* conn,
                   uint8_t* payload, uint16_t payload_len)
{
    ssl_session_t* sess = conn->ssl_session;
    if (unlikely(!payload || !payload_len))
        return -1;

#if VERBOSE_SSL
    fprintf(stderr, "\n--------------< SSL Packet >--------------\n");
#endif /* VERBOSE_SSL */

    return process_new_record(sess, payload, payload_len);
}

int
process_new_record(ssl_session_t* sess, uint8_t* pkt_buf, uint16_t pkt_len)
{
    size_t processed_len = 0;
    size_t copy_len = 0;
    record_t* crr = sess->current_read_record;
    uint16_t record_len = 0;

#if VERBOSE_SSL
    fprintf(stderr, "\n[Process New Record]\n");
#endif /* VERBOSE_SSL */

    while (processed_len < pkt_len) {
        if (crr == NULL) {
            uint8_t* record_hdr;

            if (pkt_len - processed_len < RECORD_HEADER_SIZE)
                break;

            crr = sess->current_read_record = new_recv_record(sess);

            record_hdr = pkt_buf + processed_len;

            record_len = ntohs(*(uint16_t *)(record_hdr + 3));

#if VERBOSE_SSL
			uint8_t record_type;
            record_type = *record_hdr;
            fprintf(stderr, "\nNew RECORD Session %d: "
					"%d, processed: %lu, record type: %u, len: %u\n",
					sess->parent->session_id, crr->id,
					processed_len, record_type, record_len);
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
		if (crr->current_len > 0 ||
			crr->length > pkt_len - processed_len ||
			// sess->waiting_crypto ||
            /* 
             * It works with this logic: record free == buf free
             * So, currently, it can't handle multiple records in one packet.
             * That's the reason of checking SERVER_HELLO_DONE.
             */ 
			sess->handshake_state == SERVER_HELLO_DONE) {

			copy_len = MIN(crr->length - crr->current_len,
						   pkt_len - processed_len);
			memcpy(crr->data + crr->current_len,
				   pkt_buf + processed_len, copy_len);
			crr->current_len += copy_len;
			processed_len += copy_len;
		} else {
			crr->data = pkt_buf + processed_len;
			crr->current_len += crr->length;
			processed_len += crr->length;
		}
#else /* !ZERO_COPY_RECV */
		copy_len = MIN(crr->length - crr->current_len,
					   pkt_len - processed_len);
		memcpy(crr->data + crr->current_len, 
               pkt_buf + processed_len, copy_len);
		crr->current_len += copy_len;
		processed_len += copy_len;
#endif /* !ZERO_COPY_RECV */

#if VERBOSE_SSL
        fprintf(stderr, "crr->length: %lu, crr->current_len: %lu, "
                        "len: %lu, processed_len: %lu\n",
                        crr->length, crr->current_len, len, processed_len);
#endif /* VERBOSE_SSL */

        if (crr->current_len == crr->length) {
#if MODIFY_FLAG
			if (sess->waiting_crypto)
				push_read_record(sess, crr);
			else
				process_read_record(sess, crr);
#else /* !MODIFY_FLAG */
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
push_read_record(ssl_session_t* sess, record_t* record)
{    
    TAILQ_INSERT_TAIL(&sess->recv_q, record, recv_q_link);
    sess->recv_q_cnt++;
}

void
unpack_header(record_t* record)
{
    uint8_t* data = record->data;
    plain_text_t* plain_text = &record->plain_text;
    cipher_text_t* cipher_text = &record->cipher_text;

    assert(record->state == TO_UNPACK_HEADER);

#if VERBOSE_SSL
    fprintf(stderr, "\n[Unpack Header]\n");
#endif /* VERBOSE_SSL */

#if VERBOSE_STATE
    fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
                    ((ssl_session_t *)record->sess)->parent->session_id,
                    record->id,
                    state_to_string(TO_UNPACK_HEADER),
                    state_to_string(record->state));
#endif /* VERBOSE_STATE */

    if (likely(data[0] == HANDSHAKE ||
               data[0] == CHANGE_CIPHER_SPEC ||
               data[0] == ALERT ||
               data[0] == APPLICATION_DATA)) {
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
decrypt_record(ssl_session_t* sess, record_t* record)
{
    security_params_t* read_sp = &sess->read_sp;

    assert(record->state == TO_DECRYPT);

#if VERBOSE_SSL
    fprintf(stderr, "[Decrypt Record]\n");
#endif /* VERBOSE_SSL */

    record->seq_num = sess->recv_seq_num_;
    sess->recv_seq_num_++;

    record->is_encrypted = 1;

    ssl_crypto_op_t* op = new_ssl_crypto_op(sess);

	if (unlikely(!op))
        return -1;

    switch (read_sp->cipher_type) {
        case BLOCK: {
            generic_block_cipher_t* block_cipher =
                &record->cipher_text.fragment.block_cipher;
            block_cipher->IV = record->data + RECORD_HEADER_SIZE;
            record->cipher_text.length -= read_sp->fixed_iv_length;

            op->in = block_cipher->IV + read_sp->fixed_iv_length;
            op->out = record->decrypted + RECORD_HEADER_SIZE;

            memcpy(record->decrypted, record->data, RECORD_HEADER_SIZE);

            op->in_len = record->cipher_text.length;
            op->out_len = record->cipher_text.length;
            op->iv = block_cipher->IV;
            op->key = sess->client_write_key;
            op->key_len = read_sp->enc_key_size;
            op->iv_len = read_sp->fixed_iv_length;

            op->opcode.u32 = TLS_OPCODE_AES_CBC_256_DECRYPT;

            op->data = (void *)record;

            if (unlikely(execute_aes_crypto(sess->ctx->symmetric_crypto_ctx, op) < 0)) {
                delete_op(op);
                delete_record(sess, record); /* delete record */

                return -1;
            }

            *((uint16_t *)(record->decrypted + 3)) = htons(record->cipher_text.length);

#if VERBOSE_AES
            fprintf(stderr, "\nDecrypted Data:\n");
            {
                int z;
                for (z = 0; z < record->cipher_text.length + RECORD_HEADER_SIZE; z++)
                    fprintf(stderr, "%02X%c", record->decrypted[z],
                            ((z + 1) % 16) ? ' ' : '\n');
            }
#endif /* VERBOSE_AES */

            break;
        }
        case AEAD: {
            uint8_t nonce[read_sp->fixed_iv_length + read_sp->record_iv_length];
            uint8_t additional_data[sizeof(sequence_num_t) + RECORD_HEADER_SIZE];
            generic_aead_cipher_t* aead_cipher =
                &record->cipher_text.fragment.aead_cipher;
            sequence_num_t seq_num;

            aead_cipher->nonce_explicit = record->data + RECORD_HEADER_SIZE;
            record->cipher_text.length -= read_sp->record_iv_length + GCM_TAG_SIZE;

#if VERBOSE_AES
            fprintf(stderr, "[decrypt record] decrypt with gcm !!!!!!!!!!!!!!!!!!!!!!!\n");
            fprintf(stderr, "RECORD DATA:\n");
            uint16_t z;
            for (z = 0; z < record->length; z++)
                fprintf(stderr, "%02X%c", record->data[z],
                        ((z + 1) % 16)? ' ' : '\n');

            fprintf(stderr, "\nImplicit part iv (client_write_iv):\n");
            for (z = 0; z < read_sp->fixed_iv_length; z++)
                fprintf(stderr, "%02X%c", sess->client_write_IV[z],
                        ((z + 1) % 16)? ' ' : '\n');
            fprintf(stderr, "\n");

            fprintf(stderr, "Explicit part iv: \n");
            for (z = 0; z < read_sp->record_iv_length; z++)
                fprintf(stderr, "%02X%c", aead_cipher->nonce_explicit[z],
                        ((z + 1) % 16)? ' ' : '\n');
            fprintf(stderr, "\n");
#endif /* VERBOSE_AES */

            /* Make nonce */
            memcpy(nonce, sess->client_write_IV, read_sp->fixed_iv_length);
            memcpy(nonce + read_sp->fixed_iv_length, 
                   aead_cipher->nonce_explicit,
                   read_sp->record_iv_length);

            /* Make AAD */
            seq_num = bswap_64(record->seq_num);
            memcpy(additional_data, &seq_num, sizeof(seq_num));
            memcpy(additional_data + sizeof(seq_num), 
                   record->data,
                   RECORD_HEADER_SIZE);
            // additional_data[sizeof(additional_data) - 1] -= sizeof(sequence_num_t) + GCM_TAG_SIZE;
            uint16_t aad_len = record->cipher_text.length;
            uint16_t aad_len_be = htons(aad_len);
            memcpy(additional_data + sizeof(sequence_num_t) + 3, &aad_len_be, sizeof(aad_len_be));

            op->in = aead_cipher->nonce_explicit + read_sp->record_iv_length;
            op->out = record->decrypted + RECORD_HEADER_SIZE;

            memcpy(record->decrypted, record->data, RECORD_HEADER_SIZE);

            op->in_len = record->cipher_text.length;
            op->iv = nonce;
            op->iv_len = read_sp->fixed_iv_length + read_sp->record_iv_length;
            op->aad = additional_data;
            op->aad_len = sizeof(sequence_num_t) + RECORD_HEADER_SIZE;
            op->key = sess->client_write_key;
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

            break;
        }

        default:
            fprintf(stderr, "[decrypt record] can't support cipher type\n");
            exit(EXIT_FAILURE);
    }

	return handle_after_aes_crypto(sess, op);
}

int
submit_pka_request(thread_context_t *ctx, ssl_crypto_op_t* op)
{
    // if (unlikely(rte_ring_enqueue(ctx->submit_pka_ring, op) < 0)) {
    if (unlikely(sj_ring_enqueue(ctx->submit_pka_ring, op) < 0)) {
        delete_op(op);

        return -1;
    }

    return 0;
}

int
rsa_decrypt_record(ssl_session_t* sess, record_t* record)
{
    assert(record != NULL);

#if VERBOSE_SSL
    fprintf(stderr, "[RSA Decrypt RECORD]\n");
#endif /* VERBOSE_SSL */

    ssl_crypto_op_t* op = new_ssl_crypto_op(sess);

	if (unlikely(!op))
        return -1;

    client_key_exchange_t* cke_ptr =
        &record->fragment.handshake.body.client_key_exchange;

    uint8_t* secret = cke_ptr->key.rsa.encrypted_premaster_secret;
    string_to_operand((((uint8_t *)secret) + 2),
                      sess->rsa_operand,
                      ntohs(*(uint16_t *)secret),
                      0);

    op->pka_in = sess->rsa_operand;
    op->pka_out = sess->ctx->rsa_result;
    op->in_len = ntohs(*(uint16_t *)secret);
    op->out_len = op->in_len;
    op->key = (uint8_t *)(sess->ctx->ssl_context->pka);

    assert(op->key != NULL);

#if VERBOSE_KEY
    fprintf(stderr, "RSA %d\n", op->in_len * 8);
#endif /* VERBOSE_KEY */

    switch (op->in_len) {
        case 128:
            op->opcode.u32 = TLS_OPCODE_RSA_1024_PRIVATE_DECRYPT;
            break;
        case 256:
            op->opcode.u32 = TLS_OPCODE_RSA_2048_PRIVATE_DECRYPT;
            break;
        case 512:
            op->opcode.u32 = TLS_OPCODE_RSA_4096_PRIVATE_DECRYPT;
            break;

        default:
            fprintf(stderr, "Error: Unsupported RSA key length: %u\n",
                    op->in_len * 8);
            exit(EXIT_FAILURE);
    }

    op->sess = sess;
    op->data = (void *)record;
    
    if (unlikely(submit_pka_request(sess->ctx, op) < 0)) {
        delete_op(op);

        return -1;
    }

    sess->waiting_crypto = TRUE;
    op->pka_flag = 1;
    sess->pending_rsa_op = op;

	return 0;
}


void
handle_submitted_pka(thread_context_t* ctx)
{
    // if (ctx->coreid != 0) return;
    int max_outstanding_pka_req = MAX_OUTSTANDING_PKA_REQ;

    if (host_threads_num != 1) 
        max_outstanding_pka_req = MAX_OUTSTANDING_PKA_REQ / 4;

    for (int core_id = 0; core_id < rte_lcore_count(); core_id++) {
        while (ctx_array[core_id]->cur_crypto_cnt < max_outstanding_pka_req) {
            ssl_crypto_op_t* op;
            int ret = 0;

            // if (rte_ring_dequeue(ctx_array[core_id]->submit_pka_ring, (void **)&op) < 0)
            if (sj_ring_dequeue(ctx_array[core_id]->submit_pka_ring, (void **)&op) < 0)
                break;

            switch (op->opcode.u32) {
                case TLS_OPCODE_RSA_1024_PRIVATE_DECRYPT:
                case TLS_OPCODE_RSA_2048_PRIVATE_DECRYPT:
                case TLS_OPCODE_RSA_4096_PRIVATE_DECRYPT:
                    ret = execute_rsa_crypto(op);
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
            op->sess->pending_rsa_op = op;
            ctx_array[core_id]->cur_crypto_cnt++;
        }
    }
}

void
handle_completed_pka(thread_context_t* ctx)
{
    // if (ctx->coreid != 0) return;

    int ret = 0;
    thread_context_t *ctx_of_pka_result;
    ssl_session_t* sess;
    record_t* record;

    for (int core_id = 0; core_id < rte_lcore_count(); core_id++) {
        while (ctx_array[core_id]->cur_crypto_cnt > 0) {
            uint64_t start = rte_rdtsc();
            ret = pka_get_result(*(ctx->handle), ctx->rsa_result);
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

            if (unlikely(ret == FAILURE))
                break;

            if (unlikely(ctx->rsa_result->status != 0))
                fprintf(stderr, "PKA Result Status: %d\n", ctx->rsa_result->status);

            sess = (ssl_session_t *)((ssl_crypto_op_t *)(ctx->rsa_result->user_data))->sess;
            
            sess->pka_op = (ssl_crypto_op_t *)(ctx->rsa_result->user_data);

            if (unlikely(!sess->pka_op)) {
                DEBUG_PRINT("[process crypto] op is null..\n");
                fprintf(stderr, "ERRORED pka_result ptr = %p\n", (void*)ctx->rsa_result);
                ctx_array[core_id]->cur_crypto_cnt--;
                continue;
            }

            /* it may be already rotten */
            if (unlikely(sess->pka_op->pka_flag == FALSE))
                continue;

            record = (record_t *)(sess->pka_op->data);

            if (unlikely(!record)) {
                DEBUG_PRINT("[process crypto] record is null..\n");
                ctx_array[core_id]->cur_crypto_cnt--;
                continue;
            }

            sess->pka_results->opcode = ctx->rsa_result->opcode;
            sess->pka_results->result_cnt = ctx->rsa_result->result_cnt;

            for (int i = 0; i < ctx->rsa_result->result_cnt; i++) {
                sess->pka_results->results[i].buf_len 
                    = ctx->rsa_result->results[i].buf_len;

                sess->pka_results->results[i].actual_len 
                    = ctx->rsa_result->results[i].actual_len;

                memcpy(sess->pka_results->results[i].buf_ptr,
                       ctx->rsa_result->results[i].buf_ptr,
                       ctx->rsa_result->results[i].buf_len);
            }

            rte_wmb(); /* wow! */

            ctx_array[core_id]->cur_crypto_cnt--;
            ctx_array[core_id]->completed_crypto_cnt++;
            sess->completed_crypto = TRUE;
        }
    }
}

int
get_processed_crypto(ssl_session_t *sess)
{
    if (!sess->completed_crypto)
        return 0;

    rte_rmb(); /* wow! */

#if VERBOSE_CONN_LAT
        clock_gettime(CLOCK_MONOTONIC, &sess->decrypt_rsa_time);
        uint64_t rsa_decrypt_decrypt_rsa_lat = (sess->decrypt_rsa_time.tv_sec - sess->rsa_decrypt_time.tv_sec) * 1000000000L
            + (sess->decrypt_rsa_time.tv_nsec - sess->rsa_decrypt_time.tv_nsec);
        
        if (rsa_decrypt_decrypt_rsa_lat > max_rsa_decrypt_decrypt_rsa_lat[sess->coreid]) {
            max_rsa_decrypt_decrypt_rsa_lat[sess->coreid] = rsa_decrypt_decrypt_rsa_lat;
        }

        sum_rsa_decrypt_decrypt_rsa_lat[sess->coreid] += rsa_decrypt_decrypt_rsa_lat;
        num_decrypt_rsa[sess->coreid]++;
#endif /* VERBOSE_CONN_LAT */
    
    int ret, need_read_record;
    ssl_crypto_op_t* op = sess->pka_op;
    record_t* record = (record_t *)(op->data);
    crypto_func_t func;

    func = handle_after[DECRYPT][TLS_RSA];
    sess->pending_rsa_op = NULL;

    if (unlikely(func(sess, record, op) < 0))
        return -1;

    delete_op(op);

    if (unlikely(handle_read_record(sess, record) < 0))
        return -1;

    sess->completed_crypto = FALSE;
    sess->waiting_crypto = FALSE;
}

int
verify_mac(ssl_session_t* sess, record_t* record)
{
    unsigned pad_len;
    security_params_t* read_sp = &sess->read_sp;
    generic_block_cipher_t* block_cipher =
                            &record->cipher_text.fragment.block_cipher;

#if VERBOSE_SSL
    fprintf(stderr, "[verify mac]\n");
#endif /* VERBOSE_SSL */

    ssl_crypto_op_t* op = new_ssl_crypto_op(sess);
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

        uint8_t* end = record->decrypted + 
                       RECORD_HEADER_SIZE +
                       record->cipher_text.length - 1;

        pad_len = *end;

		if (pad_len != *(end - 1) || pad_len > record->cipher_text.length)
			pad_len = 0;

        op->in_len = record->cipher_text.length +
                     sizeof(record->seq_num) +
                     RECORD_HEADER_SIZE -
                     read_sp->mac_key_size -
                     pad_len - 1;

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
            fprintf(stderr, "%02X%c", op->key[z],
                            ((z + 1) % 16) ? ' ' : '\n');
    }

    fprintf(stderr, "\nmac_in:\n");
    {
        for (unsigned z = 0; z < op->in_len; z++)
            fprintf(stderr, "%02X%c", op->in[z],
                            ((z + 1) % 16) ? ' ' : '\n');
    }

    fprintf(stderr, "\nmac_out:\n");
    {
        for (unsigned z = 0; z < op->out_len; z++)
            fprintf(stderr, "%02X%c", op->out[z],
                            ((z + 1) % 16) ? ' ' : '\n');
    }
#endif /* VERBOSE_MAC */

    return handle_after_mac_crypto(sess, op);
}

int
unpack_record(record_t* record)
{
    uint8_t* decrypted = record->decrypted;
    uint8_t* data = record->data;
    plain_text_t* plain_text = &record->plain_text;
    uint8_t record_type;

    assert(unlikely(record != NULL));
    assert(unlikely(record->state == TO_UNPACK_CONTENT));

#if VERBOSE_SSL
    fprintf(stderr, "[Unpack Record]\n");
#endif /* VERBOSE_SSL */

#if VERBOSE_STATE
    fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
                    ((ssl_session_t *)record->sess)->parent->session_id,
                    record->id,
                    state_to_string(TO_UNPACK_CONTENT),
                    state_to_string(record->state));
#endif /* VERBOSE_STATE */

    if (likely(plain_text->version.major == 0x03)) {
        if (unlikely(decrypted != data))
            plain_text->length = record->cipher_text.length;

        plain_text->fragment = decrypted + RECORD_HEADER_SIZE; 
    } else /* drop unappropriate pkt */
        return -1;

    record_type = plain_text->record_type;

    int ret = -1;
    switch(record_type) {
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

int
unpack_handshake(record_t* record)
{
    plain_text_t* plain_text = &record->plain_text;
    uint8_t* pf = plain_text->fragment;
    uint8_t* hl = record->fragment.handshake.length.u8;
    int offset = HANDSHAKE_HEADER_SIZE;
    int end = plain_text->length;
    client_hello_t* pch = &record->fragment.handshake.body.client_hello;
    client_key_exchange_t* pcke =
        &record->fragment.handshake.body.client_key_exchange;
    finished_t* pcf = &record->fragment.handshake.body.client_finished;

#if VERBOSE_SSL
    fprintf(stderr, "[Unpack Handshake]\n");
#endif /* VERBOSE_SSL */

    record->fragment.handshake.msg_type = pf[0];
    memcpy(hl, pf + 1, HANDSHAKE_HEADER_SIZE - 1);

    switch(record->fragment.handshake.msg_type) {
        case CLIENT_HELLO: {
#if VERBOSE_SSL
            fprintf(stderr, "Client Hello!\n");
#endif /* VERBOSE_SSL */

#if VERBOSE_CONN_LAT
            clock_gettime(CLOCK_MONOTONIC, &record->sess->ch_time);
            uint64_t syn_ch_lat = (record->sess->ch_time.tv_sec - record->sess->parent->conn_start_time.tv_sec) * 1000000000L
                + (record->sess->ch_time.tv_nsec - record->sess->parent->conn_start_time.tv_nsec);
            
            if (syn_ch_lat > max_syn_ch_lat[record->sess->coreid]) {
                max_syn_ch_lat[record->sess->coreid] = syn_ch_lat;
            }

            sum_syn_ch_lat[record->sess->coreid] += syn_ch_lat;
            num_ch[record->sess->coreid]++;
#endif /* VERBOSE_CONN_LAT */

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
                    pch->extension_length = ntohs(*(uint16_t *)(pf + offset));
                    offset += sizeof(uint16_t);

                    if (pch->extension_length > 0) {
                        pch->extension = pf + offset;
                        offset += pch->extension_length;
                    }
                }
            } else {
                fprintf(stderr, "This version does not supported\n");
            }

#if VERBOSE_SSL
            fprintf(stderr, "Client Version: %u.%u,\n", 
                            pch->version.major, pch->version.minor);
            fprintf(stderr, "Session ID Length: %u,\n",
                            pch->session_id_length);
            fprintf(stderr, "Cipher Length: %x,\n",
                            pch->cipher_suite_length);
            fprintf(stderr, "Compression Length: %x,\n",
                            pch->compression_method_length);
            fprintf(stderr, "off: %u, off_value: %u\n\n",
                            off, *(pf + off));
#endif /* VERBOSE_SSL */

            break;
        }
        case CLIENT_KEY_EXCHANGE: {
#if VERBOSE_SSL
            fprintf(stderr, "Client Key Exchange!\n");
#endif /* VERBOSE_SSL */

#if VERBOSE_CONN_LAT
            clock_gettime(CLOCK_MONOTONIC, &record->sess->cke_time);
            uint64_t sh_sc_shd_cke_lat = (record->sess->cke_time.tv_sec - record->sess->sh_sc_shd_time.tv_sec) * 1000000000L
                + (record->sess->cke_time.tv_nsec - record->sess->sh_sc_shd_time.tv_nsec);
            
            if (sh_sc_shd_cke_lat > max_sh_sc_shd_cke_lat[record->sess->coreid]) {
                max_sh_sc_shd_cke_lat[record->sess->coreid] = sh_sc_shd_cke_lat;
            }

            sum_sh_sc_shd_cke_lat[record->sess->coreid] += sh_sc_shd_cke_lat;
            num_cke[record->sess->coreid]++;
#endif /* VERBOSE_CONN_LAT */

            /* Assume RSA */
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
    return 0;
}

int
unpack_alert(record_t* record)
{
    if (unlikely(!record))
        return -1;
    record->fragment.alert.level =
        *(record->decrypted + RECORD_HEADER_SIZE);
    record->fragment.alert.description =
        *(record->decrypted + RECORD_HEADER_SIZE + 1);

    return 0;
}

int
unpack_application_data(record_t* record)
{
    if (unlikely(!record))
        return -1;
    record->fragment.application_data.data =
        record->decrypted + RECORD_HEADER_SIZE;
    return 0;
}

int
process_session_read(ssl_session_t* sess)
{
    int processed_record = 0;
    record_t* target;

    assert(sess->recv_q_cnt >= 0);

    while(sess->recv_q_cnt > 0 && !sess->waiting_crypto) {
        target = TAILQ_FIRST(&sess->recv_q);

        TAILQ_REMOVE(&sess->recv_q, target, recv_q_link);
        sess->recv_q_cnt--;

        process_read_record(sess, target);
        processed_record++;
    }

    return processed_record;
}

/* return */
int
process_read_record(ssl_session_t* sess, record_t* record)
{    
    assert(record != NULL);

    if (unlikely(sess->handshake_state >= CLIENT_FINISHED)) {
        /* Retransmitted CKE / CCCS / CF */
        if (unlikely(record->data[0] == CHANGE_CIPHER_SPEC))
            send_meta_packet(sess->coreid, sess->parent->portid + 1,  sess->parent);
        delete_record(sess, record);
        return 0;
    }

    // if (unlikely(sess->handshake_state >= CLIENT_CIPHER_SPEC)) {
    //     /* Retransmitted CKE / CCCS / CF */
    //     if (record->data[0] == CHANGE_CIPHER_SPEC ||
    //         record->data[5] == CLIENT_KEY_EXCHANGE) {
    //         delete_record(sess, record);
    //         return 0;
    //     }
    // }

#if VERBOSE_SSL
	fprintf(stderr, "[PROCESS READ RECORD]\n");
#endif /* VERBOSE_SSL */

#if VERBOSE_CHUNK
    fprintf(stderr,"\nNew READ RECORD\n");
    {
		unsigned z;
        for (z = 0; z < record->length; z++)
            fprintf(stderr, "%02X%c", record->data[z],
                                ((z + 1) % 16) ? ' ' : '\n');
    }
#endif /* VERBOSE_CHUNK */

    unpack_header(record);

	if (unlikely(sess->read_sp.bulk_cipher_algorithm != NO_CIPHER)) {
		if (unlikely(sess->read_sp.mac_algorithm == NO_MAC)) {
			fprintf(stderr, "[process_read_record] Error: the encrypted packet has no MAC!\n");
            exit(EXIT_FAILURE);
        }

        if (unlikely(decrypt_record(sess, record) < 0))
            return -1;

        if (sess->read_sp.cipher_type != AEAD) { /* for CF */
            if (unlikely(verify_mac(sess, record) < 0)) {
				fprintf(stderr, "[process read record] verify mac failed\n");
				return -1;
			}
        }
    } else /* Others (CH, CKE, CCCS)*/
        record->decrypted = record->data;

	record->state = TO_UNPACK_CONTENT;

	if (unlikely(unpack_record(record) < 0))
		return -1;

    /* Do RSA decryption if CKE */
    if (unlikely(record->plain_text.record_type == HANDSHAKE &&
        record->fragment.handshake.msg_type == CLIENT_KEY_EXCHANGE)) {
#if VERBOSE_SSL
        fprintf(stderr, "RSA Decrypt Needed!\n");
#endif /* VERBOSE_SSL */

#if VERBOSE_CONN_LAT
        clock_gettime(CLOCK_MONOTONIC, &sess->rsa_decrypt_time);
        uint64_t cke_rsa_decrypt_lat = (sess->rsa_decrypt_time.tv_sec - sess->cke_time.tv_sec) * 1000000000L
            + (sess->rsa_decrypt_time.tv_nsec - sess->cke_time.tv_nsec);
        
        if (cke_rsa_decrypt_lat > max_cke_rsa_decrypt_lat[sess->coreid]) {
            max_cke_rsa_decrypt_lat[sess->coreid] = cke_rsa_decrypt_lat;
        }

        sum_cke_rsa_decrypt_lat[sess->coreid] += cke_rsa_decrypt_lat;
        num_rsa_decrypt[sess->coreid]++;
#endif /* VERBOSE_CONN_LAT */

        if (unlikely(rsa_decrypt_record(sess, record) < 0))
            return -1;
		else
			return 0;
    }

    return handle_read_record(sess, record);
}

int
handle_read_record(ssl_session_t* sess, record_t* record)
{
    int ret = -1;

    assert(record != NULL);
#if VERBOSE_SSL
    fprintf(stderr, "[Handle Read Record]\n");
#endif /* VERBOSE_SSL */

    assert(record->state == READ_READY);

    switch(record->plain_text.record_type) {
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
            ret = handle_data(sess, record);
            break;

        default:
            fprintf(stderr, "Unmatched Record Type\n");
            break;
    }

    return ret;
}

int
handle_handshake(ssl_session_t* sess, record_t* record)
{
    cipher_suite_t cipher = TLS_NULL_WITH_NULL_NULL;
    client_hello_t* client_hello;
    premaster_secret_t* pms;
    security_params_t* pending_sp = &sess->pending_sp;
    security_params_t* write_sp = &sess->write_sp;
    uint8_t* vd;

    int random_size = sizeof(pending_sp->client_random) +
                      sizeof(pending_sp->server_random);
    uint8_t randoms[random_size];
	const EVP_MD* (*hash_func)(void);
    unsigned z;

#if VERBOSE_SSL
    fprintf(stderr, "[Handle Handshake] type: %d, len: %d\n",
                        record->fragment.handshake.msg_type,
                        record->plain_text.length);
#endif /* VERBOSE_SSL */

    if (unlikely(store_handshake(sess, record) < 0)) {
#if VERBOSE_SSL
        fprintf(stderr, "handshake retransmission\n");
#endif /* VERBOSE_SSL */

    }

    switch(record->fragment.handshake.msg_type) {
        case CLIENT_HELLO: {
            if (sess->handshake_state >= CLIENT_HELLO)
                goto handshake_record_finish;

            sess->state = STATE_HANDSHAKE;

            sess->handshake_state = CLIENT_HELLO;

            switch (record->plain_text.version.major) { /* TODO sj */
                case SSL_V_3: {
                    client_hello = &(record->fragment.handshake.body.client_hello);
                    cipher = select_cipher(client_hello->cipher_suite_length,
                                           client_hello->cipher_suites);
                    pending_sp->cipher = cipher;

                    if (COMPARE_CIPHER(cipher, TLS_RSA_WITH_AES_256_GCM_SHA384)) {
                        pending_sp->entity = SERVER;
                        pending_sp->prf_algorithm = PRF_SHA384;
                        pending_sp->bulk_cipher_algorithm = AES;
                        pending_sp->cipher_type = AEAD;
                        pending_sp->enc_key_size = 32;
                        pending_sp->block_length = 16; /* Actually, not used */
                        pending_sp->fixed_iv_length = 4; /* length of implicit part of nonce */
                        pending_sp->record_iv_length = 8; /* length of explicit part of nonce */
                        pending_sp->mac_length = 48; /* not used? */
                        pending_sp->mac_key_size = 48;
                        pending_sp->mac_algorithm = MAC_SHA384;
                        pending_sp->compression_algorithm = NO_COMP;

                        memcpy(pending_sp->client_random,
                            &(client_hello->random),
                            sizeof(pending_sp->client_random));

                        uint32_t now = time(NULL);
                        memcpy(pending_sp->server_random, &now, sizeof(uint32_t));
                        init_random(sess, (pending_sp->server_random) + sizeof(uint32_t),
                                    sizeof(pending_sp->server_random) - sizeof(uint32_t));
                    } else if (COMPARE_CIPHER(cipher, TLS_RSA_WITH_AES_256_CBC_SHA)) {
                        pending_sp->entity = SERVER;
                        pending_sp->prf_algorithm = PRF_SHA256;
                        pending_sp->bulk_cipher_algorithm = AES;
                        pending_sp->cipher_type = BLOCK;
                        pending_sp->enc_key_size = 32;
                        pending_sp->block_length = 16; /* Actually, not used */
                        pending_sp->fixed_iv_length = 16;
                        pending_sp->record_iv_length = 16; /* Actually, not used */
                        pending_sp->mac_length = 16; /* Actually, not used */
                        pending_sp->mac_key_size = 20;
                        pending_sp->mac_algorithm = MAC_SHA1;
                        pending_sp->compression_algorithm = NO_COMP;

                        memcpy(pending_sp->client_random,
                            &(client_hello->random),
                            sizeof(pending_sp->client_random));

                        uint32_t now = time(NULL);
                        memcpy(pending_sp->server_random, &now, sizeof(uint32_t));
                        init_random(sess, (pending_sp->server_random) + sizeof(uint32_t),
                                    sizeof(pending_sp->server_random) - sizeof(uint32_t));
                    } else {
                        fprintf(stderr, "Unsupported Cipher\n");
                    }

                    sess->version = client_hello->version;
                    
                    break;
                }
                case SSL_V_2: {
                    fprintf(stderr, "Not supported version\n");
                    break;
                }

                default:
                    assert(0);
            }

#if VERBOSE_SSL
            fprintf(stderr, "CLIENT HELLO RECEIVED\n\n");
            fprintf(stderr, "Prepare SERVER HELLO\n");
#endif /* VERBOSE_SSL */

            /* send server hello */
            send_server_hello(sess);
            sess->handshake_state = SERVER_HELLO;

#if VERBOSE_SSL
            fprintf(stderr, "SERVER HELLO SENT\n\n");
            fprintf(stderr, "Prepare CERTIFICATE\n");
#endif /* VERBOSE_SSL */

            /* send certificate */
            send_certificate(sess);
            sess->handshake_state = CERTIFICATE;

#if VERBOSE_SSL
            fprintf(stderr, "CERTIFICATE SENT\n\n");
            fprintf(stderr, "Prepare SERVER HELLO DONE\n");
#endif /* VERBOSE_SSL */

            /* send server hello done */
            send_server_hello_done(sess);
            sess->handshake_state = SERVER_HELLO_DONE;

#if VERBOSE_SSL
            fprintf(stderr, "SERVER HELLO DONE SENT\n\n");
#endif /* VERBOSE_SSL */

#if VERBOSE_CONN_LAT
            clock_gettime(CLOCK_MONOTONIC, &sess->sh_sc_shd_time);
            uint64_t ch_sh_sc_shd_lat = (sess->sh_sc_shd_time.tv_sec - sess->ch_time.tv_sec) * 1000000000L
                + (sess->sh_sc_shd_time.tv_nsec - sess->ch_time.tv_nsec);
            
            if (ch_sh_sc_shd_lat > max_ch_sh_sc_shd_lat[sess->coreid]) {
                max_ch_sh_sc_shd_lat[sess->coreid] = ch_sh_sc_shd_lat;
            }

            sum_ch_sh_sc_shd_lat[sess->coreid] += ch_sh_sc_shd_lat;
            num_sh_sc_shd[sess->coreid]++;
#endif /* VERBOSE_CONN_LAT */

            break;
        }
        case CLIENT_KEY_EXCHANGE: {
            if (sess->handshake_state >= CLIENT_KEY_EXCHANGE)
                goto handshake_record_finish;

            sess->handshake_state = CLIENT_KEY_EXCHANGE;

            pms = &record->fragment.handshake.body.client_key_exchange.pms;

            memcpy(randoms,
                   pending_sp->client_random,
                   sizeof(pending_sp->client_random));
            memcpy(randoms + sizeof(pending_sp->client_random),
                   pending_sp->server_random,
                   sizeof(pending_sp->server_random));

            if (unlikely(pending_sp->prf_algorithm < 0 || 
                         pending_sp->prf_algorithm >= PRF_MAX || 
                         prf_hash_table[pending_sp->prf_algorithm] == NULL)) {
                fprintf(stderr,
                        "Error: unsupported or invalid PRF algorithm index (%d). "
                        "Valid range: [0, %d)\n",
                        pending_sp->prf_algorithm, PRF_MAX);
                exit(EXIT_FAILURE);
            }

            hash_func = prf_hash_table[pending_sp->prf_algorithm];

            PRF(hash_func, 48, (const uint8_t *)pms,
                13, (const uint8_t *)"master secret",
                64, randoms,
                48, pending_sp->master_secret);

            memcpy(randoms,
                   pending_sp->server_random,
                   sizeof(pending_sp->server_random));
            memcpy(randoms + sizeof(pending_sp->server_random),
                   pending_sp->client_random,
                   sizeof(pending_sp->client_random));

            int key_block_len = (pending_sp->mac_key_size * 2) +
                                (pending_sp->enc_key_size * 2) +
                                (pending_sp->fixed_iv_length * 2);

            uint8_t key_block[MAX_KEY_BLOCK_LEN];

            PRF(hash_func, 48, pending_sp->master_secret,
                13, (const uint8_t *)"key expansion",
                64, randoms,
                key_block_len, key_block);

#if VERBOSE_KEY
            fprintf(stderr, "\npre-master\n");
            {
                for (z = 0; z < 48; z++)
                    fprintf(stderr, "%02X%c", *((uint8_t *)pms + z),
                                    ((z + 1) % 16) ? ' ' : '\n');
            }

            fprintf(stderr, "\nclient random\n");
            {
                for (z = 0; z < 32; z++)
                    fprintf(stderr, "%02X%c", pending_sp->client_random[z],
                                    ((z + 1) % 16) ? ' ' : '\n');
            }

            fprintf(stderr, "\nserver random\n");
            {
                for (z = 0; z < 32; z++)
                    fprintf(stderr, "%02X%c", pending_sp->server_random[z],
                                    ((z + 1) % 16) ? ' ' : '\n');
            }

            fprintf(stderr, "\nmaster\n");
            {
                for (z = 0; z < 48; z++)
                    fprintf(stderr, "%02X%c", pending_sp->master_secret[z],
                                    ((z + 1) % 16) ? ' ' : '\n');
            }

            fprintf(stderr, "\nkey block\n");
            {
                for (z = 0; z < (unsigned)key_block_len; z++)
                    fprintf(stderr, "%02X%c", key_block[z],
                                    ((z + 1) % 16) ? ' ' : '\n');
            }
#endif /* VERBOSE_KEY */

            int offset = 0;

			if (pending_sp->cipher_type != AEAD) {
				memcpy(&sess->client_write_MAC_secret,
					   key_block + offset,
					   pending_sp->mac_key_size);
				offset += pending_sp->mac_key_size;

				memcpy(&sess->server_write_MAC_secret,
					   key_block + offset,
					   pending_sp->mac_key_size);
				offset += pending_sp->mac_key_size;
			}

            memcpy(&sess->client_write_key,
                   key_block + offset,
                   pending_sp->enc_key_size);
            offset += pending_sp->enc_key_size;

            memcpy(&sess->server_write_key,
                   key_block + offset,
                   pending_sp->enc_key_size);
            offset += pending_sp->enc_key_size;

            memcpy(&sess->client_write_IV,
                   key_block + offset,
                   pending_sp->fixed_iv_length);
            offset += pending_sp->fixed_iv_length;

            memcpy(&sess->server_write_IV,
                   key_block + offset,
                   pending_sp->fixed_iv_length);
            offset += pending_sp->fixed_iv_length;

#if VERBOSE_KEY
			if (pending_sp->cipher_type != AEAD) {
				fprintf(stderr, "\n\nclient_MAC_secret\n");
				{
					for (z = 0; z < pending_sp->mac_key_size; z++)
						fprintf(stderr, "%02X%c", sess->client_write_MAC_secret[z],
								((z + 1) % 16) ? ' ' : '\n');
				}

				fprintf(stderr, "\n\nserver_MAC_secret\n");
				{
					for (z = 0; z < pending_sp->mac_key_size; z++)
						fprintf(stderr, "%02X%c", sess->server_write_MAC_secret[z],
								((z + 1) % 16) ? ' ' : '\n');
				}
			}

            fprintf(stderr, "\n\nclient_key\n");
            {
                for (z = 0; z < pending_sp->enc_key_size; z++)
                    fprintf(stderr, "%02X%c", sess->client_write_key[z],
                                    ((z + 1) % 16) ? ' ' : '\n');
            }

            fprintf(stderr, "\n\nserver key\n");
            {
                for (z = 0; z < pending_sp->enc_key_size; z++)
                    fprintf(stderr, "%02X%c", sess->server_write_key[z],
                                    ((z + 1) % 16) ? ' ' : '\n');
            }

            fprintf(stderr, "\n\nclient IV\n");
            {
                for (z = 0; z < pending_sp->fixed_iv_length; z++)
                    fprintf(stderr, "%02X%c", sess->client_write_IV[z],
                                    ((z + 1) % 16) ? ' ' : '\n');
            }

            fprintf(stderr, "\n\nserver IV\n");
            {
                for (z = 0; z < pending_sp->fixed_iv_length; z++)
                    fprintf(stderr, "%02X%c", sess->server_write_IV[z],
                                    ((z + 1) % 16) ? ' ' : '\n');
            }
#endif /* VERBOSE_KEY */

#if VERBOSE_SSL
            fprintf(stderr, "\nCLIENT KEY EXCHANGE RECEIVED\n\n");
#endif /* VERBOSE_SSL */

            break;
        }
        case CLIENT_FINISHED: {
            if (sess->handshake_state >= CLIENT_FINISHED)
                goto handshake_record_finish;

            vd = record->fragment.handshake.body.client_finished.verify_data;
            sess->handshake_state = CLIENT_FINISHED;

#if VERBOSE_SSL
            fprintf(stderr, "CLIENT FINISHED!!\n");
#endif /* VERBOSE_SSL */

            /* Verify Handshake */
            uint8_t calculated_vd[12];
            uint8_t handshake_hash[MAX_HASH_SIZE];
			int hash_size;

            /* Exclude the last message */
            switch (pending_sp->prf_algorithm) {
                case PRF_SHA256: {
                    hash_size = HASH_SIZE_SHA256;
                    hash_func = EVP_sha256;
                    SHA256(sess->handshake_msgs,
                           sess->handshake_msgs_len - record->plain_text.length,
                           handshake_hash);
                    break;
                }
                case PRF_SHA384: {
                    hash_size = HASH_SIZE_SHA384;
                    hash_func = EVP_sha384;
                    SHA384(sess->handshake_msgs,
                           sess->handshake_msgs_len - record->plain_text.length,
                           handshake_hash);
                    break;
                }

                default:
                    fprintf(stderr, "during client_finished, not supported prf algorithm\n");
                    exit(EXIT_FAILURE);
            }

            PRF(hash_func, sizeof(sess->read_sp.master_secret),
                sess->read_sp.master_secret,
                15, (const uint8_t *)"client finished",
                hash_size, handshake_hash,
                sizeof(calculated_vd), calculated_vd);

#if VERBOSE_CHUNK
            fprintf(stderr, "\nHandshake Chunk\n");
            {
				int z;
                for (z = 0; z < sess->handshake_msgs_len -
                                    record->plain_text.length; z++)
                    fprintf(stderr, "%02X%c", sess->handshake_msgs[z],
                                    ((z + 1) % 16) ? ' ' : '\n');
            }
#endif /* VERBOSE_CHUNK */

#if VERBOSE_SSL
            fprintf(stderr, "\nClient Handshake Verify\n");
            {
                for (z = 0; z < sizeof(calculated_vd); z++)
                    fprintf(stderr, "%02X%c", calculated_vd[z],
                                    ((z + 1) % 16) ? ' ' : '\n');
            }

            fprintf(stderr, "\nMy Handshake Verify\n");
            {
                for (z = 0; z < sizeof(calculated_vd); z++)
                    fprintf(stderr, "%02X%c", vd[z],
                                    ((z + 1) % 16) ? ' ' : '\n');
            }
            fprintf(stderr, "\n");
#endif /* VERBOSE_SSL */

            /* Verify verify_data */
            int diff = 0;

            for (z = 0; z < sizeof(calculated_vd); z++)
                diff |= vd[z] ^ calculated_vd[z];

            if (unlikely(diff)) {
                fprintf(stderr, "Wrong Handshake Data!!\n");
				abort_session(sess);
				goto handshake_record_finish;
			} else {
#if VERBOSE_SSL
                /* Verified */
                fprintf(stderr, "\nCorrect Verify Data!!\n");
#endif /* VERBOSE_SSL */
            }

#if VERBOSE_SSL
            else
                fprintf(stderr, "Handshake Verified!!\n");
#endif /* VERBOSE_SSL */

            /* Send CHANGE_CIPHER_SPEC */
            int change_cipher_pkt_len;

            change_cipher_pkt_len = send_change_cipher_spec(sess);
            
			if (unlikely(change_cipher_pkt_len < 0))
				return -1;

            sess->handshake_state = SERVER_CIPHER_SPEC;

#if VERBOSE_CHUNK
			fprintf(stderr, "\nFinal Handshake Chunk\n");
            {
                int z;
                for (z = 0; z < sess->handshake_msgs_len; z++)
                    fprintf(stderr, "%02X%c", sess->handshake_msgs[z],
							((z + 1) % 16) ? ' ' : '\n');
            }
#endif /* VERBOSE_CHUNK */

            /* Change write-side cipher specification */
            memcpy(write_sp, pending_sp, sizeof(*pending_sp));
            
            sess->send_seq_num_ = 0;
            sess->server_write_IV_seq_num = 0;

#if OFFLOAD_AES_GCM
			/* Add tls_ctx on established session */
			if (COMPARE_CIPHER(sess->write_sp.cipher, 
							   TLS_RSA_WITH_AES_256_GCM_SHA384)) {
				sess->is_offl_aead = 1;
				sess->tls_ctx.tls_version[0] = 3;
				sess->tls_ctx.tls_version[1] = 3;
				/**< TLS v1.2 */
				sess->tls_ctx.cipher_suite = 0x009d;
				/**< TLS_RSA_WITH_AES_256_GCM_SHA384 */
				sess->tls_ctx.aead_key.key_size = 32;
				sess->tls_ctx.aead_key.key = sess->server_write_key;
				sess->tls_ctx.aead_key.iv_size = 4; /* implicit */
				sess->tls_ctx.aead_key.server_write_iv =
					sess->server_write_IV;
				sess->tls_ctx.next_record_num = 0;
				sess->tls_ctx.next_tcp_seq = sess->parent->next_sent_seq;
				sess->tls_ctx.is_ooo = 1;

				/* create tls dev for this session key */
				if (unlikely(rte_eth_tls_device_create(
							  sess->parent->portid, &sess->tls_ctx) < 0)) {
					DEBUG_PRINT("can't create tls_dev!\n");
					exit(EXIT_FAILURE);
				}

				/* DEBUG_PRINT("[core %u] create tls_dev!\n",  */
				/* 			rte_lcore_id()); */
			}
			/* /\* debug *\/ */
			/* exit(EXIT_FAILURE); */
#endif /* OFFLOAD_AES_GCM */

            /* Make Server Finish */
            int server_finish_len;
            uint8_t digest[FINISH_DIGEST_SIZE];

            server_finish_len = FINISH_DIGEST_SIZE;

            switch (pending_sp->prf_algorithm) {
                case PRF_SHA256: {
                    SHA256(sess->handshake_msgs,
                           sess->handshake_msgs_len,
                           handshake_hash);
                    break;
                }
                case PRF_SHA384: {
                    SHA384(sess->handshake_msgs,
                           sess->handshake_msgs_len,
                           handshake_hash);
                    break;
                }

                default:
                    fprintf(stderr, "during server_finished, not supported prf algorithm\n");
                    exit(EXIT_FAILURE);
            }

            PRF(hash_func, sizeof(write_sp->master_secret), write_sp->master_secret,
                15, (const uint8_t *)"server finished",
                hash_size, handshake_hash,
                FINISH_DIGEST_SIZE, digest);

#if ONLOAD
            // int ret;
            // ret = send_connection_state(sess, change_cipher_pkt_len, server_finish_len);
            // if (unlikely(ret < 0)) {
            //     fprintf(stderr, "Sending Connection State Failed!\n");
            // }

            /* Change the connection rule */
            int ret = change_connection_rule(sess);
            if (unlikely(ret < 0)) {
                fprintf(stderr, "Changing Connection Rule Failed!\n");
            }
#else /* ONLOAD */
            UNUSED(server_finish_len);
            UNUSED(change_cipher_pkt_len);
#endif /* !ONLOAD */

            memcpy(sess->server_finish_digest, digest, FINISH_DIGEST_SIZE);
            /* Don't send server finish to client */
            /* Wait till the host ACK packet's arrival */
            make_sccs_sf(sess);

#if VERBOSE_CONN_LAT
            clock_gettime(CLOCK_MONOTONIC, &sess->meta_tx_time);
            uint64_t decrypt_rsa_meta_tx_lat = (sess->meta_tx_time.tv_sec - sess->decrypt_rsa_time.tv_sec) * 1000000000L
                + (sess->meta_tx_time.tv_nsec - sess->decrypt_rsa_time.tv_nsec);
            
            if (decrypt_rsa_meta_tx_lat > max_decrypt_rsa_meta_tx_lat[sess->coreid]) {
                max_decrypt_rsa_meta_tx_lat[sess->coreid] = decrypt_rsa_meta_tx_lat;
            }

            sum_decrypt_rsa_meta_tx_lat[sess->coreid] += decrypt_rsa_meta_tx_lat;
            num_meta_tx[sess->coreid]++;
#endif /* VERBOSE_CONN_LAT */

            ret = send_connection_state(sess, change_cipher_pkt_len, server_finish_len);
            if (unlikely(ret < 0)) {
                fprintf(stderr, "Sending Connection State Failed!\n");
            }

            break;
        }

        default:
            fprintf(stderr, "Unmatched handshake, %d\n", record->fragment.handshake.msg_type);
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
handle_change_cipher_spec(ssl_session_t* sess, record_t* record)
{
#if VERBOSE_SSL
    fprintf(stderr, "[Handle CHANGE_CIPHER_SPEC]\n\n");
#endif /* VERBOSE_SSL */

    if (sess->handshake_state >= CLIENT_CIPHER_SPEC)
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
handle_alert(ssl_session_t* sess, record_t* record)
{
    unsigned char level = record->fragment.alert.level;
    unsigned char description = record->fragment.alert.description;

    const char FATAL = 2;
    const char CLOSE_NOTIFY = 0;

    fprintf(stderr, "Alert received\n");

    delete_record(sess, record); /* delete record */

    /* serve simplified respond */
    if (level == FATAL || description == CLOSE_NOTIFY)
        abort_session(sess);

    return 0;
}

int
handle_data(ssl_session_t* sess, record_t* record)
{
#if VERBOSE_DATA
    unsigned char* data = record->fragment.application_data.data;
    unsigned data_len = record->plain_text.length;
    unsigned z;

    fprintf(stderr, "\nAPP DATA LEN: %u\n", data_len);
    for (z = 0; z < data_len; z++)
        fprintf(stderr, "%c", data[z]);
#else /* VERBOSE_DATA */
    UNUSED(record);
#endif /* !VERBOSE_DATA */

#if !ONLOAD
    sess->ctx->cur_stat.completes++;
#endif /* !ONLOAD */

    fprintf(stderr, "App data received\n");

    delete_record(sess, record); /* delete record */
    abort_session(sess);

    return 0;
}

int 
send_server_hello(ssl_session_t* sess)
{
    record_t* server_hello = new_send_record(sess);
    int length = 0;
    server_hello_t* psh =
        &server_hello->fragment.handshake.body.server_hello;
    int ret;

    security_params_t* sp;
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

    ret = send_handshake(sess, server_hello, SERVER_HELLO, length, PKT_TYPE_NONE);

    if (unlikely(ret < 0)) {
        fprintf(stderr, "send_handshake for server_hello failed\n");
        exit(EXIT_FAILURE);
    }

    return ret;
}

int 
send_certificate(ssl_session_t* sess)
{
    record_t* certificates = new_send_record(sess);
    int length = 0;
    int temp_len;
    certificate_list_t* pcert =
        &certificates->fragment.handshake.body.certificate;
    int ret;

#if VERBOSE_SSL
	fprintf(stderr, "[send certificate]\n");
#endif /* VERBOSE_SSL */

    pcert->certificates = sess->ctx->certificates;
    pcert->certificates->certificate = sess->ctx->ssl_context->certificate;
    length += sess->ctx->ssl_context->certificate_length;

    set_u32(&pcert->certificates->length, (uint32_t *)&length);
    length += sizeof(pcert->certificates[0].length);

    set_u32(&pcert->certificate_length, (uint32_t *)&length);
    length += sizeof(pcert->certificate_length);

    ret = send_handshake(sess,
                         certificates, 
                         CERTIFICATE, 
                         length, 
                         PKT_TYPE_NONE);

    if (unlikely(ret < 0)) {
        fprintf(stderr, "send_handshake for certificate failed\n");
        exit(EXIT_FAILURE);
    }

    return ret;
}

int 
send_server_hello_done(ssl_session_t* sess)
{
    record_t* server_hello_done = new_send_record(sess);
    int length = 0;
    int ret;

#if VERBOSE_SSL
	fprintf(stderr, "[send server hello done]\n");
#endif /* VERBOSE_SSL */

    ret =  send_handshake(sess,
                          server_hello_done,
                          SERVER_HELLO_DONE,
                          length,
                          PKT_TYPE_HELLO);

    if (unlikely(ret < 0)) {
        fprintf(stderr,
                "send_handshake for server_hello_done failed\n");
        exit(EXIT_FAILURE);
    }

    return ret;
}

int 
send_change_cipher_spec(ssl_session_t* sess)
{
    record_t* change_cipher_spec = new_send_record(sess);
    int length = 0;
    int ret;

#if VERBOSE_SSL
	fprintf(stderr, "[send change cipher spec]\n");
#endif /* VERBOSE_SSL */

    change_cipher_spec->fragment.change_cipher_spec.type = 1;
    length +=
        sizeof(change_cipher_spec->fragment.change_cipher_spec.type);

#if OFFLOAD_AES_GCM
    ret = send_record(sess,
					  change_cipher_spec,
					  CHANGE_CIPHER_SPEC,
					  length,
					  PKT_TYPE_FINISH);
#else /* !OFFLOAD_AES_GCM */
    ret = send_record(sess,
                      change_cipher_spec,
                      CHANGE_CIPHER_SPEC,
                      length,
                      PKT_TYPE_NONE);
#endif /* !OFFLOAD_AES_GCM */

    if (unlikely(ret < 0)) {
        fprintf(stderr, "send_record for change_cipher_spec failed.\n");
        return -1;
    }

    return ret;
}

int
make_sccs_sf(ssl_session_t* sess)
{
    uint8_t* my_vd;
    uint8_t* digest = sess->server_finish_digest;
    record_t* server_finished = new_send_record(sess);
    int length = 0;
    int ret;

#if USE_RTE_HWS
#if RTE_FLOW_SYNC
    /* Insert rte_flow flow steering rule to eSwitch (synchronous version) */
    int ret = ins_sync_hws_recv(sess->parent->portid, sess->parent);
       
    if (unlikely(ret < 0))
        return -1;
#endif /* RTE_FLOW_SYNC */
#endif /* USE_RTE_HWS */

#if VERBOSE_AES
	fprintf(stderr, "[send server finish] check \n");
#endif /* VERBOSE_AES */

    /* Send Server Finish */
    my_vd = server_finished-> \
            fragment.handshake.body.server_finished.verify_data;

    if (unlikely(!digest)) {
        fprintf(stderr, "NULL digest!\n");
        exit(EXIT_FAILURE);
    }

    memcpy(my_vd, digest, FINISH_DIGEST_SIZE);

    length += FINISH_DIGEST_SIZE;

    /* There is only FINISHED (20), actually */
#if OFFLOAD_AES_GCM
	if (sess->is_offl_aead) {
		ret = send_handshake(sess,
							 server_finished,
							 CLIENT_FINISHED,
							 length,
							 PKT_TYPE_OFFL_TLS_AES);
	} else {
		ret = send_handshake(sess,
							 server_finished,
							 CLIENT_FINISHED,
							 length,
							 PKT_TYPE_FINISH);
	}
#else /* !OFFLOAD_AES_GCM */
    ret = send_handshake(sess,
                         server_finished,
                         CLIENT_FINISHED,
                         length,
                         PKT_TYPE_NONE);
#endif /* !OFFLOAD_AES_GCM */

    if (unlikely(ret < 0)) {
        fprintf(stderr, "send_handshake for server_finished failed.\n");
        exit(EXIT_FAILURE);
    }

    return ret;
}

// int 
// send_server_finish(ssl_session_t* sess)
// {
//     uint8_t* my_vd;
//     uint8_t* digest = sess->server_finish_digest;
//     record_t* server_finished = new_send_record(sess);
//     int length = 0;
//     int ret;

// #if USE_RTE_HWS
// #if RTE_FLOW_SYNC
//     /* Insert rte_flow flow steering rule to eSwitch (synchronous version) */
//     int ret = ins_sync_hws_recv(sess->parent->portid, sess->parent);
       
//     if (unlikely(ret < 0))
//         return -1;
// #endif /* RTE_FLOW_SYNC */
// #endif /* USE_RTE_HWS */

// #if VERBOSE_AES
// 	fprintf(stderr, "[send server finish] check \n");
// #endif /* VERBOSE_AES */

//     /* Send Server Finish */
//     my_vd = server_finished-> \
//             fragment.handshake.body.server_finished.verify_data;

//     if (unlikely(!digest)) {
//         fprintf(stderr, "NULL digest!\n");
//         exit(EXIT_FAILURE);
//     }

//     memcpy(my_vd, digest, FINISH_DIGEST_SIZE);

//     length += FINISH_DIGEST_SIZE;

//     /* There is only FINISHED (20), actually */
// #if OFFLOAD_AES_GCM
// 	if (sess->is_offl_aead) {
// 		ret = send_handshake(sess,
// 							 server_finished,
// 							 CLIENT_FINISHED,
// 							 length,
// 							 PKT_TYPE_OFFL_TLS_AES);
// 	} else {
// 		ret = send_handshake(sess,
// 							 server_finished,
// 							 CLIENT_FINISHED,
// 							 length,
// 							 PKT_TYPE_FINISH);
// 	}
// #else /* !OFFLOAD_AES_GCM */
//     ret = send_handshake(sess,
//                          server_finished,
//                          CLIENT_FINISHED,
//                          length,
//                          PKT_TYPE_FINISH);
// #endif /* !OFFLOAD_AES_GCM */

//     if (unlikely(ret < 0)) {
//         fprintf(stderr, "send_handshake for server_finished failed.\n");
//         exit(EXIT_FAILURE);
//     }

//     return ret;
// }
int
send_server_finish(ssl_session_t* sess)
{
    // make_sccs_sf(sess);

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
#else /* OFFLOAD_AES_GCM */
        ret = send_tcp_packet(sess->parent, sess->send_buffer,
                                sess->send_buffer_offset, TCP_FLAG_ACK, 0);
#endif /* !OFFLOAD_AES_GCM */

        if (unlikely(ret < 0))
            fprintf(stderr, "\nSending Payload failed, len: %d\n",
                            sess->ctx->dpc->wmbufs[sess->parent->portid].len);
    }

    memset(&sess->send_buffer, 0, sizeof(sess->send_buffer));
    sess->send_buffer_offset = 0;

    return 0;
}

int
send_handshake(ssl_session_t* sess, record_t* record,
               uint8_t msg_type, int length, int send_type)
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
send_record(ssl_session_t* sess, record_t* record,
            uint8_t record_type, int length, int send_type)
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

    if (unlikely(pack_record(record) < 0))
        return -1;

    if (record->plain_text.record_type == HANDSHAKE) {
        if (unlikely(store_handshake(sess, record) < 0)) {
#if VERBOSE_SSL
            fprintf(stderr, "handshake retransmission\n");
#endif /* VERBOSE_SSL */
        }
    }

	if (unlikely(sess->write_sp.bulk_cipher_algorithm != NO_CIPHER)) {
		if (unlikely(sess->write_sp.mac_algorithm == NO_MAC)) {
			fprintf(stderr, "[send record] Error: the packet has no need to attach MAC!\n");
            exit(EXIT_FAILURE);
        }

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
#else /* !OFFLOAD_AES_GCM */
		record->state = TO_ENCRYPT;

        if (unlikely(encrypt_record(sess, record) < 0))
            return -1;
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

    if (send_type) {
		ret = -1;
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
#else /* OFFLOAD_AES_GCM */
            ret = send_tcp_packet(sess->parent, sess->send_buffer,
                                  sess->send_buffer_offset, TCP_FLAG_ACK, 0);
#endif /* !OFFLOAD_AES_GCM */

            if (unlikely(ret < 0))
                fprintf(stderr, "\nSending Payload failed, len: %d\n",
                                sess->ctx->dpc->wmbufs[sess->parent->portid].len);
        }

        memset(&sess->send_buffer, 0, sizeof(sess->send_buffer));
        sess->send_buffer_offset = 0;
    }

    delete_record(sess, record);

    return copy_len;
}

int
pack_record(record_t* record)
{
    uint8_t* decrypted = record->decrypted;;
    plain_text_t* plain_text = &record->plain_text;
    int offset = 0;

    assert(record->state == TO_PACK_HEADER);
    record->state = TO_APPEND_MAC;

#if VERBOSE_STATE
    fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
                    ((ssl_session_t *)record->sess)->parent->session_id,
                    record->id,
                    state_to_string(TO_PACK_HEADER),
                    state_to_string(record->state));
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
        case APPLICATION_DATA:
            fprintf(stderr, "Not supported yet\n");
            break;
    }

    return ret;
}

int
pack_handshake(record_t* record, int offset)
{
    uint8_t* decrypted = record->decrypted;
    handshake_t* phs = &record->fragment.handshake;

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
            server_hello_t* psh = &phs->body.server_hello;

            memcpy(decrypted + offset,
                   &psh->version,
                   sizeof(psh->version));
            offset += sizeof(psh->version);

            memcpy(decrypted + offset,
                   &psh->random,
                   sizeof(psh->random));
            offset += sizeof(psh->random);

            *(uint8_t *)(decrypted + offset) = 
                    psh->session_id_length;
            offset += sizeof(uint8_t);

            memcpy(decrypted + offset,
                   &psh->session_id,
                   sizeof(psh->session_id));
            offset += sizeof(psh->session_id);

            *(cipher_suite_t *)(decrypted + offset) = 
                    psh->cipher_suite;
            offset += sizeof(psh->cipher_suite);

            *(compression_method_t *)(decrypted + offset) =
                    psh->compression_method;
            offset += sizeof(psh->compression_method);

            break;
        }
        case CERTIFICATE: {
            certificate_list_t* pc = &phs->body.certificate;

            memcpy(decrypted + offset,
                   &pc->certificate_length,
                   sizeof(pc->certificate_length));
            offset += sizeof(pc->certificate_length);

            int remain_cert_len = get_u32(pc->certificate_length);

            certificate_t* cert;
            cert = pc->certificates;
            while (remain_cert_len > 0) {
                memcpy(decrypted + offset,
                       &cert->length,
                       sizeof(cert->length));
                offset += sizeof(cert->length);
                remain_cert_len -= sizeof(cert->length);

                memcpy(decrypted + offset,
                       cert->certificate,
                       get_u32(cert->length));
                offset += get_u32(cert->length);
                remain_cert_len -= get_u32(cert->length);

                cert = (certificate_t *)(((uint8_t *)pc->certificates) +
                                         get_u32(cert->length) +
                                         sizeof(cert->length));
            }
            break;
        }
        case SERVER_HELLO_DONE: {
            break;
        }
        case CLIENT_FINISHED:
        case SERVER_FINISHED: {
            finished_t* pf = &phs->body.server_finished;
            memcpy(decrypted + offset,
                   pf->verify_data, sizeof(pf->verify_data));
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
pack_change_cipher_spec(record_t* record, int offset)
{
#if VERBOSE_SSL
    fprintf(stderr, "[PACK CHANGE CIPHER SPEC]\n");
#endif /* VERBOSE_SSL */

    memcpy(record->decrypted + offset,
           &record->fragment,
           sizeof(change_cipher_spec_t));
    offset += sizeof(change_cipher_spec_t);
    return 0;
}

int
attach_mac(ssl_session_t* sess, record_t* record)
{
    security_params_t* write_sp = &sess->write_sp;
    generic_block_cipher_t* block_cipher =
                            &record->cipher_text.fragment.block_cipher;

#if VERBOSE_SSL
    fprintf(stderr, "[attach mac]\n");
#endif /* VERBOSE_SSL */

    ssl_crypto_op_t* op = new_ssl_crypto_op(sess);
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
        op->in_len = record->plain_text.length +
                     sizeof(record->seq_num) +
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
            fprintf(stderr, "%02X%c", op->key[z],
                            ((z + 1) % 16) ? ' ' : '\n');
    }

    fprintf(stderr, "\nmac_in:\n");
    {
        for (unsigned z = 0; z < op->in_len; z++)
            fprintf(stderr, "%02X%c", op->in[z],
                            ((z + 1) % 16) ? ' ' : '\n');
    }

    fprintf(stderr, "\nmac_out:\n");
    {
        for (unsigned z = 0; z < op->out_len; z++)
            fprintf(stderr, "%02X%c", op->out[z],
                            ((z + 1) % 16) ? ' ' : '\n');
    }
#endif /* VERBOSE_MAC */

    return handle_after_mac_crypto(sess, op);
}

int
encrypt_record(ssl_session_t* sess, record_t* record)
{
    security_params_t* write_sp = &sess->write_sp;
    generic_block_cipher_t* block_cipher =
        &record->cipher_text.fragment.block_cipher;

#if VERBOSE_SSL
    fprintf(stderr, "[encrypt Record]\n");
#endif /* VERBOSE_SSL */

    if (unlikely(sess->server_write_IV_seq_num != record->seq_num)) {
        fprintf(stderr, "Something wrong with sequence number!\n");
        return -1;
    }

    ssl_crypto_op_t* op = new_ssl_crypto_op(sess);

	if (unlikely(!op))
        return -1;

    switch (write_sp->cipher_type) {
        case BLOCK: {
            int pad_len = (record->cipher_text.length % 16) ?
                (16 - record->cipher_text.length % 16) : 0;

            block_cipher->padding = block_cipher->mac + MAC_SIZE;
            block_cipher->padding_length = pad_len;
            memset(block_cipher->padding, pad_len - 1, pad_len);

#if VERBOSE_AES
            fprintf(stderr, "\ndecrypted:\n");
            {
                unsigned z;
                for (z = 0; z < 64; z++)
                    fprintf(stderr, "%02X%c", record->decrypted[z],
                            ((z + 1) % 16) ? ' ' : '\n');
            }
#endif /* VERBOSE_AES */

            record->cipher_text.length += pad_len;
            block_cipher->IV = record->decrypted + RECORD_HEADER_SIZE;

            memmove(block_cipher->IV + write_sp->fixed_iv_length,
                    block_cipher->IV,
                    record->cipher_text.length);

            block_cipher->content += write_sp->fixed_iv_length;
            block_cipher->mac += write_sp->fixed_iv_length;
            block_cipher->padding += write_sp->fixed_iv_length;

#if VERBOSE_AES
            fprintf(stderr, "\n IV: %p,\n content: %p,\n mac: %p,\n padding: %p\n",
                    block_cipher->IV,
                    block_cipher->content,
                    block_cipher->mac,
                    block_cipher->padding);
#endif /* VERBOSE_AES */

            /* Set initial iv as all 0 */
            /* Need to support normal packets */
            memset(block_cipher->IV, 0, write_sp->fixed_iv_length);
            /* sj: why? */
            // record->cipher_text.length += write_sp->fixed_iv_length;

            *(uint16_t *)(record->decrypted + 3) = htons(record->cipher_text.length);
            /* sj: why? */
            // op->in = block_cipher->IV;
            op->in = block_cipher->IV + write_sp->fixed_iv_length;
            op->out = record->data + RECORD_HEADER_SIZE;
            // memcpy(record->data, record->decrypted, RECORD_HEADER_SIZE);
            /* sj: why not? */
            memcpy(record->data, 
                   block_cipher->IV, 
                   write_sp->fixed_iv_length);
            memcpy(record->data + RECORD_HEADER_SIZE, record->decrypted, RECORD_HEADER_SIZE);

#if VERBOSE_AES
            fprintf(stderr, "\nRevised decrypted:\n");
            {
                unsigned z;
                for (z = 0; z < 80; z++)
                    fprintf(stderr, "%02X%c", record->decrypted[z],
                            ((z + 1) % 16) ? ' ' : '\n');
            }
#endif /* VERBOSE_AES */

            op->iv = sess->server_write_IV;
            op->key = sess->server_write_key;
            op->in_len = record->cipher_text.length;
            op->key_len = write_sp->enc_key_size;
            op->iv_len = write_sp->fixed_iv_length;
            op->out_len = record->cipher_text.length;
            record->length = record->cipher_text.length + RECORD_HEADER_SIZE;

            op->opcode.u32 = TLS_OPCODE_AES_CBC_256_ENCRYPT;

            op->data = (void *)record;

            if (unlikely(execute_aes_crypto(sess->ctx->symmetric_crypto_ctx, op) < 0)) {
                delete_op(op);
        
                return -1;
            }

#if VERBOSE_AES
            fprintf(stderr, "\nEncrypted Data with Total Length %lu\n", record->length);
            {
                unsigned z;
                for (z = 0; z < 80; z++)
                    fprintf(stderr, "%02X%c", record->data[z],
                            ((z + 1) % 16) ? ' ' : '\n');
            }
#endif /* VERBOSE_AES */

            break;
        }
        case AEAD: {
            uint8_t nonce[write_sp->fixed_iv_length + write_sp->record_iv_length];
            uint8_t additional_data[sizeof(sequence_num_t) + RECORD_HEADER_SIZE];
            generic_aead_cipher_t* aead_cipher =
                &record->cipher_text.fragment.aead_cipher;
            sequence_num_t seq_num;

#if VERBOSE_AES
            fprintf(stderr, "[encrypt record] encrypt with gcm !!!!!!!!!!!!!!!!!!!!!!!\n");
            {
                int z;
                fprintf(stderr, "Implicit part iv (client_write_iv):\n");
                for (z = 0; z < write_sp->fixed_iv_length; z++)
                    fprintf(stderr, "%02X%c", sess->server_write_IV[z],
                            ((z + 1) % 16)? ' ' : '\n');
                fprintf(stderr, "\n");
            }
#endif /* VERBOSE_AES */

            record->cipher_text.length = record->plain_text.length;
            record->data -= write_sp->record_iv_length;

            aead_cipher->nonce_explicit = record->data + RECORD_HEADER_SIZE;

            memcpy(nonce, sess->server_write_IV,
                   write_sp->fixed_iv_length);

            /* Set initial explicit iv as all 0 */
            /* ToDo: generate IV with random function */
#if 0
/* #if MODIFY_FLAG */
            int i;
            int copy_byte;
            long int rand_tmp;
            for(i = 0; i < write_sp->record_iv_length; i += copy_byte) {
                /* debug */
                rand_tmp = random();
                copy_byte = MIN(write_sp->fixed_iv_length - i, (uint8_t)sizeof(long int));
                memcpy((unsigned char *)(aead_cipher->nonce_explicit) + i, &rand_tmp, copy_byte);
            }

            /* debug */
            {
                int z;
                fprintf(stderr, "[encrypt record] explicit iv:\n");
                for (z = 0; z < write_sp->record_iv_length; z++)
                    fprintf(stderr, "%02X%c", aead_cipher->nonce_explicit[z],
                            ((z + 1) % 16)? ' ' : '\n');
                fprintf(stderr, "\n");
            }

#else
            memset(aead_cipher->nonce_explicit, 0,
                   write_sp->record_iv_length);
#endif
            memcpy(nonce + write_sp->fixed_iv_length, aead_cipher->nonce_explicit,
                   write_sp->record_iv_length);
            record->cipher_text.length += write_sp->record_iv_length;

            record->cipher_text.length += GCM_TAG_SIZE;

            /* fill aead_cipher content */
            aead_cipher->content = record->decrypted + RECORD_HEADER_SIZE;

            *(uint16_t *)(record->decrypted + 3) = htons(record->cipher_text.length);
            op->in = aead_cipher->content;
            op->out = record->data + RECORD_HEADER_SIZE + write_sp->record_iv_length;

            memcpy(record->data, record->decrypted, RECORD_HEADER_SIZE);
            seq_num = bswap_64(sess->send_seq_num_);

            /* make aad */
            memcpy(additional_data, &seq_num, sizeof(seq_num));
            memcpy(additional_data + sizeof(sequence_num_t), record->data,
                RECORD_HEADER_SIZE);

            if (additional_data[sizeof(additional_data) - 1] < sizeof(sequence_num_t) + GCM_TAG_SIZE) {
                additional_data[sizeof(additional_data) - 2] -= 1;
            }
            additional_data[sizeof(additional_data) - 1] -= sizeof(sequence_num_t) + GCM_TAG_SIZE;

            op->in_len = record->plain_text.length;
            op->out_len = record->cipher_text.length;
            op->iv = nonce;
            op->iv_len = write_sp->fixed_iv_length + write_sp->record_iv_length;
            op->aad = additional_data;
            op->aad_len = sizeof(sequence_num_t) + RECORD_HEADER_SIZE;
            op->key = sess->server_write_key;
            op->key_len = write_sp->enc_key_size;

            op->opcode.u32 = TLS_OPCODE_AES_GCM_256_ENCRYPT;
            op->data = (void *)record;

            record->length = record->cipher_text.length + RECORD_HEADER_SIZE;

#if VERBOSE_AES
            fprintf(stderr, "\n[encrypt record] op->in (aead->content) with length %d:\n",
                    op->in_len);
            uint8_t z;
            for (z = 0; z < op->in_len; z++)
                fprintf(stderr, "%02X%c", op->in[z],
                        ((z + 1) % 16) ? ' ' : '\n');

            fprintf(stderr, "\n[encrypt record] op->iv (nonce) with length %d:\n",
                    op->iv_len);
            for (z = 0; z < op->iv_len; z++)
                fprintf(stderr, "%02X%c", op->iv[z],
                        ((z + 1) % 16) ? ' ' : '\n');

            fprintf(stderr, "\n[encrypt record] op->aad (additional_data) with length %d:\n",
                    op->aad_len);
            for (z = 0; z < op->aad_len; z++)
                fprintf(stderr, "%02X%c", op->aad[z],
                        ((z + 1) % 16) ? ' ' : '\n');

            fprintf(stderr, "\n[encrypt record] op->key (sess->server_write_key) with length %d:\n",
                    op->key_len);
            for (z = 0; z < op->key_len; z++)
                fprintf(stderr, "%02X%c", op->key[z],
                        ((z + 1) % 16) ? ' ' : '\n');
#endif /* VERBOSE_AES */

            if (unlikely(execute_aes_crypto(sess->ctx->symmetric_crypto_ctx, op) < 0)) {
                delete_op(op);
        
                return -1;
            }

#if VERBOSE_AES
            fprintf(stderr, "\n[encrypt record] Encrypted Data with Total Length %lu\n", record->length);
            {
                int z;
                for (z = 0; z < 160; z++)
                    fprintf(stderr, "%02X%c", record->data[z],
                            ((z + 1) % 16) ? ' ' : '\n');
            }
#endif /* VERBOSE_AES */
        }

        default:
            break;
    }

    return handle_after_aes_crypto(sess, op);
}

/*--------------------------------- MISC ------------------------------------*/
int
handle_after_rsa_crypto(ssl_session_t* sess,
						ssl_crypto_op_t *op)
{
	int ret = -1;
    record_t* record = (record_t *)op->data;
    int crypto_type = op->opcode.s.op;
    if (unlikely(!record))
        return -1;

    assert(op->opcode.s.function == TLS_RSA);

#if VERBOSE_SSL
    fprintf(stderr, "Handle after RSA Crypto\n");
#endif /* VERBOSE_SSL */

	if (likely(crypto_type == PRIVATE_DECRYPT)) {
		ret = handle_after_private_decrypt(sess, record, op);
	}
	else
		assert(0);

    delete_op(op);

	return ret;
}

int
handle_after_private_decrypt(ssl_session_t* sess, 
                             record_t* record, 
                             ssl_crypto_op_t* op)
{
    UNUSED(sess); /* for fnptr */
    
    premaster_secret_t* pms =
        &record->fragment.handshake.body.client_key_exchange.pms;

    assert(op->pka_out->result_cnt == 1);
    // operand_to_string(&op->pka_out->results[0], (uint8_t *)pms, 48u);
    operand_to_string(&sess->pka_results->results[0], (uint8_t *)pms, 48u);

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
handle_after_aes_crypto(ssl_session_t* sess, ssl_crypto_op_t* op)
{
	int ret = -1;
    int invalid = 0;
    record_t* record = (record_t *)op->data;
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
                "[handle after aes crypto] invalid crypto_type: %d (expected %d~%d)\n",
                crypto_type, ENCRYPT, DECRYPT);
        invalid = 1;
    }

    if (unlikely(function < TLS_AES_CBC || function > TLS_AES_GCM)) {
        fprintf(stderr,
                "[handle after aes crypto] invalid function: %d (expected %d~%d)\n",
                function, TLS_AES_CBC, TLS_AES_GCM);
        invalid = 1;
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
handle_after_aes_cbc_encrypt(ssl_session_t* sess,
                             record_t* record, 
                             ssl_crypto_op_t* op)
{
    assert(record->state == TO_ENCRYPT);
    record->state = WRITE_READY;

#if VERBOSE_STATE
    fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
                    ((ssl_session_t *)record->sess)->parent->session_id,
                    record->id,
                    state_to_string(TO_ENCRYPT),
                    state_to_string(record->state));
#endif /* VERBOSE_STATE */

    memcpy(sess->server_write_IV,
           op->out + op->out_len - sess->write_sp.fixed_iv_length,
           sess->write_sp.fixed_iv_length);

    sess->server_write_IV_seq_num = record->seq_num + 1;

	return 0;
}

int
handle_after_aes_cbc_decrypt(ssl_session_t* sess,
                             record_t* record, ssl_crypto_op_t* op)
{
    assert(record->state == TO_DECRYPT);
    record->state = TO_VERIFY_MAC;

#if VERBOSE_STATE
    fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
                    ((ssl_session_t *)record->sess)->parent->session_id,
                    record->id,
                    state_to_string(TO_DECRYPT),
                    state_to_string(record->state));
#endif /* VERBOSE_STATE */

#if VERBOSE_AES
    unsigned z = 0;
    fprintf(stderr, "\n[handle after aes cbc decrypt] op->in (original data):\n\n");
    {
        for (z = 0; z < op->in_len; z++)
            fprintf(stderr, "%02X%c", *((uint8_t *)(op->in) + z),
                ((z + 1) % 16) ? ' ' : '\n');
    }

    fprintf(stderr, "\n[handle after aes cbc decrypt] op->out (decrypted data):\n\n");
    {
        for (z = 0; z < op->out_len; z++)
            fprintf(stderr, "%02X%c", *((uint8_t *)(op->out) + z),
                ((z + 1) % 16) ? ' ' : '\n');
    }
#else /* VERBOSE_AES */
    UNUSED(op);
#endif /* !VERBOSE_AES */

    sess->client_write_IV_seq_num = record->seq_num + 1;

	return 0;
}

int
handle_after_aes_gcm_encrypt(ssl_session_t* sess,
                             record_t* record, ssl_crypto_op_t* op)
{
	UNUSED(op);

	if (record->state != TO_ENCRYPT) {
		fprintf(stderr, "[handle after aes gcm encrypt] wrong record->state: %d!\n",
				record->state);
		return -1;
	}

    record->state = WRITE_READY;

#if VERBOSE_STATE
    fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
                    ((ssl_session_t *)record->sess)->parent->session_id,
                    record->id,
                    state_to_string(TO_ENCRYPT),
                    state_to_string(record->state));
#endif /* VERBOSE_STATE */

    sess->server_write_IV_seq_num = record->seq_num + 1;

	return 0;
}

int
handle_after_aes_gcm_decrypt(ssl_session_t* sess,
                             record_t* record, ssl_crypto_op_t* op)
{
    assert(record->state == TO_DECRYPT);
    record->state = TO_VERIFY_MAC;

#if VERBOSE_STATE
    fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
                    ((ssl_session_t *)record->sess)->parent->session_id,
                    record->id,
                    state_to_string(TO_DECRYPT),
                    state_to_string(record->state));
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
#else /* VERBOSE_AES */
    UNUSED(op);
#endif /* !VERBOSE_AES */

    sess->client_write_IV_seq_num = record->seq_num + 1;

	return 0;
}

int
handle_after_mac_crypto(ssl_session_t* sess,
						ssl_crypto_op_t* op)
{
	int ret = -1;
    record_t* record = (record_t *)op->data;

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
handle_mac(ssl_session_t* sess,
                record_t* record, ssl_crypto_op_t* op)
{
    int diff = 0;
    unsigned z = 0;
    generic_block_cipher_t* block_cipher =
        &record->cipher_text.fragment.block_cipher;
    security_params_t* read_sp = &sess->read_sp;

    assert(record->state == TO_APPEND_MAC ||
           record->state == TO_VERIFY_MAC);

    if (record->is_received) {
        uint8_t* recv_mac = block_cipher->mac;

#if VERBOSE_SSL
        fprintf(stderr, "\n[HANDLE MAC] VERIFY MAC\n");
#endif /* VERBOSE_SSL */

#if VERBOSE_MAC
        fprintf(stderr, "\nmac received:\n");
        {
            for (z = 0; z < read_sp->mac_key_size; z++)
                fprintf(stderr, "%02X%c",
                                recv_mac[z],
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
        *(uint16_t *)(record->decrypted + 3) = htons(record->cipher_text.length);

#if VERBOSE_STATE
        fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
                        sess->parent->session_id,
                        record->id,
                        state_to_string(TO_APPEND_MAC),
                        state_to_string(record->state));
#endif /* VERBOSE_STATE */

		return 0;
    }

	/* can't reach here */
	return -1;
}
