#include "host.h"

/* Functions for printing connection meta */
void print_hex_array(const char *label, const uint8_t *data, size_t size) {
    printf("%s: ", label);
    for (size_t i = 0; i < size; ++i) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0)
            printf("\n%*s", (int)strlen(label) + 2, "");
    }
    printf("\n");
}

void print_conn_meta(const conn_meta_t *meta) {
    printf("\n[Meta Packet Info - SSL]\n");
    printf("Session ID           : %u\n", meta->session_id);
    printf("SSL Version          : %u.%u\n", meta->version.major, meta->version.minor);
    printf("Bulk Cipher Alg      : 0x%08x\n", meta->bulk_cipher_algorithm);
    printf("Cipher Type          : 0x%08x\n", meta->cipher_type);
    printf("MAC Algorithm        : 0x%08x\n", meta->mac_algorithm);

    printf("MAC Key Size         : %u\n", meta->mac_key_size);
    print_hex_array("Client MAC Secret", meta->client_write_MAC_secret, MAX_KEY_SIZE);
    print_hex_array("Server MAC Secret", meta->server_write_MAC_secret, MAX_KEY_SIZE);

    printf("Encryption Key Size  : %u\n", meta->enc_key_size);
    print_hex_array("Client Write Key", meta->client_write_key, MAX_KEY_SIZE);
    print_hex_array("Server Write Key", meta->server_write_key, MAX_KEY_SIZE);

    printf("Fixed IV Length      : %u\n", meta->fixed_iv_length);
    print_hex_array("Client Write IV", meta->client_write_IV, MAX_KEY_SIZE);
    print_hex_array("Server Write IV", meta->server_write_IV, MAX_KEY_SIZE);
    printf("====================\n");
}

#if ONLOAD

int
change_connection_rule(ssl_session_t* sess)
{
    sess->parent->onload = 1;

    return 0;
}

void
build_connection_meta(ssl_session_t *sess, conn_meta_t *meta)
{
    tcp_connection_t *tcp = sess->parent;
    security_params_t *sp = &sess->write_sp;

    memset(meta, 0, sizeof(*meta));

    meta->session_id = tcp->session_id;

    /* SSL related parameter */
    meta->version = sess->version;

    meta->bulk_cipher_algorithm = sp->bulk_cipher_algorithm;
    meta->cipher_type = sp->cipher_type;
    meta->mac_algorithm = sp->mac_algorithm;

    meta->mac_key_size = sp->mac_key_size;

    memcpy(&meta->client_write_MAC_secret,
           &sess->client_write_MAC_secret,
           sp->mac_key_size);

    memcpy(&meta->server_write_MAC_secret,
           &sess->server_write_MAC_secret,
           sp->mac_key_size);

    meta->enc_key_size = sp->enc_key_size;

    memcpy(&meta->client_write_key,
           &sess->client_write_key,
           sp->enc_key_size);

    memcpy(&meta->server_write_key,
           &sess->server_write_key,
           sp->enc_key_size);

    meta->fixed_iv_length = sp->fixed_iv_length;

    memcpy(&meta->client_write_IV,
           &sess->client_write_IV,
           sp->fixed_iv_length);

    memcpy(&meta->server_write_IV,
           &sess->server_write_IV,
           sp->fixed_iv_length);
    
}

static void
encrypt_meta(ssl_session_t *sess, uint8_t *meta, uint8_t *encrypted, int len)
{
    ssl_crypto_op_t *op;
    thread_context_t *ctx = sess->ctx;

    op = TAILQ_FIRST(&ctx->op_pool);
    if (unlikely(!op)) {
        fprintf(stderr, "[encrypt_meta] Not enough op, and this must not happen.\n");
        exit(EXIT_FAILURE);
    }

    TAILQ_REMOVE(&ctx->op_pool, op, op_pool_link);
    ctx->free_op_cnt--;
    ctx->using_op_cnt++;

    op->in = meta;
    op->out = encrypted;
    op->key = nic_key;
    op->iv = nic_iv;

    op->in_len = len;
    op->out_len = len;
    op->key_len = nic_key_size;
    op->iv_len = nic_iv_size;

    op->opcode.u32 = TLS_OPCODE_AES_CBC_256_ENCRYPT;
    op->data = NULL;


#if VERBOSE_TCP
    fprintf(stderr, "\nOriginal Data:\n");
    {
        int z;
        for (z = 0; z < len; z++)
            fprintf(stderr, "%02X%c", op->in[z],
                            ((z + 1) % 16) ? ' ' : '\n');
        fprintf(stderr, "\n");
    }
#endif /* VERBOSE_TCP */

    execute_aes_crypto(sess->ctx->symmetric_crypto_ctx, op);

#if VERBOSE_TCP
    fprintf(stderr, "\nEncrypted Data:\n");
    {
        int z;
        for (z = 0; z < len; z++)
            fprintf(stderr, "%02X%c", op->out[z],
                            ((z + 1) % 16) ? ' ' : '\n');
        fprintf(stderr, "\n");
    }
#endif /* VERBOSE_TCP */
}

int
send_connection_state(ssl_session_t* sess, int change_cipher_pkt_len, int server_finish_len)
{
    assert(sess);
    conn_meta_t meta;
    uint8_t encrypted[sizeof(conn_meta_t)];
    uint32_t next_recv_seq = 0, next_recv_ack = 0, next_pkt_len = 0, pad_len = 0;

    /* TCP related parameter */
    next_recv_seq = htonl(sess->parent->last_sent_ack + sess->parent->last_recv_len);

    switch(sess->write_sp.cipher_type) {
        /* AES-CBC */
        case BLOCK: {
            next_pkt_len = sess->write_sp.fixed_iv_length +
                sizeof(sequence_num_t) + 4 + server_finish_len + MAC_SIZE;
            pad_len = (next_pkt_len % 16) ? (16 - (next_pkt_len % 16)) : 0;
            next_pkt_len += pad_len;
            next_pkt_len += RECORD_HEADER_SIZE;

            next_recv_ack = htonl(sess->parent->last_recv_ack +
                                next_pkt_len + change_cipher_pkt_len);
            break;
        }
        /* AES-GCM */
        case AEAD: {
            next_pkt_len = RECORD_HEADER_SIZE;
            next_pkt_len += sizeof(sequence_num_t) + 4 + server_finish_len + GCM_TAG_SIZE;

            next_recv_ack = htonl(sess->parent->last_recv_ack +
                                next_pkt_len + change_cipher_pkt_len);
            break;
        }
        default:
            fprintf(stderr, "[send_connection_state] can't support cipher type\n");
            exit(EXIT_FAILURE);
    }

#if VERBOSE_TCP
    fprintf(stderr, "Sending Meta!\n\n"
                    "last_sent_ack: %u\n"
                    "last_sent_seq: %u\n"
                    "last_sent_len: %u\n"
                    "last_recv_ack: %u\n"
                    "last_recv_seq: %u\n"
                    "last_recv_len: %u\n\n"
                    "change_cipher_pkt_len: %d\n"
                    "server_finish_len: %d\n"
                    "next_pkt_len: %u\n\n"
                    "next_recv_seq: %u\n"
                    "next_recv_ack: %u\n",
                    sess->parent->last_sent_ack,
                    sess->parent->last_sent_seq,
                    sess->parent->last_sent_len,
                    sess->parent->last_recv_ack,
                    sess->parent->last_recv_seq,
                    sess->parent->last_recv_len,
                    change_cipher_pkt_len,
                    server_finish_len,
                    next_pkt_len,
                    ntohl(next_recv_seq),
                    ntohl(next_recv_ack));
#endif /* VERBOSE_TCP */

#if LINUX_TCP_SERVER
    if (send_meta_packet(sess->coreid, sess->parent->portid + 1,  sess->parent)) {
        fprintf(stderr, "Failed to send tcp tls meta for port %d\n",  sess->parent->portid + 1);
        exit(EXIT_FAILURE);
    }
#else /* !LINUX_TCP_SERVER */
#if ENCRYPT_META
    encrypt_meta(sess, (uint8_t *)&meta, encrypted, sizeof(conn_meta_t));

    if (unlikely(send_meta_packet(sess->coreid, sess->parent->portid + 1, sess->parent,
                                  next_recv_seq, next_recv_ack,
                                  (uint8_t *)&encrypted, sizeof(conn_meta_t))) < 0) {
        return -1;
    }
#else /* ENCRYPT_META */
    /* If you use mTCP, you should activate this part for establish handshaked mTCP session */
    if (unlikely(send_meta_packet(sess->coreid, sess->parent->portid + 1, sess->parent,
                                  next_recv_seq, next_recv_ack,
                                  (uint8_t *)&meta, sizeof(conn_meta_t))) < 0) {
        return -1;
    }
#endif /* !ENCRYPT_META */
#endif /* !LINUX_TCP_SERVER */

    UNUSED(encrypted);

#if VERBOSE_STAT_0    
    sess->ctx->cur_stat.completes++;
#endif /* VERBOSE_STAT_0 */

    return 0;
}

#endif /* ONLOAD */
