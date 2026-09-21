#include "meta_pkt.h"

extern int tls13;

#if EVALUATION
extern uint64_t key_metas[MAX_THREAD_NUM];
#endif /* EVALUATION */

#if DEBUG
extern int nic_unterminated_conn;
extern int sent_close_meta;
#endif /* DEBUG */
/*----------------------------------------------------------------------------*/
/* Recv */
int
validate_meta_type(uint8_t* meta_buf, 
                   ssize_t buf_len)
{
    uint16_t eth_type = (ntohs(*(uint16_t *)&meta_buf[12]));

    switch (eth_type) {
        case KEY_META_ETH_TYPE_0:
        case KEY_META_ETH_TYPE_1:
        case KEY_META_ETH_TYPE_2:
        case KEY_META_ETH_TYPE_3:
        case KEY_META_ETH_TYPE_4:
        case KEY_META_ETH_TYPE_5:
        case KEY_META_ETH_TYPE_6:
        case KEY_META_ETH_TYPE_7:
        case KEY_META_ETH_TYPE_8:
        case KEY_META_ETH_TYPE_9:
        case KEY_META_ETH_TYPE_10:
        case KEY_META_ETH_TYPE_11:
        case KEY_META_ETH_TYPE_12:
        case KEY_META_ETH_TYPE_13:
        case KEY_META_ETH_TYPE_14:
        case KEY_META_ETH_TYPE_15:
            return META_TYPE_KEY;
        case RST_CONN_META_ETH_TYPE:
            return META_TYPE_RST_CONN;
        case WEIRD_SYN:
            return META_TYPE_WEIRD_SYN;
        default:
            return META_TYPE_UNKNOWN;
    }
}

int 
handle_meta_packet(thread_ctx_t* ctx,
                   uint8_t* meta_buf, 
                   ssize_t buf_len)
{
    ssize_t len;
    int ret = 0;

    MEASURE("recvfrom",
        len = recvfrom(ctx->meta_sock, meta_buf, buf_len, 0, NULL, NULL);
    );

    if (len < 0) {
        perror("recvfrom");
        return -1;
    }

    int meta_type = validate_meta_type(meta_buf, len);

    if (unlikely(meta_type == META_TYPE_UNKNOWN)) {
        fprintf(stderr, "Ignore unknown packet\n");
        return -1;
    }

    switch (meta_type) {
        case META_TYPE_KEY:
            ret = handle_key_packet(ctx, meta_buf, len);
            break;
        case META_TYPE_RST_CONN:
            ret = handle_rst_conn_packet(ctx, meta_buf, len);
            break;
        case META_TYPE_WEIRD_SYN:
            ret = handle_unterminated_conn(ctx, meta_buf, len);
            break;
        default:
            fprintf(stderr, "Unknown meta packet type: %d\n", meta_type);
            return -1;
    }

    return ret;
}

void
handle_meta_data(struct meta_info* meta_info, 
                 uint8_t* meta_buf, 
                 ssl_crypto_info_t* crypto_info,
                 ssize_t len)
{        
    MEASURE("copy meta data",
    /* copy key meta data */
    // Set meta info vars for TCP migration
    meta_info->seq_num    = ntohl(*(uint32_t *)&meta_buf[4]);
    meta_info->ack_num    = ntohl(*(uint32_t *)&meta_buf[8]);
    meta_info->client_ip  = ntohl(*(uint32_t *)&meta_buf[26]);
    meta_info->client_port= ntohs(*(uint16_t *)&meta_buf[34]);

#if VERBOSE_META
        // Print extracted information
        fprintf(stderr, "\n[Meta Packet Info - TCP]\n");
        fprintf(stderr, "Eth type         : %02x%02x\n", meta_buf[12], meta_buf[13]);
        fprintf(stderr, "Seq Number       : 0x%08x (%u)\n", meta_info->seq_num, meta_info->seq_num);
        fprintf(stderr, "ACK Number       : 0x%08x (%u)\n", meta_info->ack_num, meta_info->ack_num);
        fprintf(stderr, "Client IP        : %u.%u.%u.%u\n", meta_buf[26], meta_buf[27], meta_buf[28], meta_buf[29]);
        fprintf(stderr, "Client Port      : %u (0x%04x)\n", meta_info->client_port, meta_info->client_port);

        hexdump(meta_buf, len);
#else /* VERBOSE_META */
        UNUSED(len);
#endif /* VERBOSE_META */

    meta_info->ssl_meta = (ssl_meta_t *)&meta_buf[38];

#if VERBOSE_KEY
    /* Print SSL meta info */
    fprintf(stderr, "\n[Meta Packet Info - SSL]\n");
    fprintf(stderr, "Session ID           : %u\n", meta_info->ssl_meta->session_id);
    fprintf(stderr, "SSL Version          : %u.%u\n", meta_info->ssl_meta->version.major, meta_info->ssl_meta->version.minor);
    fprintf(stderr, "Bulk Cipher Alg      : 0x%08x (6: AES)\n", meta_info->ssl_meta->bulk_cipher_algorithm);
    fprintf(stderr, "Cipher Type          : 0x%08x (3: AEAD)\n", meta_info->ssl_meta->cipher_type);
    fprintf(stderr, "MAC Algorithm        : 0x%08x (4: MAC_SHA384)\n", meta_info->ssl_meta->mac_algorithm);

    fprintf(stderr, "MAC Key Size         : %u\n", meta_info->ssl_meta->mac_key_size);
    print_hex_array("Client MAC Secret", meta_info->ssl_meta->client_write_MAC_secret, MAX_KEY_SIZE);
    print_hex_array("Server MAC Secret", meta_info->ssl_meta->server_write_MAC_secret, MAX_KEY_SIZE);

    fprintf(stderr, "Encryption Key Size  : %u\n", meta_info->ssl_meta->enc_key_size);
    print_hex_array("Client Write Key", meta_info->ssl_meta->client_write_key, MAX_KEY_SIZE);
    print_hex_array("Server Write Key", meta_info->ssl_meta->server_write_key, MAX_KEY_SIZE);

    fprintf(stderr, "Fixed IV Length      : %u\n", meta_info->ssl_meta->fixed_iv_length);
    print_hex_array("Client Write IV", meta_info->ssl_meta->client_write_IV, MAX_KEY_SIZE);
    print_hex_array("Server Write IV", meta_info->ssl_meta->server_write_IV, MAX_KEY_SIZE);
    fprintf(stderr, "====================\n");
#endif /* VERBOSE_KEY */

    /* Set TLS meta info */
    /* Set RX part */
    crypto_info->crypto_info_rx.info.version = 
        (meta_info->ssl_meta->version.major << 8) |
        meta_info->ssl_meta->version.minor;
    
    // TODO: Use dynamic cipher suite
    crypto_info->crypto_info_rx.info.cipher_type = TLS_CIPHER_AES_GCM_256; 
    
    /* rx iv - TLS 1.2: placeholder, TLS 1.3: 8B from client write IV + salt len (4) */
    memset(crypto_info->crypto_info_rx.iv, 0, TLS_CIPHER_AES_GCM_256_IV_SIZE);
    if (tls13)
        memcpy(crypto_info->crypto_info_rx.iv,
               meta_info->ssl_meta->client_write_IV + TLS_CIPHER_AES_GCM_256_SALT_SIZE, 
               TLS_CIPHER_AES_GCM_256_IV_SIZE);
    memcpy(crypto_info->crypto_info_rx.key, 
           meta_info->ssl_meta->client_write_key, 
           TLS_CIPHER_AES_GCM_256_KEY_SIZE);
    memcpy(crypto_info->crypto_info_rx.salt,
           meta_info->ssl_meta->client_write_IV, 
           TLS_CIPHER_AES_GCM_256_SALT_SIZE);

    memset(crypto_info->crypto_info_rx.rec_seq, 0, TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE);
    if (!tls13)
        crypto_info->crypto_info_rx.rec_seq[TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE - 1] = 0x01;

    crypto_info->crypto_info_tx.info.version = 
        (meta_info->ssl_meta->version.major << 8) |
        meta_info->ssl_meta->version.minor;
    // TODO: Use dynamic cipher suite

    /* Set TX part */
    crypto_info->crypto_info_tx.info.cipher_type = TLS_CIPHER_AES_GCM_256; 

    memset(crypto_info->crypto_info_tx.iv, 0, TLS_CIPHER_AES_GCM_256_IV_SIZE);
    if (tls13)
        memcpy(crypto_info->crypto_info_tx.iv,
            meta_info->ssl_meta->server_write_IV + TLS_CIPHER_AES_GCM_256_SALT_SIZE, 
            TLS_CIPHER_AES_GCM_256_IV_SIZE);
    memcpy(crypto_info->crypto_info_tx.key, 
           meta_info->ssl_meta->server_write_key, 
           TLS_CIPHER_AES_GCM_256_KEY_SIZE);
    memcpy(crypto_info->crypto_info_tx.salt, 
           meta_info->ssl_meta->server_write_IV, 
           TLS_CIPHER_AES_GCM_256_SALT_SIZE);

    memset(crypto_info->crypto_info_tx.rec_seq, 0, TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE);
    if (!tls13)
        crypto_info->crypto_info_tx.rec_seq[TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE - 1] = 0x01;

#if VERBOSE_KEY
    fprintf(stderr, "====== TLS RX Crypto Info ======\n");
    fprintf(stderr, "TLS Version         : %u.%u\n", crypto_info->crypto_info_rx.info.version >> 8, crypto_info->crypto_info_rx.info.version & 0xFF);
    fprintf(stderr, "Cipher Type         : 0x%08x (TLS_CIPHER_AES_GCM_256)\n", crypto_info->crypto_info_rx.info.cipher_type);
    fprintf(stderr, "IV                  : ");
    for (size_t i = 0; i < sizeof(crypto_info->crypto_info_rx.iv); ++i) {
        fprintf(stderr, "%02x", crypto_info->crypto_info_rx.iv[i]);
    }
    fprintf(stderr, "\nKey                 : ");
    for (size_t i = 0; i < sizeof(crypto_info->crypto_info_rx.key); ++i) {
        fprintf(stderr, "%02x", crypto_info->crypto_info_rx.key[i]);
    }
    fprintf(stderr, "\nSalt                : ");
    for (size_t i = 0; i < sizeof(crypto_info->crypto_info_rx.salt); ++i) {
        fprintf(stderr, "%02x", crypto_info->crypto_info_rx.salt[i]);
    }
    fprintf(stderr, "\nRec Seq             : ");
    for (size_t i = 0; i < sizeof(crypto_info->crypto_info_rx.rec_seq); ++i) {
        fprintf(stderr, "%02x", crypto_info->crypto_info_rx.rec_seq[i]);
    }
    fprintf(stderr, "\n");

    fprintf(stderr, "====== TLS TX Crypto Info ======\n");
    fprintf(stderr, "TLS Version         : %u.%u\n", crypto_info->crypto_info_tx.info.version >> 8, crypto_info->crypto_info_tx.info.version & 0xFF);
    fprintf(stderr, "Cipher Type         : 0x%08x (TLS_CIPHER_AES_GCM_256)\n", crypto_info->crypto_info_tx.info.cipher_type);
    fprintf(stderr, "IV                  : ");
    for (size_t i = 0; i < sizeof(crypto_info->crypto_info_tx.iv); ++i) {
        fprintf(stderr, "%02x", crypto_info->crypto_info_tx.iv[i]);
    }
    fprintf(stderr, "\nKey                 : ");
    for (size_t i = 0; i < sizeof(crypto_info->crypto_info_tx.key); ++i) {
        fprintf(stderr, "%02x", crypto_info->crypto_info_tx.key[i]);
    }
    fprintf(stderr, "\nSalt                : ");
    for (size_t i = 0; i < sizeof(crypto_info->crypto_info_tx.salt); ++i) {
        fprintf(stderr, "%02x", crypto_info->crypto_info_tx.salt[i]);
    }
    fprintf(stderr, "\nRec Seq             : ");
    for (size_t i = 0; i < sizeof(crypto_info->crypto_info_tx.rec_seq); ++i) {
        fprintf(stderr, "%02x", crypto_info->crypto_info_tx.rec_seq[i]);
    }
    fprintf(stderr, "\n");
#endif /* VERBOSE_KEY */
    );
}

void
handle_sccs_sf_records(conn_state_t* conn, uint8_t* meta_buf, ssize_t buf_len)
{
    conn->record_len = *(int *)(meta_buf + 16 + sizeof(ssl_meta_t));

#if VERBOSE_META
    fprintf(stderr, "rec len: %d\n", conn->record_len);
#endif /* VERBOSE_META */

    memcpy(conn->sccs_sf_buf, meta_buf + 16 + sizeof(ssl_meta_t), conn->record_len);
}

int
handle_key_packet(thread_ctx_t* ctx, 
                  uint8_t* meta_buf, 
                  ssize_t buf_len)
{
#if EVALUATION
    key_metas[ctx->core_id]++;
#endif /* EVALUATION */
    
    /* search the connection */
    uint32_t client_ip = ntohl(*(uint32_t *)&meta_buf[26]);
    uint16_t client_port = ntohs(*(uint16_t *)&meta_buf[34]);

    conn_state_t* existing_conn = ht_search(ctx->ht_conn, client_ip, client_port);

    if (existing_conn != NULL) {
        send_mig_fin_to_arm(ctx->meta_sock, existing_conn);
        // fprintf(stderr, "Send mig fin to arm for retransmitted key meta pkt"
        //                 "(client %u.%u.%u.%u:%u)\n",
        //         (client_ip >> 24) & 0xFF,
        //         (client_ip >> 16) & 0xFF,
        //         (client_ip >> 8) & 0xFF,
        //         (client_ip) & 0xFF,
        //         client_port);

        return -1; /* Already exists */
    }

    struct conn_state *new_conn = conn_state_alloc(ctx->core_id);

    clock_gettime(CLOCK_MONOTONIC, &new_conn->conn_start);

    if (!new_conn) { perror("conn alloc"); return -1; }

    handle_meta_data(&new_conn->meta_info, 
                     meta_buf, 
                     &new_conn->crypto_info,
                     buf_len);

    handle_sccs_sf_records(new_conn, meta_buf, buf_len);

    memcpy(new_conn->sccs_sf_buf, meta_buf, buf_len); /* ? */

    ht_insert(ctx->ht_conn, new_conn);

    PRINT_CUR_TIME("Set Mig TCP Start");
    new_conn->sock_fd = set_mig_sock(&new_conn->meta_info);
    PRINT_CUR_TIME("Set Mig TCP End");

    if (set_nonblock(new_conn->sock_fd) < 0) {
        perror("set_nonblock");
        close(new_conn->sock_fd);
        return -1;
    }

    PRINT_CUR_TIME("Mig TCP Start");
    if (mig_tcp_conn(new_conn, ctx->epfd) < 0) {
        fprintf(stderr, "Failed to migrate TCP connection\n");
        ht_remove(ctx->ht_conn, new_conn);
        close(new_conn->sock_fd);
        conn_state_free(new_conn, ctx->core_id);
        return -1;
    }
    PRINT_CUR_TIME("Mig TCP End");

    new_conn->sock_state = INIT;

    return 0;
}

int
handle_rst_conn_packet(thread_ctx_t* ctx, 
                       uint8_t* meta_buf, 
                       ssize_t buf_len)
{    
    /* search the connection */
    uint32_t client_ip = ntohl(*(uint32_t *)&meta_buf[0]);
    uint16_t client_port = ntohs(*(uint16_t *)&meta_buf[14]);

    // fprintf(stderr, "Handle RST connection packet (client: %u.%u.%u.%u:%u)\n",
    //         (client_ip >> 24) & 0xFF,
    //         (client_ip >> 16) & 0xFF,
    //         (client_ip >> 8) & 0xFF,
    //         (client_ip) & 0xFF,
    //         client_port);

    conn_state_t* existing_conn = ht_search(ctx->ht_conn, client_ip, client_port);

    if (existing_conn != NULL) {
        ht_remove(ctx->ht_conn, existing_conn);
        close(existing_conn->sock_fd);
        conn_state_free(existing_conn, ctx->core_id);
    } else {
        fprintf(stderr, "RST packet for non-existing connection"
                        "(client %u.%u.%u.%u:%u)\n",
                (client_ip >> 24) & 0xFF,
                (client_ip >> 16) & 0xFF,
                (client_ip >> 8) & 0xFF,
                (client_ip) & 0xFF,
                client_port);
        return -1;
    }

    struct conn_state *new_conn = NULL;
    new_conn = conn_state_alloc(ctx->core_id);

    clock_gettime(CLOCK_MONOTONIC, &new_conn->conn_start);

    if (!new_conn) { perror("conn alloc"); return -1; }

    handle_meta_data(&new_conn->meta_info, 
                     meta_buf, 
                     &new_conn->crypto_info,
                     buf_len);

    handle_sccs_sf_records(new_conn, meta_buf, buf_len);

    memcpy(new_conn->sccs_sf_buf, meta_buf, buf_len); /* ? */

    ht_insert(ctx->ht_conn, new_conn);

    PRINT_CUR_TIME("Set Mig TCP Start");
    new_conn->sock_fd = set_mig_sock(&new_conn->meta_info);
    PRINT_CUR_TIME("Set Mig TCP End");

    if (set_nonblock(new_conn->sock_fd) < 0) {
        perror("set_nonblock");
        close(new_conn->sock_fd);
        return -1;
    }

    PRINT_CUR_TIME("Mig TCP Start");
    if (mig_tcp_conn(new_conn, ctx->epfd) < 0) {
        fprintf(stderr, "Failed to migrate TCP connection\n");
        ht_remove(ctx->ht_conn, new_conn);
        close(new_conn->sock_fd);
        conn_state_free(new_conn, ctx->core_id);
        return -1;
    }
    PRINT_CUR_TIME("Mig TCP End");

    new_conn->sock_state = INIT;

    return 0;
}

int
handle_unterminated_conn(thread_ctx_t* ctx, 
                         uint8_t* meta_buf, 
                         ssize_t buf_len)
{
    struct iphdr* iph = (struct iphdr *)(meta_buf + sizeof(struct ethhdr));
    struct tcphdr* tcph = (struct tcphdr *)(meta_buf + sizeof(struct ethhdr) + iph->ihl * 4);

    uint32_t client_ip = iph->saddr;
    uint16_t client_port = tcph->source;

    conn_state_t conn;

    conn.meta_info.client_ip = ntohl(client_ip);
    conn.meta_info.client_port = ntohs(client_port);
    conn.meta_info.seq_num = ntohl(tcph->seq);
    conn.meta_info.ack_num = ntohl(tcph->ack_seq);

    send_close_to_arm(ctx->meta_sock, &conn);

#if DEBUG
    nic_unterminated_conn++;
#endif /* DEBUG */

    return 0;
}
/*----------------------------------------------------------------------------*/
/* Send */
int 
send_mig_fin_to_arm(int meta_sock, conn_state_t* conn) 
{
    uint8_t ack_buf[SND_META_PKT_SIZE] = {0};

    uint32_t src_ip = htonl(conn->meta_info.client_ip);
    uint16_t src_port = htons(conn->meta_info.client_port);
    uint32_t dst_ip = htonl(SERVER_IP);
    uint16_t dst_port = htons(SSL_PORT);
    uint32_t seq_num = htonl(conn->meta_info.seq_num);
    uint32_t ack_num = htonl(conn->meta_info.ack_num);
    uint32_t ack_num_for_rst = conn->meta_info.ack_num + conn->recv_bytes;

    /* Eth hdr */
    const uint8_t mac_zero[6] = {0};

    memcpy(&ack_buf[0], mac_zero, 6);   // dst MAC
    memcpy(&ack_buf[6], mac_zero, 6);   // src MAC

    ack_buf[12] = 0x08;                 // EtherType = 0x0800 (TODO: 0x0801)
    ack_buf[13] = 0x00;                   

    /* IP hdr */
    ack_buf[14] = 0x45;                 // Version 4, IHL 5
    ack_buf[15] = 0xfd;                 // Special ToS (Mig completion)
    ack_buf[16] = 0x00;                 // Total Length (will be set later)
    ack_buf[17] = 0x28;                 // Total Length = 40 bytes
    ack_buf[22] = 64;                   // TTL
    ack_buf[23] = 6;                    // Protocol = TCP

    memcpy(&ack_buf[26], &src_ip, 4);   // src IP (in network byte order)
    memcpy(&ack_buf[30], &dst_ip, 4);   // dst IP

    /* TCP hdr */
    memcpy(&ack_buf[34], &src_port, 2);
    memcpy(&ack_buf[36], &dst_port, 2);

    memcpy(&ack_buf[38], &seq_num, 4); // Seq number
    memcpy(&ack_buf[42], &ack_num, 4); // ACK number

    memcpy(&ack_buf[48], &ack_num_for_rst, 4); // ACK number + recv_bytes

    /* Send */
    ssize_t sent;
    MEASURE("sendto",
         sent = sendto(meta_sock, ack_buf, SND_META_PKT_SIZE, 0, NULL, 0);
    );

    if (sent < 0) {
        perror("send");
        return -1;
    }

    PRINT_CUR_TIME("Host Meta Packet Sent");

    return 0;
}

int 
send_close_to_arm(int meta_sock, conn_state_t* conn) 
{
    uint8_t ack_buf[SND_META_PKT_SIZE] = {0};

    uint32_t src_ip = htonl(conn->meta_info.client_ip);
    uint16_t src_port = htons(conn->meta_info.client_port);
    uint32_t dst_ip = htonl(SERVER_IP);
    uint16_t dst_port = htons(SSL_PORT);
    uint32_t seq_num = htonl(conn->meta_info.seq_num);
    uint32_t ack_num = htonl(conn->meta_info.ack_num);

    /* Eth hdr */
    const uint8_t mac_zero[6] = {0};
    memcpy(&ack_buf[0], mac_zero, 6);   // dst MAC
    memcpy(&ack_buf[6], mac_zero, 6);   // src MAC
    ack_buf[12] = 0x08;                 // EtherType = 0x0800 (TODO: 0x0801)
    ack_buf[13] = 0x00;

    /* IP hdr */
    ack_buf[14] = 0x45;                 // Version 4, IHL 5
    ack_buf[15] = 0xfc;                 // Special ToS (Close)
    ack_buf[16] = 0x00;                 // Total Length (will be set later)
    ack_buf[17] = 0x28;                 // Total Length = 40 bytes
    ack_buf[22] = 64;                   // TTL
    ack_buf[23] = 6;                    // Protocol = TCP

    memcpy(&ack_buf[26], &src_ip, 4);   // src IP (in network byte order)
    memcpy(&ack_buf[30], &dst_ip, 4);   // dst IP

    /* TCP hdr */
    memcpy(&ack_buf[34], &src_port, 2);
    memcpy(&ack_buf[36], &dst_port, 2);

    memcpy(&ack_buf[38], &seq_num, 4); // Seq number
    memcpy(&ack_buf[42], &ack_num, 4); // ACK number

    /* Send */
    ssize_t sent;
    MEASURE("sendto",
        sent = sendto(meta_sock, ack_buf, SND_META_PKT_SIZE, 0, NULL, 0);
    );

    if (sent < 0) {
        perror("send");
        return -1;
    }
    
    PRINT_CUR_TIME("Host Close Packet Sent");

#if DEBUG
    sent_close_meta++;
#endif /* DEBUG */
    
    return 0;
}
/*----------------------------------------------------------------------------*/
