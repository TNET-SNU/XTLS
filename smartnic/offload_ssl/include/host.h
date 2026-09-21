#ifndef __HOST_H__
#define __HOST_H__

#include "ssloff.h"

/* ToDo: dynamically resize this; MAX_KEY_SIZE is too big now */
typedef
struct conn_meta /* 787 */{
    uint16_t session_id; // 2B

    /* SSL related parameter */
    protocol_version_t  version; // 2B

    bulk_cipher_algorithm_t bulk_cipher_algorithm; // 4B
    cipher_type_t cipher_type; // 4B
    mac_algorithm_t mac_algorithm; // 4B

    uint8_t mac_key_size; // 1B
    uint8_t client_write_MAC_secret[MAX_KEY_SIZE]; // 128B
    uint8_t server_write_MAC_secret[MAX_KEY_SIZE]; // 128B

    uint8_t enc_key_size; // 1B
    uint8_t client_write_key[MAX_KEY_SIZE]; // 128B
    uint8_t server_write_key[MAX_KEY_SIZE]; // 128B

    uint8_t fixed_iv_length; // 1B
    uint8_t client_write_IV[MAX_KEY_SIZE]; // 128B
    uint8_t server_write_IV[MAX_KEY_SIZE]; // 128B
} conn_meta_t;

#if LINUX_TCP_SERVER
#pragma pack(push, 1)
typedef
struct meta_hdr /* 38 + sizeof(conn_meta_t) */ {
    int8_t eth_pad[4];
    uint32_t server_seq_num;
    uint32_t server_ack_num;
    uint16_t custom_eth_type;
    int8_t ip_pad[12];
    uint32_t client_ip; /* source ip */
    uint32_t server_ip; /* destination ip */
    uint16_t client_port; /* source port */
    uint16_t server_port; /* destination port */
    conn_meta_t conn_meta;
} meta_hdr_t;
#pragma pack(pop)
#else /* !LINUX_TCP_SERVER */
typedef
struct meta_hdr {
    uint32_t key_size;
    uint32_t iv_size;
    uint32_t reserved;
    uint16_t h_proto;
} meta_hdr_t;
#endif /* !LINUX_TCP_SERVER */

void
build_connection_meta(struct ssl_session *sess, conn_meta_t *meta);

int
change_connection_rule(struct ssl_session* sess);

#endif /* __HOST_H__ */
