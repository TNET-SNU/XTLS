#include <sys/queue.h>
#include "ssloff.h"

#define NUM_BINS 1024

typedef
struct hash_bucket_head {
    tcp_connection_t *tqh_first;
    tcp_connection_t **tqh_last;
} hash_bucket_head;

typedef
struct hashtable {
  uint32_t bins;
  hash_bucket_head *ht_table;
  size_t count;
} hashtable_t;

hashtable_t *create_ht(int bins);

void destroy_ht(hashtable_t *ht);

int ht_insert(hashtable_t *ht, tcp_connection_t *, thread_context_t* ctx);
void *ht_remove(hashtable_t *ht, tcp_connection_t *);
void *ht_search(hashtable_t *ht, uint32_t client_ip, uint16_t client_port,
		uint32_t server_ip, uint16_t server_port);
