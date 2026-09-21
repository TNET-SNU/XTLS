#include <stdio.h>

#include "fhash.h"

/*---------------------------------------------------------------------------*/
static inline unsigned int
calculate_hash(tcp_connection_t* conn)
{
    unsigned int hash, i;
    uint8_t* key = (uint8_t *)&conn->client_ip;

    for (hash = 0, i = 0; i < 12; i++) {
        hash += key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
        hash += (hash << 3);
        hash ^= (hash >> 11);
        hash += (hash << 15);

    return hash & (NUM_BINS - 1);
}
/*----------------------------------------------------------------------------*/
hashtable_t* 
create_ht(int bins) // no of bins
{
    int i;
    hashtable_t* ht = calloc(1, sizeof(hashtable_t));
    if (unlikely(!ht)) {
        fprintf(stderr, "calloc: create_ht");
        return 0;
    }

    ht->bins = bins;

    /* creating bins */
    ht->ht_table = calloc(bins, sizeof(hash_bucket_head));
    if (unlikely(!ht->ht_table)) {
        fprintf(stderr, "calloc: create_ht bins!\n");
        free(ht);
        return 0;
    }
    /* init the tables */
    for (i = 0; i < bins; i++)
	    TAILQ_INIT(&ht->ht_table[i]);

    return ht;
}
/*----------------------------------------------------------------------------*/
void
destroy_ht(hashtable_t* ht)
{
    free(ht->ht_table);
    free(ht);
}
/*----------------------------------------------------------------------------*/
int
ht_insert(hashtable_t* ht, tcp_connection_t* item, thread_context_t* ctx)
{
    /* create an entry*/
    assert(ht);

    unsigned int idx = calculate_hash(item);
    assert(idx >= 0 && idx < NUM_BINS);

    TAILQ_INSERT_TAIL(&ht->ht_table[idx], item, active_session_link);

    ht->count++;

    return 0;
}
/*----------------------------------------------------------------------------*/
void*
ht_remove(hashtable_t* ht, tcp_connection_t* item)
{
    hash_bucket_head* head;
    unsigned int idx = calculate_hash(item);
        
    head = &ht->ht_table[idx];
    TAILQ_REMOVE(head, item, active_session_link);

    ht->count--;

    return (item);
}
/*----------------------------------------------------------------------------*/ 
void*                     
ht_search(hashtable_t* ht, uint32_t client_ip, uint16_t client_port,
	  uint32_t server_ip, uint16_t server_port)
{
    tcp_connection_t* walk;
    hash_bucket_head* head;
    int count = 0;

    tcp_connection_t target;
    memset(&target, 0, sizeof(tcp_connection_t));
    target.client_ip = client_ip;
    target.client_port = client_port;
    target.server_ip = server_ip;
    target.server_port = server_port;

    unsigned int idx = calculate_hash(&target);
    head = &ht->ht_table[idx];
    TAILQ_FOREACH(walk, head, active_session_link) {
        assert(walk->state != TCP_SESSION_IDLE);
        count++;

        if ((walk->client_ip == client_ip) &&
            (walk->client_port == client_port) &&
            (walk->server_ip == server_ip) &&
            (walk->server_port == server_port))
            return walk;
    }
    
    return NULL;
}
/*----------------------------------------------------------------------------*/