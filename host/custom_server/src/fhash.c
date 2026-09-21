#include <stdio.h>

#include "fhash.h"
/*---------------------------------------------------------------------------*/
static inline uint32_t
calculate_hash(conn_state_t* conn)
{
    uint32_t hash, i;
    uint8_t key[6];

    memcpy(key, &conn->meta_info.client_ip, 4);
    memcpy(key + 4, &conn->meta_info.client_port, 2);

    for (hash = 0, i = 0; i < 6; i++) {
        hash += key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
        hash += (hash << 3);
        hash ^= (hash >> 11);
        hash += (hash << 15);

    return hash & (NUM_BINS - 1);
}

hashtable_t* 
create_ht(int bins)
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

void
destroy_ht(hashtable_t* ht)
{
    free(ht->ht_table);
    free(ht);
}

int
ht_insert(hashtable_t* ht, conn_state_t* conn)
{
    /* create an entry*/
    assert(ht);

    uint32_t idx = calculate_hash(conn);
    assert(idx >= 0 && idx < NUM_BINS);

    TAILQ_INSERT_TAIL(&ht->ht_table[idx], conn, active_connection_link);

    ht->count++;

    return 0;
}

void*
ht_remove(hashtable_t* ht, conn_state_t* conn)
{
    hash_bucket_head* head;
    uint32_t idx = calculate_hash(conn);
        
    head = &ht->ht_table[idx];
    TAILQ_REMOVE(head, conn, active_connection_link);

    ht->count--;

    return conn;
}

void*                     
ht_search(hashtable_t* ht, uint32_t client_ip, uint16_t client_port)
{
    conn_state_t* walk;
    hash_bucket_head* head;

    conn_state_t target;
    memset(&target, 0, sizeof(conn_state_t));
    target.meta_info.client_ip = client_ip;
    target.meta_info.client_port = client_port;

    uint32_t idx = calculate_hash(&target);
    head = &ht->ht_table[idx];
    TAILQ_FOREACH(walk, head, active_connection_link) {
        if ((walk->meta_info.client_ip == client_ip) &&
            (walk->meta_info.client_port == client_port))
            return walk;
    }
    
    return NULL;
}
