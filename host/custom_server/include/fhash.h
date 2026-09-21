#pragma once

#include <sys/queue.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "common.h"
/*---------------------------------------------------------------------------*/
#define NUM_BINS 1024

typedef
struct hash_bucket_head {
    conn_state_t *tqh_first;
    conn_state_t **tqh_last;
} hash_bucket_head;

typedef
struct hashtable {
  uint32_t bins;
  hash_bucket_head *ht_table;
  size_t count;
} hashtable_t;
/*---------------------------------------------------------------------------*/
hashtable_t*
create_ht(int bins);

void 
destroy_ht(hashtable_t* ht);

int 
ht_insert(hashtable_t* ht, conn_state_t* item);

void*
ht_remove(hashtable_t* ht, conn_state_t* item);

void*
ht_search(hashtable_t* ht, uint32_t client_ip, uint16_t client_port);
