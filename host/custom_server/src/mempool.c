#include "mempool.h"

struct conn_state* conn_pool[MAX_THREAD_NUM][MAX_CONN];
int pool_top[MAX_THREAD_NUM];
/*----------------------------------------------------------------------------*/
void
conn_pool_init(int core_id) 
{
    pool_top[core_id] = -1;
    
    for (int i = 0; i < MAX_CONN; i++) {
        conn_pool[core_id][i] = malloc(sizeof(struct conn_state));

        if (!conn_pool[core_id][i]) {
            fprintf(stderr, "mempool_init: malloc failed at %d\n", i);
            exit(1);
        }

        memset(conn_pool[core_id][i], 0, sizeof(struct conn_state));

        pool_top[core_id]++;
        conn_pool[core_id][pool_top[core_id]] = conn_pool[core_id][i];
    }
}

struct conn_state*
conn_state_alloc(int core_id) 
{
    if (pool_top[core_id] < 0)
        return NULL;

    struct conn_state *c = conn_pool[core_id][pool_top[core_id]];
    pool_top[core_id]--;

    // memset(&c->meta_info, 0, sizeof(c->meta_info));
    // memset(&c->crypto_info, 0, sizeof(c->crypto_info));
    memset(c, 0, sizeof(*c));
    c->file_idx  = -1;
    c->resp_fd   = -1;
    
    return c;
}

void
conn_state_free(struct conn_state* conn, int core_id) 
{
    if (!conn) return;

    if (unlikely(conn->resp_fd >= 0)) {
        close(conn->resp_fd);
        conn->resp_fd = -1;
    }

    pool_top[core_id]++;
    conn_pool[core_id][pool_top[core_id]] = conn;
}
