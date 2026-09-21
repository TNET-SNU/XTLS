#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdalign.h>
#include <stdint.h>
#include "ring.h"

/**
 * Create ring
 * @param count: power of 2 for bit operation
 */
sj_ring_t* 
sj_ring_create(const char *name, uint32_t count)
{
    if (count == 0 || (count & (count - 1)) != 0) {
        fprintf(stderr, "Ring size must be a power of 2. Given: %u\n", count);
        exit(EXIT_FAILURE);
    }

    size_t sz = sizeof(sj_ring_t) + (count * sizeof(void *));
    sj_ring_t *r = (sj_ring_t *)aligned_alloc(64, sz);
    if (!r) {
        fprintf(stderr, "Failed to allocate memory for ring\n");
        exit(EXIT_FAILURE);
    }

    memset(r, 0, sz);
    r->size = count;
    r->mask = count - 1;
    snprintf(r->name, sizeof(r->name), "%s", name);
    
    atomic_init(&r->head, 0);
    atomic_init(&r->tail, 0);

    return r;
}

int 
sj_ring_enqueue(sj_ring_t *r, void *obj)
{
    uint32_t t = atomic_load_explicit(&r->tail, memory_order_relaxed);
    uint32_t h = atomic_load_explicit(&r->head, memory_order_acquire);

    if (((t + 1) & r->mask) == h) {
        return SJ_ERROR;
    }

    r->ring[t] = obj;

    atomic_store_explicit(&r->tail, (t + 1) & r->mask, memory_order_release);
    
    return SJ_SUCCESS;
}

int 
sj_ring_dequeue(sj_ring_t *r, void **obj_p)
{
    uint32_t h = atomic_load_explicit(&r->head, memory_order_relaxed);
    uint32_t t = atomic_load_explicit(&r->tail, memory_order_acquire);

    if (h == t) {
        return SJ_ERROR;
    }

    *obj_p = r->ring[h];

    atomic_store_explicit(&r->head, (h + 1) & r->mask, memory_order_release);

    return SJ_SUCCESS;
}