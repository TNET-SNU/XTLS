#ifndef __RING_H__
#define __RING_H__

#include <stdlib.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdalign.h>
#include <stdint.h>

#define SJ_SUCCESS 0
#define SJ_ERROR  -1

typedef struct sj_ring {
    uint32_t size;
    uint32_t mask;
    char name[32];

    alignas(64) _Atomic uint32_t tail; 
    alignas(64) _Atomic uint32_t head;

    alignas(64) void *ring[] ;
} sj_ring_t;

/**
 * Create ring
 * @param count: power of 2 for bit operation
 */
sj_ring_t* 
sj_ring_create(const char *name, uint32_t count);

int 
sj_ring_enqueue(sj_ring_t *r, void *obj);

int 
sj_ring_dequeue(sj_ring_t *r, void **obj_p);

#endif /* __RING_H__ */
