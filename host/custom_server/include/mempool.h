#pragma once

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "option.h"
#include "common.h"

void 
conn_pool_init(int core_id);

conn_state_t* 
conn_state_alloc(int core_id);

void 
conn_state_free(conn_state_t* ptr, int core_id);
