#include "ssloff.h"

/* with dpdk 24.11.3 */
/*---------------------------------------------------------------------------*/
inline void
free_pkts(struct rte_mbuf **mtable, unsigned len)
{
    unsigned i;

    for (i = 0; i < len; i++) {
        rte_pktmbuf_free(mtable[i]);
        RTE_MBUF_PREFETCH_TO_FREE(mtable[i+1]);
    }
}
/*---------------------------------------------------------------------------*/
inline int32_t
recv_pkts(uint16_t core_id, uint16_t port) 
{
    struct dpdk_private_context* dpc;
    int ret;

    dpc = ctx_array[core_id]->dpc;

    if (dpc->rmbufs[port].len != 0) {
        free_pkts(dpc->rmbufs[port].m_table, dpc->rmbufs[port].len);
        dpc->rmbufs[port].len = 0;
    }

    ret = rte_eth_rx_burst((uint8_t)port, core_id - 1,
                           dpc->pkts_burst, MAX_PKT_BURST);

    dpc->rx_idle = (likely(ret != 0)) ? 0 : dpc->rx_idle + 1;
    dpc->rmbufs[port].len = ret;

#if VERBOSE_STAT
    ssl_stat_t* stat = &ctx_array[core_id]->cur_stat;

    stat->rx_pkts[port] += ret;
#endif /* VERBOSE_STAT */

    return ret;
}
/*---------------------------------------------------------------------------*/
inline uint8_t* 
get_rptr(uint16_t core_id, uint16_t port, int index, uint16_t* len) 
{
    struct dpdk_private_context* dpc;
    struct rte_mbuf* m;
    uint8_t* pktbuf;

    dpc = ctx_array[core_id]->dpc;

    m = dpc->pkts_burst[index];

    *len = m->pkt_len;
    pktbuf = rte_pktmbuf_mtod(m, uint8_t* );

    dpc->rmbufs[port].m_table[index] = m;

    if ((m->ol_flags &  \
        (RTE_MBUF_F_RX_L4_CKSUM_BAD | RTE_MBUF_F_RX_IP_CKSUM_BAD)) != 0) {
        fprintf(stderr,
                "[CPU %d][Port %d] mbuf(index: %d) with invalid checksum: "
                "%p(%lu);\n",
                core_id, port, index, m, m->ol_flags);
        pktbuf = NULL;
    }

#if VERBOSE_STAT
    ssl_stat_t* stat = &ctx_array[core_id]->cur_stat;

    stat->rx_bytes[port] += *len;
#endif /* VERBOSE_STAT */

    return pktbuf;
}
/*---------------------------------------------------------------------------*/
#if OFFLOAD_AES_GCM
inline struct rte_mbuf* 
get_wmbuf(uint16_t core_id, uint16_t port, uint16_t pktsize) 
{
    struct dpdk_private_context* dpc;
    struct rte_mbuf* m;
    int len_mbuf;
    int send_cnt;
    ssl_stat_t* stat = &ctx_array[core_id]->stat;

    dpc = ctx_array[core_id]->dpc;

    if (unlikely(dpc->wmbufs[port].len == MAX_PKT_BURST)) {
        while(1) {
            send_cnt = send_pkts(core_id, port);
            if (likely(send_cnt))
                break;
        }
    }

    /* sanity check */
    len_mbuf = dpc->wmbufs[port].len;
    m = dpc->wmbufs[port].m_table[len_mbuf];

    m->pkt_len = m->data_len = pktsize;
    m->nb_segs = 1;
    m->next = NULL;

#if OFFLOAD_AES_GCM
	m->tls_ctx = NULL;
#endif /* OFFLOAD_AES_GCM */

	m->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM |
		PKT_TX_TCP_CKSUM;

    dpc->wmbufs[port].len = len_mbuf + 1;

    stat->tx_bytes[port] += pktsize;

    return m;
}
#endif /* OFFLOAD_AES_GCM */
/*---------------------------------------------------------------------------*/
inline uint8_t* 
get_wptr(uint16_t core_id, uint16_t port, 
         uint16_t pktsize, 
         int hw_csum, int l4_len) 
{
    struct dpdk_private_context* dpc;
    struct rte_mbuf* m;
    uint8_t* ptr;
    int len_mbuf;
    int send_cnt;

    dpc = ctx_array[core_id]->dpc;

    if (unlikely(dpc->wmbufs[port].len == MAX_PKT_BURST)) {
        while(1) {
            send_cnt = send_pkts(core_id, port);
            if (likely(send_cnt))
                break;
        }
    }

    /* sanity check */
    len_mbuf = dpc->wmbufs[port].len;
    m = dpc->wmbufs[port].m_table[len_mbuf];

    ptr = (void *)rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    m->pkt_len = m->data_len = pktsize;
    m->nb_segs = 1;
    m->next = NULL;

#if OFFLOAD_AES_GCM
	m->tls_ctx = NULL;
#endif /* OFFLOAD_AES_GCM */

    if (hw_csum)
        m->ol_flags = RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM |
                    RTE_MBUF_F_TX_TCP_CKSUM;
    else
        m->ol_flags = RTE_MBUF_F_TX_IPV4;
    
    m->l2_len = sizeof(struct rte_ether_hdr);
    m->l3_len = sizeof(struct rte_ipv4_hdr);
    m->l4_len = l4_len;

    dpc->wmbufs[port].len = len_mbuf + 1;

#if VERBOSE_STAT
    ssl_stat_t* stat = &ctx_array[core_id]->cur_stat;

    stat->tx_bytes[port] += pktsize;
#endif /* VERBOSE_STAT */

    return (uint8_t *)ptr;
}
/*---------------------------------------------------------------------------*/
inline int
send_pkts(uint16_t core_id, uint16_t port) 
{
    struct dpdk_private_context* dpc;
    int ret, i;

    dpc = ctx_array[core_id]->dpc;
    ret = 0;

    if (dpc->wmbufs[port].len > 0) {
        struct rte_mbuf** pkts;
        int cnt = dpc->wmbufs[port].len;
        pkts = dpc->wmbufs[port].m_table;

        ret = rte_eth_tx_burst(port, core_id - 1, pkts, cnt);
        if (ret < cnt) {
            rte_pktmbuf_free_bulk(&pkts[ret], cnt - ret);
            printf("[CPU %d] [Port %d] tx burst failed, "
                   "ret: %d, cnt: %d\n", core_id, port, ret, cnt);
        }

        for (i = 0; i < dpc->wmbufs[port].len; i++) {
            dpc->wmbufs[port].m_table[i] =
                rte_pktmbuf_alloc(pktmbuf_pool[core_id]);
            if (unlikely(dpc->wmbufs[port].m_table[i] == NULL)) {
                rte_exit(EXIT_FAILURE,
                         "[CPU %d] Failed to allocate wmbuf[%d] on port %d\n",
                         core_id, i, port);
                fflush(stdout);
            }
        }
        dpc->wmbufs[port].len = 0;
    }

#if VERBOSE_STAT
    ssl_stat_t* stat = &ctx_array[core_id]->cur_stat;

    stat->tx_pkts[port] += ret;
#endif /* VERBOSE_STAT */
    return ret;
}
/*---------------------------------------------------------------------------*/
#if USE_RTE_HWS
/////////////////////////////// rte_flow (sync) ///////////////////////////////
inline int
ins_sync_hws_recv(uint16_t port, tcp_connection_t* conn) 
{
    struct rte_flow_attr attr = { 
        .transfer = 1 
    };
    struct rte_flow_item pattern[PATTERN_NUM_SYNC];
    struct rte_flow_action action[ACTION_NUM_SYNC];
    struct rte_flow* flow = NULL;
    struct rte_flow_error error;

    memset(&error, 0, sizeof(error));
    memset(pattern, 0, sizeof(pattern));
    memset(action, 0, sizeof(action));

    /* pattern */
    struct rte_flow_item_eth eth_spec, eth_mask;
    memset(&eth_spec, 0, sizeof(eth_spec));
    memset(&eth_mask, 0, sizeof(eth_mask));
    eth_spec.type = htons(0x0800);
    eth_mask.type = 0xFFFF;
    
    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[0].spec = &eth_spec;
    pattern[0].mask = &eth_mask;

    struct rte_flow_item_ipv4 ipv4_spec, ipv4_mask;
    memset(&ipv4_spec, 0, sizeof(ipv4_spec));
    memset(&ipv4_mask, 0, sizeof(ipv4_mask));
    ipv4_spec.hdr.src_addr = conn->client_ip;
    ipv4_spec.hdr.dst_addr = conn->server_ip;
    ipv4_mask.hdr.src_addr = 0xFFFFFFFF;
    ipv4_mask.hdr.dst_addr = 0xFFFFFFFF;
    
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[1].spec = &ipv4_spec;
    pattern[1].mask = &ipv4_mask;

    struct rte_flow_item_tcp tcp_spec, tcp_mask;
    memset(&tcp_spec, 0, sizeof(tcp_spec));
    memset(&tcp_mask, 0, sizeof(tcp_mask));
    tcp_spec.hdr.src_port = conn->client_port;
    tcp_spec.hdr.dst_port = conn->server_port;
    tcp_mask.hdr.src_port = 0xFFFF;
    tcp_mask.hdr.dst_port = 0xFFFF;

    pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
    pattern[2].spec = &tcp_spec;
    pattern[2].mask = &tcp_mask;

    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    
    /* action */
    struct rte_flow_action_port_id fwd = {
        .id = port + 1 // host representor port ID
    };
    action[0].type = RTE_FLOW_ACTION_TYPE_PORT_ID;
    action[0].conf = &fwd;

    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    /* validate rule */
    if (unlikely(rte_flow_validate(port, &attr, pattern, action, &error) < 0)) {
        printf("Flow validation failed.\n");
        if (error.message)
            printf("Error message: %s\n", error.message);
        else
            printf("Error cause: type = %d, cause = %p\n",
                   error.type, error.cause);
        return -1;
    }
    
    /* create flow */
    flow = rte_flow_create(port, &attr, pattern, action, &error);
    if (unlikely(!flow)) {
        printf("Flow creation failed.\n");
        if (error.message)
            printf("Error message: %s\n", error.message);
        else
            printf("Error cause: type = %d, cause = %p\n",
                   error.type, error.cause);
        return -1;
    } 

    return 0;
}

struct rte_flow_item* 
fill_pattern_hws_send() 
{
    struct rte_flow_item* pattern = 
        calloc(PATTERN_NUM_HWS, sizeof(struct rte_flow_item));
    
    /* port pattern */
    struct rte_flow_item_ethdev* port_spec = 
        calloc(1, sizeof(struct rte_flow_item_ethdev));
    struct rte_flow_item_ethdev* port_mask = 
        calloc(1, sizeof(struct rte_flow_item_ethdev));

    port_spec->port_id = 1; // host representor port ID
    port_mask->port_id = 0xFFFF; // mask for port ID

    pattern[0].type = RTE_FLOW_ITEM_TYPE_REPRESENTED_PORT;
    pattern[0].spec = port_spec;
    pattern[0].mask = port_mask;

    /* eth pattern */
    struct rte_flow_item_eth* eth_spec = 
        calloc(1, sizeof(struct rte_flow_item_eth));
    struct rte_flow_item_eth* eth_mask = 
        calloc(1, sizeof(struct rte_flow_item_eth));

    eth_spec->type = htons(0x0800);
    eth_mask->type = 0xFFFF;
    
    pattern[1].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].spec = eth_spec;
    pattern[1].mask = eth_mask;

    /* ipv4 pattern */
    struct rte_flow_item_ipv4* ipv4_spec = 
        calloc(1, sizeof(struct rte_flow_item_ipv4));
    struct rte_flow_item_ipv4* ipv4_mask = 
        calloc(1, sizeof(struct rte_flow_item_ipv4));

    ipv4_spec->hdr.type_of_service = 0x00;
    ipv4_mask->hdr.type_of_service = 0xFF;
    
    pattern[2].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[2].spec = ipv4_spec;
    pattern[2].mask = ipv4_mask;

    /* pattern end */
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;

    return pattern;
}

struct rte_flow_action* 
fill_action_hws_send() 
{
    struct rte_flow_action_ethdev* fwd = 
        calloc(1, sizeof(struct rte_flow_action_ethdev));
    fwd->port_id = 0; // port ID of p0

    struct rte_flow_action* action = 
        calloc(ACTION_NUM_HWS, sizeof(struct rte_flow_action));

    action[0].type = RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT;
    action[0].conf = fwd; // conn->fwd;

    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    return action;
}

inline int
ins_sync_hws_send()
{
    int ret;
    struct rte_flow_attr attr = { 
        .transfer = 1 
    };
    struct rte_flow_item pattern[PATTERN_NUM_SYNC];
    struct rte_flow_action action[ACTION_NUM_SYNC];
    struct rte_flow* flow = NULL;
    struct rte_flow_error error;

    struct rte_flow_item* pattern_hws_send = 
        calloc(PATTERN_NUM_HWS, sizeof(struct rte_flow_item));
    struct rte_flow_action* action_hws_send = 
        calloc(ACTION_NUM_HWS, sizeof(struct rte_flow_action));

    memset(&error, 0, sizeof(error));

    /* pattern */
    pattern_hws_send = fill_pattern_hws_send();
    
    /* action */
    action_hws_send = fill_action_hws_send();

    /* create flow */
    struct rte_flow* flow_hws_send = rte_flow_create(
        0,
		&attr,
		pattern_hws_send,
		action_hws_send,
		&error);
    if (unlikely(!flow_hws_send)) {
        fprintf(stderr, "HWS rule (send) creation failed.\n");
        fprintf(stderr, "Core ID: %d\n", 0);
        if (error.message)
            fprintf(stderr, "Error type: %d, Error message: %s\n", 
                    error.type, error.message);
        else
            fprintf(stderr, "Error cause: type = %d, cause = %p\n",
                    error.type, error.cause);
        return -1;
    } 

    return 0;
}
/*---------------------------------------------------------------------------*/
//////////////////////////////// rte_flow_async ///////////////////////////////
/*----------------------------- init stage (recv) ---------------------------*/
static inline int
flow_configure(uint16_t port_id) 
{
    struct rte_flow_error error;

    /* flow configure */
    int num_op_queue = 2 * rte_lcore_count(); /* for ins & del */
    struct rte_flow_port_attr port_attr = { 
        .nb_counters = MAX_SESSIONS /* # of counters */ 
    };
    struct rte_flow_queue_attr queue_attr = { 
        // .size = MAX_SESSIONS / num_op_queue
        .size = MAX_RESULTS /* !caveat! hard coded up to 1K */
    };
    const struct rte_flow_queue_attr** queue_attr_set \
        = (const struct rte_flow_queue_attr** )calloc(num_op_queue, sizeof(void *));
    
    for (int i = 0; i < num_op_queue; i++)
        queue_attr_set[i] = &queue_attr;
    
    if (unlikely(rte_flow_configure(port_id,
                           (const struct rte_flow_port_attr *)&port_attr,
                           num_op_queue,
                           queue_attr_set,
                           &error) < 0)) {
        printf("rte_flow_configure() failed. %s\n", error.message);
        
        return -1;
    }
    
    free(queue_attr_set);

    return 0;
}
/*---------------------------------------------------------------------------*/
static struct rte_flow_pattern_template* 
create_pattern_template_jump_recv(uint16_t port_id, struct rte_flow_error* error)
{
    struct rte_flow_item titems[PATTERN_NUM_JUMP] = {0};
    struct rte_flow_item_eth eth_mask = {0};
	struct rte_flow_item_ipv4 ipv4_mask = {0};
    struct rte_flow_item_tcp tcp_mask = {0};

    struct rte_flow_pattern_template_attr attr = {
        .relaxed_matching = 1,
        .ingress = 1
    };
    
    /* eth pattern template */
    titems[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    eth_mask.type = 0xFFFF;
    titems[0].mask = &eth_mask;
    
    /* ipv4 pattern template */
    titems[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    ipv4_mask.hdr.src_addr = 0xFFFFFFFF;
    ipv4_mask.hdr.dst_addr = 0xFFFFFFFF;
    titems[1].mask = &ipv4_mask;

    /* tcp pattern template */
    titems[2].type = RTE_FLOW_ITEM_TYPE_TCP;
    tcp_mask.hdr.src_port = 0xFFFF;
    tcp_mask.hdr.dst_port = 0xFFFF;
    titems[2].mask = &tcp_mask;

    /* pattern template end */
    titems[3].type = RTE_FLOW_ITEM_TYPE_END;

    return rte_flow_pattern_template_create(port_id, &attr, titems, error);
}
/*---------------------------------------------------------------------------*/
static struct rte_flow_pattern_template* 
create_pattern_template_hws_recv(uint16_t port_id, struct rte_flow_error* error)
{
    struct rte_flow_item titems[PATTERN_NUM_HWS] = {0};
    struct rte_flow_item_eth eth_mask = {0};
	struct rte_flow_item_ipv4 ipv4_mask = {0};
    struct rte_flow_item_tcp tcp_mask = {0};

    struct rte_flow_pattern_template_attr attr = {
        .relaxed_matching = 1,
        .transfer = 1
    };
    
    /* eth pattern template */
    titems[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    memset(eth_mask.hdr.dst_addr.addr_bytes, 0xFF, RTE_ETHER_ADDR_LEN);
    memset(eth_mask.hdr.src_addr.addr_bytes, 0xFF, RTE_ETHER_ADDR_LEN);
    eth_mask.type = 0xFFFF;
    titems[0].mask = &eth_mask;
    
    /* ipv4 pattern template */
    titems[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    ipv4_mask.hdr.src_addr = 0xFFFFFFFF;
    ipv4_mask.hdr.dst_addr = 0xFFFFFFFF;
    titems[1].mask = &ipv4_mask;

    /* tcp pattern template */
    titems[2].type = RTE_FLOW_ITEM_TYPE_TCP;
    tcp_mask.hdr.src_port = 0xFFFF;
    tcp_mask.hdr.dst_port = 0xFFFF;
    tcp_mask.hdr.tcp_flags = RTE_TCP_SYN_FLAG;
    titems[2].mask = &tcp_mask;

    /* pattern template end */
    titems[3].type = RTE_FLOW_ITEM_TYPE_END;

    return rte_flow_pattern_template_create(port_id, &attr, titems, error);
}
/*---------------------------------------------------------------------------*/
static struct rte_flow_actions_template* 
create_actions_template_jump_recv(uint16_t port_id, struct rte_flow_error* error)
{
    struct rte_flow_action tactions[ACTION_NUM_JUMP] = {0};
    struct rte_flow_action action_mask[ACTION_NUM_JUMP] = {0};
    struct rte_flow_actions_template_attr action_attr = {
        .ingress = 1
    };
    
    /* HWS action template */
    tactions[0].type = RTE_FLOW_ACTION_TYPE_JUMP;
    
    /* action template end */
    tactions[1].type = RTE_FLOW_ACTION_TYPE_END;

    /* This sets the masks to match the actions, 
     * indicating that all fields of the actions
	 * should be considered as part of the template.
	 */
	memcpy(action_mask, tactions, sizeof(action_mask));

    return rte_flow_actions_template_create(port_id, &action_attr,
        tactions, action_mask, error);
}
/*---------------------------------------------------------------------------*/
static struct rte_flow_actions_template* 
create_actions_template_hws_recv(uint16_t port_id, struct rte_flow_error* error)
{
    struct rte_flow_action tactions[ACTION_NUM_HWS] = {0};
    struct rte_flow_action action_mask[ACTION_NUM_HWS] = {0};
    struct rte_flow_actions_template_attr action_attr = {
        .transfer = 1
    };
    
    /* HWS action template */
    tactions[0].type = RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT;
    
    /* action template end */
    tactions[1].type = RTE_FLOW_ACTION_TYPE_END;

    /* This sets the masks to match the actions, indicating that all fields of the actions
	 * should be considered as part of the template.
	 */
	memcpy(action_mask, tactions, sizeof(action_mask));

    return rte_flow_actions_template_create(port_id, &action_attr,
        tactions, action_mask, error);
}
/*---------------------------------------------------------------------------*/
struct rte_flow_template_table* 
create_table_jump_recv(uint16_t port_id) 
{
	struct rte_flow_pattern_template* pt;
	struct rte_flow_actions_template* at;
    struct rte_flow_error* error;

	if (unlikely(flow_configure(port_id) < 0))
        return NULL;
    printf("flow_configure() done!\n");
    
    /* Set the rule attribute, only ingress packets will be checked. */
	struct rte_flow_template_table_attr table_attr = {
			.flow_attr = {
				.group = 0,
				.priority = 1, // it will be ignored after applying hws rule
                .ingress = 1,
				.egress = 0,
				.transfer = 0,
				.reserved = 0,
		},
			/* Maximum number of flow rules that this table holds. */
			.nb_flows = MAX_SESSIONS, // for safety
	};

	/* The pattern template defines common matching fields without values.
	 * The number and order of items in the template must be the same 
     * at the rule creation.
	 */
	pt = create_pattern_template_jump_recv(port_id, error);
	if (pt == NULL) {
		printf("Failed to create pattern template: %s (%s)\n",
		error->message, rte_strerror(rte_errno));
		return NULL;
	}

	/* The actions template holds a list of action types without values.
	 * The number and order of actions in the template must be the same 
     * at the rule creation.
	 */
	at = create_actions_template_jump_recv(port_id, error);
	if (at == NULL) {
		printf("Failed to create actions template: %s (%s)\n",
		error->message, rte_strerror(rte_errno));
		return NULL;
	}

    struct rte_flow_template_table* table = 
        rte_flow_template_table_create(port_id, 
                                       &table_attr, 
                                       &pt, 1, // 1: # of pattern templates 
                                       &at, 1, // 1: # of action templates
                                       error);

    if (unlikely(!table)) {
        printf("Table creation failed. (g0)\n");
        if (error->message)
            printf("Error type: %d, Error message: %s\n", error->type, error->message);
        else
            printf("Error cause: type = %d, cause = %p\n",
                   error->type, error->cause);
        return NULL;
    }

	return table;
}
/*---------------------------------------------------------------------------*/
struct rte_flow_template_table* 
create_table_hws_recv(uint16_t port_id) 
{
	struct rte_flow_pattern_template* pt;
	struct rte_flow_actions_template* at;
    struct rte_flow_error* error;

	if (unlikely(flow_configure(port_id) < 0))
        return NULL;
    printf("flow_configure() done!\n");
    
    /* Set the rule attribute, only ingress packets will be checked. */
	struct rte_flow_template_table_attr table_attr = {
			.flow_attr = {
				.group = 1,
				.priority = 0,
                .ingress = 0,
				.egress = 0,
				.transfer = 1,
				.reserved = 0,
		},
			/* Maximum number of flow rules that this table holds. */
			.nb_flows = MAX_SESSIONS,
	};

	/* The pattern template defines common matching fields without values.
	 * The number and order of items in the template must be the same 
     * at the rule creation.
	 */
	pt = create_pattern_template_hws_recv(port_id, error);
	if (pt == NULL) {
		printf("Failed to create pattern template: %s (%s)\n",
		error->message, rte_strerror(rte_errno));
		return NULL;
	}

	/* The actions template holds a list of action types without values.
	 * The number and order of actions in the template must be the same 
     * at the rule creation.
	 */
	at = create_actions_template_hws_recv(port_id, error);
	if (at == NULL) {
		printf("Failed to create actions template: %s (%s)\n",
		error->message, rte_strerror(rte_errno));
		return NULL;
	}

    struct rte_flow_template_table* table = 
        rte_flow_template_table_create(port_id, 
                                       &table_attr, 
                                       &pt, 1, // 1: # of pattern templates 
                                       &at, 1, // 1: # of action templates
                                       error);

    if (unlikely(!table)) {
        printf("Table creation failed. (g1)\n");
        if (error->message)
            printf("Error type: %d, Error message: %s\n", error->type, error->message);
        else
            printf("Error cause: type = %d, cause = %p\n",
                   error->type, error->cause);
        return NULL;
    }

	return table;
}
/*---------------------------------------------------------------------------*/
/*----------------------------- runtime (recv) ------------------------------*/
void
fill_pattern_jump_recv(tcp_connection_t* conn) 
{   
    /* eth pattern */
    struct rte_flow_item_eth* eth_spec;
    struct rte_flow_item_eth* eth_mask;
    struct rte_flow_item* pattern = conn->pattern_jump;

    eth_spec = conn->eth_spec_jump;
    eth_mask = conn->eth_mask_jump;

    eth_spec->type = htons(0x0800);
    eth_mask->type = 0xFFFF;
    
    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[0].spec = eth_spec;
    pattern[0].mask = eth_mask;

    /* ipv4 pattern */
    struct rte_flow_item_ipv4* ipv4_spec;
    struct rte_flow_item_ipv4* ipv4_mask;

    ipv4_spec = conn->ipv4_spec_jump;
    ipv4_mask = conn->ipv4_mask_jump;

    ipv4_spec->hdr.src_addr = conn->client_ip;
    ipv4_spec->hdr.dst_addr = conn->server_ip;
    ipv4_mask->hdr.src_addr = 0xFFFFFFFF;
    ipv4_mask->hdr.dst_addr = 0xFFFFFFFF;
    
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[1].spec = ipv4_spec;
    pattern[1].mask = ipv4_mask;

    /* tcp pattern */
    struct rte_flow_item_tcp* tcp_spec;
    struct rte_flow_item_tcp* tcp_mask;

    tcp_spec = conn->tcp_spec_jump;
    tcp_mask = conn->tcp_mask_jump;

    tcp_spec->hdr.src_port = conn->client_port;
    tcp_spec->hdr.dst_port = conn->server_port;
    tcp_mask->hdr.src_port = 0xFFFF;
    tcp_mask->hdr.dst_port = 0xFFFF;

    pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
    pattern[2].spec = tcp_spec;
    pattern[2].mask = tcp_mask;

    /* pattern end */
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;

}
/*---------------------------------------------------------------------------*/
void
fill_pattern_hws_recv(tcp_connection_t* conn) 
{
    struct rte_flow_item_eth* eth_spec;
    struct rte_flow_item_eth* eth_mask;
    struct rte_flow_item* pattern = conn->pattern_hws;

    eth_spec = conn->eth_spec_hws;
    eth_mask = conn->eth_mask_hws;

    eth_spec->type = htons(0x0800);
    eth_mask->type = 0xFFFF;

    rte_ether_addr_copy((struct rte_ether_addr* )&conn->client_mac, &eth_spec->hdr.src_addr);
    rte_ether_addr_copy((struct rte_ether_addr* )&conn->server_mac, &eth_spec->hdr.dst_addr);
    memset(eth_mask->hdr.src_addr.addr_bytes, 0xFF, RTE_ETHER_ADDR_LEN);
    memset(eth_mask->hdr.dst_addr.addr_bytes, 0xFF, RTE_ETHER_ADDR_LEN);
    
    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[0].spec = eth_spec;
    pattern[0].mask = eth_mask;

    /* ipv4 pattern */
    struct rte_flow_item_ipv4* ipv4_spec;
    struct rte_flow_item_ipv4* ipv4_mask;

    ipv4_spec = conn->ipv4_spec_hws;
    ipv4_mask = conn->ipv4_mask_hws;

    ipv4_spec->hdr.src_addr = conn->client_ip;
    ipv4_spec->hdr.dst_addr = conn->server_ip;
    ipv4_mask->hdr.src_addr = 0xFFFFFFFF;
    ipv4_mask->hdr.dst_addr = 0xFFFFFFFF;
    
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[1].spec = ipv4_spec;
    pattern[1].mask = ipv4_mask;

    /* tcp pattern */
    struct rte_flow_item_tcp* tcp_spec;
    struct rte_flow_item_tcp* tcp_mask;

    tcp_spec = conn->tcp_spec_hws;
    tcp_mask = conn->tcp_mask_hws;

    tcp_spec->hdr.src_port = conn->client_port;
    tcp_spec->hdr.dst_port = conn->server_port;
    tcp_mask->hdr.src_port = 0xFFFF;
    tcp_mask->hdr.dst_port = 0xFFFF;
    tcp_spec->hdr.tcp_flags = 0;
    tcp_mask->hdr.tcp_flags = RTE_TCP_SYN_FLAG;

    pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
    pattern[2].spec = tcp_spec;
    pattern[2].mask = tcp_mask;

    /* pattern end */
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
}
/*---------------------------------------------------------------------------*/
void
fill_action_jump_recv(tcp_connection_t* conn) 
{
    conn->group_to_jump->group = 1; // jump to group 1

    conn->action_jump[0].type = RTE_FLOW_ACTION_TYPE_JUMP;
    conn->action_jump[0].conf = conn->group_to_jump;

    conn->action_jump[1].type = RTE_FLOW_ACTION_TYPE_END;
}
/*---------------------------------------------------------------------------*/
void
fill_action_hws_recv(tcp_connection_t* conn) 
{
    
    conn->fwd->port_id = conn->portid + 1; // port ID of pf0hpf

    conn->action_hws[0].type = RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT;
    conn->action_hws[0].conf = conn->fwd;

    conn->action_hws[1].type = RTE_FLOW_ACTION_TYPE_END;
}
/*---------------------------------------------------------------------------*/
inline int
ins_async_hws_recv(tcp_connection_t* conn, 
              struct rte_flow_template_table* table_jump, 
              struct rte_flow_template_table* table_hws) 
{
    int ret;
    struct rte_flow_error error_jump, error_hws, error;
    
    memset(&error_jump, 0, sizeof(error_jump));
    memset(&error_hws, 0, sizeof(error_hws));

#if RTE_FLOW_JUMP
    /* Jump */
    fill_pattern_jump_recv(conn);
    fill_action_jump_recv(conn);

    const struct rte_flow_op_attr ops_attr_jump = { .postpone = 0 };
#endif /* RTE_FLOW_JUMP */
    
    /* HWS */
    fill_pattern_hws_recv(conn);
    fill_action_hws_recv(conn);

    /* create flow */
    const struct rte_flow_op_attr ops_attr_hws = { .postpone = 1 };

#if RTE_FLOW_JUMP
    conn->flow_jump = rte_flow_async_create(conn->portid,
		conn->ctx->coreid, /* Flow queue used to insert the rule. */
		&ops_attr_jump,
		table_jump,
		conn->pattern_jump,
		0, /* Pattern template index in the table. */
		conn->action_jump,
		0, /* Actions template index in the table. */
		0, /* user data */
		&error_jump);
    if (unlikely(!conn->flow_jump)) {
        fprintf(stderr, "Flow for group 0 creation failed.\n");
        if (error_jump.message)
            fprintf(stderr, "Error type: %d, Error message: %s\n", 
                    error_jump.type, error_jump.message);
        else
            fprintf(stderr, "Error cause: type = %d, cause = %p\n",
                    error_jump.type, error_jump.cause);
        return -1;
    }
#endif /* RTE_FLOW_JUMP */

    int queue_id = 2 * (conn->ctx->coreid);

    conn->flow_hws = rte_flow_async_create(conn->portid,
		queue_id, /* Flow queue used to insert the rule. */
		&ops_attr_hws,
		table_hws,
		conn->pattern_hws,
		0, /* Pattern template index in the table. */
		conn->action_hws,
		0, /* Actions template index in the table. */
		conn, /* user data */
		&error_hws);

    if (unlikely(!conn->flow_hws)) {
        fprintf(stderr, "Flow for group 1 creation failed.\n");
        fprintf(stderr, "Core ID: %d\n", conn->ctx->coreid);
        if (error_hws.message)
            fprintf(stderr, "Error type: %d, Error message: %s\n", 
                    error_hws.type, error_hws.message);
        else
            fprintf(stderr, "Error cause: type = %d, cause = %p\n",
                    error_hws.type, error_hws.cause);
        return -1;
    }

    return 0;
}
/*---------------------------------------------------------------------------*/
/*----------------------------- Miscellaneous -------------------------------*/
inline int
del_hws_async(tcp_connection_t* conn) 
{
    struct rte_flow_error error_hws;
    const struct rte_flow_op_attr ops_attr_hws = { .postpone = 1 };

#if RTE_FLOW_JUMP
    if (rte_flow_async_destroy(conn->portid,
                               conn->ctx->coreid,
                               &ops_attr_hws,
                               conn->flow_jump, 
                               0, /* user data */
                               &error_hws) < 0) {
        fprintf(stderr, "Flow for group 1 deletion failed.\n");
        if (error_hws.message)
            fprintf(stderr, "Error type: %d, Error message: %s\n", 
                    error_hws.type, error_hws.message);
        else
            fprintf(stderr, "Error cause: type = %d, cause = %p\n",
                    error_hws.type, error_hws.cause);
        return -1;
    }
#endif /* RTE_FLOW_JUMP */

    int queue_id = 2 * (conn->ctx->coreid) + 1;

    if (unlikely(rte_flow_async_destroy(conn->portid,
                                        queue_id,
                                        &ops_attr_hws,
                                        conn->flow_hws, 
                                        conn, /* user data */
                                        &error_hws) < 0)) {
#if VERBOSE_DPDK
        fprintf(stderr, "Flow for group 1 deletion failed.\n");
        if (error_hws.message)
            fprintf(stderr, "Error type: %d, Error message: %s\n", 
                    error_hws.type, error_hws.message);
        else
            fprintf(stderr, "Error cause: type = %d, cause = %p\n",
                    error_hws.type, error_hws.cause);
#endif /* VERBOSE_DPDK */
        return -1;
    }

    return 0;
}
/*---------------------------------------------------------------------------*/
inline void
rte_flow_pull_and_push(thread_context_t* ctx) 
{
    struct rte_flow_error error_hws;
    struct rte_flow_op_result result[MAX_RESULTS];
    int ret;

    int hws_ins_queue_id = 2 * (ctx->coreid);
    int hws_del_queue_id = 2 * (ctx->coreid) + 1;
    
    // TODO: do not use hardcoding
    /* pull hws inserts */
    ret = rte_flow_pull(0, hws_ins_queue_id, result, MAX_RESULTS, &error_hws);
    for (int i = 0; i < ret; i++) {
        if (result[i].status == RTE_FLOW_OP_SUCCESS)
            ((tcp_connection_t *)(result[i].user_data))->hws_applied = 1;
        else 
            fprintf(stderr, "flow create failed for client ip: %u, port: %u - %s\n",
                    ((tcp_connection_t *)(result[i].user_data))->client_ip,
                    ((tcp_connection_t *)(result[i].user_data))->client_port,
                    error_hws.message);
    }

    /* push hws inserts */
    if (unlikely(rte_flow_push(0, hws_ins_queue_id, &error_hws) < 0))
        fprintf(stderr, "rte_flow_push() failed. Error msg: %s\n", error_hws.message);

    /* pull hws dels */
    ret = rte_flow_pull(0, hws_del_queue_id, result, MAX_RESULTS, &error_hws);
    for (int i = 0; i < ret; i++) {
        if (result[i].status == RTE_FLOW_OP_SUCCESS)
            ((tcp_connection_t *)(result[i].user_data))->hws_deleted = 1;
        else
            fprintf(stderr, "flow delete failed for client ip: %u, port: %u - %s\n",
                    ((tcp_connection_t *)(result[i].user_data))->client_ip,
                    ((tcp_connection_t *)(result[i].user_data))->client_port,
                    error_hws.message);
    }

    /* push hws dels */
    if (unlikely(rte_flow_push(0, hws_del_queue_id, &error_hws) < 0))
        fprintf(stderr, "rte_flow_push() failed. Error msg: %s\n", error_hws.message);
}
/*---------------------------------------------------------------------------*/
#endif /* USE_RTE_HWS */
