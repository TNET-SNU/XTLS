#include "helpers.h"

#define IP_HDR_OFFSET 14
#define HTTPS_PORT 0x01BB    	// 443
#define HTTPS_PORT_N 0xBB01    	// htons(443)
/*---------------------------------------------------------------------------*/
char *
scode_2_str(int scode) 
{
    switch (scode) {
		case 200:
			return "OK";
			break;

		case 404:
			return "Not Found";
			break;
	}

	return NULL;
}

int 
find_http_header(char* data, int len) 
{
    char* temp = data;
	int hdr_len = 0;

	/* null terminate the string first */
	data[len] = 0;

	while (!hdr_len && (temp = strchr(temp, '\n')) != NULL) {
		temp++;
		if (*temp == '\n') 
			hdr_len = temp - data;
		else if (*temp == '\r' && *(temp + 1) == '\n') 
			hdr_len = temp - data + 1;
	}

	return hdr_len;
}

void
http_get_url(char* data, int data_len, char* value, int value_len) 
{
    char* ret = data;
	int i = 0;

	if (strncmp(data, HTTP_GET, sizeof(HTTP_GET) - 1))
		*value = 0;
	
	ret += sizeof(HTTP_GET) - 1;

	while (*ret && SPACE_OR_TAB(*ret)) 
		ret++;

	while (*ret && *ret != ' ' && i < value_len - 1) {
		value[i++] = *ret++;
	}

	value[i] = '\0';
}

void 
hexdump(const void* ptr, size_t size) 
{
    const uint8_t* data = (const uint8_t *)ptr;
    size_t i, j;

    for (i = 0; i < size; i += 16) {
        fprintf(stderr, "%08zx  ", i);  // Print offset

        // Print hex values
        for (j = 0; j < 16; j++) {
            if (i + j < size)
                fprintf(stderr, "%02x ", data[i + j]);
            else
                fprintf(stderr, "   ");  // Fill for alignment
        }

        fprintf(stderr, " ");

        // Print ASCII characters
        for (j = 0; j < 16; j++) {
            if (i + j < size)
                fprintf(stderr, "%c", isprint(data[i + j]) ? data[i + j] : '.');
        }

        fprintf(stderr, "\n");
    }
}

void 
print_hex_array(const char* label, const uint8_t* data, size_t size) 
{
    fprintf(stderr, "%s: ", label);
    for (size_t i = 0; i < size; ++i) {
        fprintf(stderr, "%02x", data[i]);
        if ((i + 1) % 16 == 0)
            fprintf(stderr, "\n%*s", (int)strlen(label) + 2, "");
    }
    fprintf(stderr, "\n");
}

void 
load_file_cache(DIR* dir, const char* dir_path, 
                file_cache_t* fcache, int* nfiles) 
{
    struct dirent* ent;
    int fd, ret;
    uint64_t total_read;

    *nfiles = 0;
    while ((ent = readdir(dir)) != NULL) {
		if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
			continue;

		snprintf(fcache[*nfiles].name, NAME_LIMIT, "%s", ent->d_name);
		snprintf(fcache[*nfiles].fullname, FULL_PATH_LIMIT, "%s/%s",
			 dir_path, ent->d_name);
		fd = open(fcache[*nfiles].fullname, O_RDONLY);
		if (fd < 0) {
			perror("open");
			continue;
		} 
        else {
			fcache[*nfiles].size = lseek64(fd, 0, SEEK_END);
			lseek64(fd, 0, SEEK_SET);
		}

		fcache[*nfiles].file = (char *)malloc(fcache[*nfiles].size);
		if (!fcache[*nfiles].file) {
			TRACE_CONFIG("Failed to allocate memory for file %s\n", 
				     fcache[*nfiles].name);
			perror("malloc");
			continue;
		}

		TRACE_INFO("Reading %s (%lu bytes)\n", 
				fcache[*nfiles].name, fcache[*nfiles].size);
		total_read = 0;
		while (1) {
			ret = read(fd, fcache[*nfiles].file + total_read, 
					fcache[*nfiles].size - total_read);
			if (ret < 0) {
				break;
			} 
            else if (ret == 0) {
				break;
			}
			total_read += ret;
		}
		if (total_read < fcache[*nfiles].size) {
			free(fcache[*nfiles].file);
			continue;
		}
		close(fd);
		(*nfiles)++;

		if (*nfiles >= MAX_FILES)
			break;
	}
}

struct sock_fprog 
bpf_filter_for_meta(thread_ctx_t* ctx) 
{
    static const uint16_t key_eth_types[] = {
        KEY_META_ETH_TYPE_0,
        KEY_META_ETH_TYPE_1,
        KEY_META_ETH_TYPE_2,
        KEY_META_ETH_TYPE_3,
        KEY_META_ETH_TYPE_4,
        KEY_META_ETH_TYPE_5,
        KEY_META_ETH_TYPE_6,
        KEY_META_ETH_TYPE_7,
        KEY_META_ETH_TYPE_8,
        KEY_META_ETH_TYPE_9,
        KEY_META_ETH_TYPE_10,
        KEY_META_ETH_TYPE_11,
        KEY_META_ETH_TYPE_12,
        KEY_META_ETH_TYPE_13,
        KEY_META_ETH_TYPE_14,
        KEY_META_ETH_TYPE_15,
    };

    uint16_t eth_type = key_eth_types[ctx->core_id];

    static __thread struct sock_filter bpf_code[] = {
        /* [0] Load EtherType at offset 12 */
        BPF_STMT(BPF_LD  | BPF_H | BPF_ABS, 12),

        /* Meta type - key? → ACCEPT */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 11, 0),

        /* else: expect IPv4 → if not, REJECT */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, 0, 11),

        /* Load first byte of IP header: version+ihl */
        BPF_STMT(BPF_LD  | BPF_B | BPF_ABS, IP_HDR_OFFSET),
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x0f),
        BPF_STMT(BPF_ALU | BPF_MUL | BPF_K, 4),
        BPF_STMT(BPF_ST, 0),   /* M[0] = IHL */

        /* protocol == TCP ? */
        BPF_STMT(BPF_LD  | BPF_B | BPF_ABS, IP_HDR_OFFSET + offsetof(struct iphdr, protocol)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_TCP, 0, 5),

        /* load TCP dest port = (eth + iphdr + 2) */
        BPF_STMT(BPF_LD  | BPF_H | BPF_IND, IP_HDR_OFFSET + 2),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, HTTPS_PORT_N, 0, 3),

        /* Load TCP flags: (eth + iphdr + 13) */
        BPF_STMT(BPF_LD  | BPF_B | BPF_IND, IP_HDR_OFFSET + 13),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, TH_SYN, 0, 1),

        /* ACCEPT */
        BPF_STMT(BPF_RET | BPF_K, 0x0000FFFF),

        /* REJECT */
        BPF_STMT(BPF_RET | BPF_K, 0),
    };

    bpf_code[1].k = eth_type;

    struct sock_fprog bpf = {
        .len = sizeof(bpf_code) / sizeof(struct sock_filter),
        .filter = bpf_code,
    };

    return bpf;
}

void
reset_conn_for_next_req(conn_state_t* conn) 
{
    conn->req_len = 0;
    conn->hdr_sent = 0;
    conn->hdr_len = 0;
    conn->hdr_offset = 0;
    conn->hdr_remain = 0;
    conn->scode = 0;
    conn->file_idx = -1;
    conn->file_size = 0;

    if (conn->resp_fd >= 0) {
        close(conn->resp_fd);
        conn->resp_fd = -1;
    }
    conn->resp_offset = 0;
    conn->resp_remain = 0;
    
    memset(conn->req_buf, 0, sizeof(conn->req_buf));
}
/*----------------------------------------------------------------------------*/
