//go:build ignore

// Type definitions (no includes needed for eBPF)
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef unsigned char __u8;
typedef unsigned short __u16;

#define NULL ((void*)0)

// Minimal BPF definitions (compatible with all kernel versions)
#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name

// BPF helper functions
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;

// XDP action codes
#define XDP_ABORTED 0
#define XDP_DROP 1
#define XDP_PASS 2
#define XDP_TX 3
#define XDP_REDIRECT 4

// Ethernet protocol
#define ETH_P_IP 0x0800

// BPF map type
#define BPF_MAP_TYPE_HASH 1

// Byte order conversion
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htons(x) __builtin_bswap16(x)

// Network structures (minimal definitions)
struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	__u32 ingress_ifindex;
	__u32 rx_queue_index;
};

struct ethhdr {
	__u8 h_dest[6];
	__u8 h_source[6];
	__u16 h_proto;
} __attribute__((packed));

struct iphdr {
	__u8 ihl:4;
	__u8 version:4;
	__u8 tos;
	__u16 tot_len;
	__u16 id;
	__u16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__u16 check;
	__u32 saddr;
	__u32 daddr;
} __attribute__((packed));

// Map to store blocked IPs (key: IPv4 address as __u32, value: expiration timestamp as __u64)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 100000);  // Support up to 100k blocked IPs
	__type(key, __u32);           // IPv4 address
	__type(value, __u64);         // Expiration timestamp (seconds since epoch)
} blocked_ips SEC(".maps");

// XDP program to filter blocked IPs
SEC("xdp")
int xdp_blocker(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	// Parse Ethernet header
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;  // Invalid packet, pass to network stack

	// Only process IPv4 packets
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	// Parse IP header
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;  // Invalid packet, pass to network stack

	// Extract source IP address (already in network byte order)
	__u32 src_ip = ip->saddr;

	// Look up source IP in blocked_ips map
	__u64 *expires_at = bpf_map_lookup_elem(&blocked_ips, &src_ip);
	if (expires_at != NULL) {
		// IP is in blocklist - DROP the packet
		// Note: Expiration checking is handled by user-space periodic cleanup
		// This keeps the kernel code simple and avoids division operations
		return XDP_DROP;
	}

	// IP not in blocklist - pass to network stack
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
