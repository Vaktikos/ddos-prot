// SPDX-License-Identifier: GPL-2.0
// Sentinel Shield XDP filter.
//
// Order of decisions for every IPv4/IPv6 packet:
//   1. source in allow list       -> XDP_PASS (trusted and management networks)
//   2. source in block list and the entry has not expired -> XDP_DROP
//   3. destination in the protected set -> count the packet against its source, XDP_PASS
//
// Blocks carry their own expiry (CLOCK_MONOTONIC nanoseconds). An expired entry is ignored,
// so a block ends on time even if the userspace agent has died.
//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

struct lpm4_key { __u32 prefixlen; __u32 addr; };
struct lpm6_key { __u32 prefixlen; __u8 addr[16]; };

struct block_val { __u64 expires_ns; };

struct src_stats { __u64 packets; __u64 bytes; __u64 syn; };

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm4_key);
	__type(value, struct block_val);
} block4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm6_key);
	__type(value, struct block_val);
} block6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm4_key);
	__type(value, __u8);
} allow4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm6_key);
	__type(value, __u8);
} allow6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm4_key);
	__type(value, __u8);
} protect4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm6_key);
	__type(value, __u8);
} protect6 SEC(".maps");

// Per-source counters for traffic toward protected destinations. LRU, so a flood from
// many spoofed sources evicts old entries instead of exhausting the map.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 131072);
	__type(key, __u32);
	__type(value, struct src_stats);
} src4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 131072);
	__type(key, struct in6_addr);
	__type(value, struct src_stats);
} src6 SEC(".maps");

// Index 0: dropped packets, 1: dropped bytes, 2: passed packets.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 3);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

static __always_inline void bump(__u32 idx, __u64 n)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &idx);
	if (v)
		*v += n;
}

static __always_inline void count_src4(__u32 saddr, __u64 len, int syn)
{
	struct src_stats *s = bpf_map_lookup_elem(&src4, &saddr);
	if (s) {
		__sync_fetch_and_add(&s->packets, 1);
		__sync_fetch_and_add(&s->bytes, len);
		if (syn)
			__sync_fetch_and_add(&s->syn, 1);
		return;
	}
	struct src_stats init = { .packets = 1, .bytes = len, .syn = syn ? 1 : 0 };
	bpf_map_update_elem(&src4, &saddr, &init, BPF_NOEXIST);
}

static __always_inline void count_src6(const struct in6_addr *saddr, __u64 len, int syn)
{
	struct src_stats *s = bpf_map_lookup_elem(&src6, saddr);
	if (s) {
		__sync_fetch_and_add(&s->packets, 1);
		__sync_fetch_and_add(&s->bytes, len);
		if (syn)
			__sync_fetch_and_add(&s->syn, 1);
		return;
	}
	struct src_stats init = { .packets = 1, .bytes = len, .syn = syn ? 1 : 0 };
	bpf_map_update_elem(&src6, saddr, &init, BPF_NOEXIST);
}

SEC("xdp")
int sentinel_filter(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > end)
		return XDP_PASS;

	__u64 len = end - data;
	__u64 now = bpf_ktime_get_ns();
	__u16 proto = eth->h_proto;
	void *l3 = eth + 1;

	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = l3;
		if ((void *)(ip + 1) > end)
			return XDP_PASS;

		struct lpm4_key sk = { .prefixlen = 32, .addr = ip->saddr };
		if (bpf_map_lookup_elem(&allow4, &sk))
			return XDP_PASS;
		struct block_val *b = bpf_map_lookup_elem(&block4, &sk);
		if (b && now < b->expires_ns) {
			bump(0, 1);
			bump(1, len);
			return XDP_DROP;
		}
		struct lpm4_key dk = { .prefixlen = 32, .addr = ip->daddr };
		if (bpf_map_lookup_elem(&protect4, &dk)) {
			int syn = 0;
			if (ip->protocol == IPPROTO_TCP && ip->ihl == 5) {
				struct tcphdr *tcp = (void *)(ip + 1);
				if ((void *)(tcp + 1) <= end)
					syn = tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst;
			}
			count_src4(ip->saddr, len, syn);
		}
		bump(2, 1);
		return XDP_PASS;
	}

	if (proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = l3;
		if ((void *)(ip6 + 1) > end)
			return XDP_PASS;

		struct lpm6_key sk = { .prefixlen = 128 };
		__builtin_memcpy(sk.addr, &ip6->saddr, 16);
		if (bpf_map_lookup_elem(&allow6, &sk))
			return XDP_PASS;
		struct block_val *b = bpf_map_lookup_elem(&block6, &sk);
		if (b && now < b->expires_ns) {
			bump(0, 1);
			bump(1, len);
			return XDP_DROP;
		}
		struct lpm6_key dk = { .prefixlen = 128 };
		__builtin_memcpy(dk.addr, &ip6->daddr, 16);
		if (bpf_map_lookup_elem(&protect6, &dk)) {
			int syn = 0;
			if (ip6->nexthdr == IPPROTO_TCP) {
				struct tcphdr *tcp = (void *)(ip6 + 1);
				if ((void *)(tcp + 1) <= end)
					syn = tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst;
			}
			count_src6(&ip6->saddr, len, syn);
		}
		bump(2, 1);
		return XDP_PASS;
	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
