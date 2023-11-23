/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "printk.h"

#include "../common/defines.h"
#include "../common/stats.h"

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} xsks_map SEC(".maps");

struct ipv4_lpm_key {
        __u32 prefixlen;
        __u32 data;
};

struct ipv6_lpm_key {
        __u32 prefixlen;
        __u128 data;
};

struct {
        __uint(type, BPF_MAP_TYPE_LPM_TRIE);
        __type(key, struct ipv4_lpm_key);
        __type(value, __u32);
        __uint(map_flags, BPF_F_NO_PREALLOC);
        __uint(max_entries, 255);
} ipv4_lpm_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_LPM_TRIE);
        __type(key, struct ipv4_lpm_key);
        __type(value, __u128);
        __uint(map_flags, BPF_F_NO_PREALLOC);
        __uint(max_entries, 255);
} ipv6_lpm_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct datarec);
	__uint(max_entries, XDP_ACTION_MAX);
} xdp_stats_map SEC(".maps");

typedef struct {
	void *end;
	void *begin;
} view_t;

static __always_inline
void stats_add(__u32 code, __u64 bytes)
{
	struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &code);
	if (rec == NULL) {
		return;
	}
	rec->rx_packets++;
	rec->rx_bytes += bytes;
}

static __always_inline 
int parse_ethhdr(view_t *view, struct ethhdr **ethhdr)
{
	struct ethhdr *eth = view->begin;
	int hdrsize = sizeof(*eth);
	if (view->begin + hdrsize > view->end) {
		return -1;
	}

	view->begin += hdrsize;
	*ethhdr = eth;

	return 0;
}

static __always_inline
int parse_iphdr(view_t *view, struct iphdr **iphdr)
{
	struct iphdr *iph = view->begin;
	int hdrsize = sizeof(*iph);
	if (view->begin + hdrsize > view->end) {
		return -1;
	}
	// Validate IPv4
	if (iph->version != 4 || iph->ihl < 5) {
		return -1;
	}

	hdrsize = iph->ihl * 4;
	if (view->begin + hdrsize > view->end) {
		return -1;
	}

	view->begin += hdrsize;
	*iphdr = iph;

	return 0;
}

static __always_inline
int parse_ip6hdr(view_t *view, struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = view->begin;
	int hdrsize = sizeof(*ip6h);
	if (view->begin + hdrsize > view->end) {
		return -1;
	}
	if (ip6h->version != 6) {
		return -1;
	}

	view->begin += hdrsize;
	*ip6hdr = ip6h;
	
	return 0;
}


static __always_inline
int parse_udphdr(view_t *view, struct udphdr **udphdr)
{
	struct udphdr *udp = view->begin;
	int hdrsize = sizeof(*udphdr);
	if (view->begin + hdrsize > view->end)
		return -1;

	view->begin += hdrsize;
	*udphdr = udp;

	return 0;
}
static __always_inline
int parse_tcphdr(view_t *view, struct tcphdr **tcphdr)
{
	struct tcphdr *tcp = view->begin;
	int hdrsize = sizeof(*tcphdr);
	if (view->begin + hdrsize > view->end)
		return -1;

	view->begin += hdrsize;
	*tcphdr = tcp;

	return 0;
}

SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
	unsigned int rx_queue_idx = ctx->rx_queue_index;

	view_t view = {
		.end = (void *)(long)ctx->data_end,
		.begin = (void *)(long)ctx->data
	};

	struct ethhdr *eth = NULL;
	int ret = parse_ethhdr(&view, &eth);
	if (ret) {
		bpf_printk("Skip: Not ETH header!\n");
		stats_add(XDP_PASS, ctx->data_end - ctx->data);
		return XDP_PASS;
	}

	unsigned char ip_proto;
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = NULL;
		ret = parse_iphdr(&view, &ip);
		if (ret) {
			bpf_printk("Error: Malformed IPv4 header!\n");
			stats_add(XDP_DROP, ctx->data_end - ctx->data);
			return XDP_DROP;
		}
		ip_proto = ip->protocol;
	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ipv6 = NULL;
		ret = parse_ip6hdr(&view, &ipv6);
		if (ret) {
			bpf_printk("Error: Malformed IPv6 header!\n");
			stats_add(XDP_DROP, ctx->data_end - ctx->data);
			return XDP_DROP;
		}
		ip_proto = ipv6->nexthdr;
	} else {
		bpf_printk("Skip: Not IPvX Header!\n");
		stats_add(XDP_PASS, ctx->data_end - ctx->data);
		return XDP_PASS;
	}

	if (ip_proto == IPPROTO_UDP) {
		struct udphdr *udp;
		ret = parse_udphdr(&view, &udp);
		if (ret) {
			bpf_printk("Error: Malformed UDP header!\n");
			stats_add(XDP_DROP, ctx->data_end - ctx->data);
			return XDP_DROP;
		}
	} else if (ip_proto == IPPROTO_TCP) {
		struct tcphdr *tcp;
		int ret = parse_tcphdr(&view, &tcp);
		if (ret < 0) {
			bpf_printk("Error: Malformed TCP header!\n");
			stats_add(XDP_DROP, ctx->data_end - ctx->data);
			return XDP_DROP;
		}
	} else {
		bpf_printk("Skip: Not UDP/TCP header!\n");
		stats_add(XDP_PASS, ctx->data_end - ctx->data);
		return XDP_PASS;
	}

	if (bpf_map_lookup_elem(&xsks_map, &rx_queue_idx)) {
		ret = bpf_redirect_map(&xsks_map, rx_queue_idx, 0);
		stats_add(ret, ctx->data_end - ctx->data);
        return ret;
	}

	bpf_printk("Skip: Not interested!\n");
	stats_add(XDP_PASS, ctx->data_end - ctx->data);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";