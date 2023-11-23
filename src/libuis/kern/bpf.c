/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
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
unsigned short parse_ethhdr(view_t *view, struct ethhdr **ethhdr)
{
	if (ethhdr == NULL) {
		return -1;
	}

	struct ethhdr *eth = view->begin;
	int hdrsize = sizeof(*eth);
	if (view->begin + hdrsize > view->end) {
		return -1;
	}

	view->begin += hdrsize;
	*ethhdr = eth;

	return eth->h_proto;
}

static __always_inline
int parse_iphdr(view_t *view, struct iphdr **iphdr)
{
	if (view == NULL || iphdr == NULL) {
		return -1;
	}
	int hdrsize = sizeof(*iphdr);
	if (view->begin + hdrsize > view->end) {
		return -1;
	}
	struct iphdr *iph = view->begin;
	if (iph->version != 4 || iph->ihl < 5) {
		return -1;
	}

	hdrsize = iph->ihl * 4;
	if (view->begin + hdrsize > view->end) {
		return -1;
	}

	view->begin += hdrsize;
	*iphdr = iph;

	return iph->protocol;
}

// static __always_inline int parse_ip6hdr(view_t *view, struct ipv6hdr **ip6hdr)
// {
// 	struct ipv6hdr *ip6h = view->begin;

// 	if (ip6h + 1 > data_end)
// 		return -1;

// 	nh->pos = ip6h + 1;
// 	*ip6hdr = ip6h;

// 	return skip_ip6hdrext(nh, data_end, ip6h->nexthdr);
// }


static __always_inline int parse_udphdr(view_t *view, struct udphdr **udphdr)
{
	int len;
	struct udphdr *udp = view->begin;
	int hdrsize = sizeof(*udphdr);
	if (view->begin + hdrsize > view->end)
		return -1;

	view->begin += hdrsize;
	*udphdr = udp;

	len = bpf_ntohs(udp->len) - sizeof(struct udphdr);
	if (len < 0)
		return -1;

	return len;
}

SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
	unsigned int rx_queue_idx = ctx->rx_queue_index;
	struct datarec *rec;

	view_t view = {
		.end = (void *)(long)ctx->data_end,
		.begin = (void *)(long)ctx->data
	};

	int eth_proto;
	struct ethhdr *eth = NULL;
	eth_proto = parse_ethhdr(&view, &eth);
	if (eth_proto == -1) {
		bpf_printk("Skip: Not ETH header!\n");
		return XDP_PASS;
	}

	__u8 ip_proto;
	if (eth_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = NULL;
		ip_proto = parse_iphdr(&view, &ip);
		if (ip_proto < 0) {
			bpf_printk("Skip: Malformed IPv4 header!\n");
			return XDP_PASS;
		}
	} else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
		bpf_printk("Skip: IPv6 Header!\n");
		return XDP_PASS;
	} else {
		bpf_printk("Skip: Not IPvX Header!\n");
		return XDP_PASS;
	}
	
	if (ip_proto == IPPROTO_UDP || ip_proto == IPPROTO_TCP) {
	// 	struct udphdr *udp;
	// 	int ret = parse_udphdr(&view, &udp);
	// 	if (ret <= 0) {
	// 		bpf_printk("Skip: Not UDP header!\n");
	// 		return XDP_PASS;
	// 	}
	// } else if (ip_proto == IPPROTO_TCP) {
	// 	struct tcphdr *tcp;
	// 	int ret = parse_tcphdr(&view, &tcp);
	// 	if (ret < 0) {
	// 		bpf_printk("Skip: Not TCP header!\n");
	// 		return XDP_PASS;
	// 	}
	} else {
		bpf_printk("Skip: Not UDP/TCP header!\n");
		return XDP_PASS;
	}

	if (bpf_map_lookup_elem(&xsks_map, &rx_queue_idx)) {
		int ret = bpf_redirect_map(&xsks_map, rx_queue_idx, 0);

		rec = bpf_map_lookup_elem(&xdp_stats_map, &ret);
		if (rec == NULL) {
			bpf_printk("Error: Unable to load stats map!\n");
			return XDP_ABORTED;
		}
		rec->rx_packets += 1;
		rec->rx_bytes += ctx->data_end - ctx->data;

		bpf_printk("%d from queue %d!\n", ret, rx_queue_idx);
        return ret;
	}

	bpf_printk("Skip: Not interested!\n");
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";