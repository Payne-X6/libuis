/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <string.h>

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

struct ipv4_lpm_value {
	__u16 port;
	__u8 addr[4];
};

struct ipv4_lpm_key {
	__u32 prefixlen;
	struct ipv4_lpm_value data;
};

struct ipv6_lpm_value {
	__u16 port;
	__u8 addr[16];
};

struct ipv6_lpm_key {
	__u32 prefixlen;
	struct ipv6_lpm_value data;
};

struct ip_port_lpm_key {
	__u32 prefixlen;
	__u16 data;
};

struct ip_lpm_key {
	__u32 prefixlen;
	union {
		__u16 port;
		struct ipv4_lpm_value ipv4;
		struct ipv6_lpm_value ipv6;
	} data;
};

struct {
		__uint(type, BPF_MAP_TYPE_LPM_TRIE);
		__type(key, struct ipv4_lpm_key);
		__type(value, struct ipv4_lpm_value);
		__uint(map_flags, BPF_F_NO_PREALLOC);
		__uint(max_entries, 255);
} ipv4_lpm_map SEC(".maps");

struct {
		__uint(type, BPF_MAP_TYPE_LPM_TRIE);
		__type(key, struct ipv6_lpm_key);
		__type(value, struct ipv6_lpm_value);
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
__u32 stats_add_and_ret(__u32 code, __u64 bytes)
{
	struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &code);
	if (rec == NULL) {
		return code;
	}
	rec->rx_packets++;
	rec->rx_bytes += bytes;
	return code;
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

	// TODO Validate IPv6
	if (ip6h->version != 6) {
		return -1;
	}

	view->begin += hdrsize;

	int nexthdr = ip6h->nexthdr;
	struct ipv6_opt_hdr *hdr_ext = view->begin;
	hdrsize = sizeof(*hdr_ext);
	if (view->begin + hdrsize > view->end) {
		return -1;
	}
	// while(view->begin < view->end) {
	// 	switch (nexthdr) {
	// 	case IPPROTO_HOPOPTS:
	// 	case IPPROTO_DSTOPTS:
	// 	case IPPROTO_ROUTING:
	// 	case IPPROTO_MH:
	// 		//TODO Validate
	// 		view->begin += (hdr_ext->hdrlen + 1) * 8;
	// 		nexthdr = hdr_ext->nexthdr;
	// 		break;
	// 	case IPPROTO_AH:
	// 		//TODO Validate
	// 		view->begin += (hdr_ext->hdrlen + 2) * 4;
	// 		nexthdr = hdr_ext->nexthdr;
	// 		break;
	// 	case IPPROTO_FRAGMENT:
	// 		//TODO Validate
	// 		view->begin += 8;
	// 		nexthdr = hdr_ext->nexthdr;
	// 		break;
	// 	default:
	// 		/* Found a header that is not an IPv6 extension header */
	// 		goto end;
	// 	}
	// }
	
end:
	*ip6hdr = ip6h;

	return 0;
}


static __always_inline
int parse_udphdr(view_t *view, struct udphdr **udphdr)
{
	struct udphdr *udp = view->begin;
	int hdrsize = sizeof(*udphdr);
	if (view->begin + hdrsize > view->end) {
		return -1;
	}

	// TODO Validate UDP
	volatile unsigned short len = bpf_ntohs(udp->len);
	if (len <= 0 || view->begin + len > view->end) {
		return -1;
	}

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

	// TODO Validate TCP
	// hdrsize = tcp->doff * 4;
	// if (hdrsize < sizeof(*tcphdr)) {
	// 	return -1;
	// }
	// if (view->begin + hdrsize > view->end) {
	// 	return -1;
	// }

	view->begin += hdrsize;
	*tcphdr = tcp;

	return 0;
}

SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
	view_t view = {
		.end = (void *)(long)ctx->data_end,
		.begin = (void *)(long)ctx->data
	};

	struct ethhdr *eth = NULL;
	int ret = parse_ethhdr(&view, &eth);
	if (ret) {
		bpf_printk("Skip: Not ETH header!\n");
		return stats_add_and_ret(XDP_PASS, ctx->data_end - ctx->data);
	}

	unsigned char ip_proto;
	struct ip_lpm_key dest;
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = NULL;
		ret = parse_iphdr(&view, &ip);
		if (ret) {
			bpf_printk("Error: Malformed IPv4 header!\n");
			return stats_add_and_ret(XDP_DROP, ctx->data_end - ctx->data);
		}
		ip_proto = ip->protocol;
	
		// TODO revisit
		dest.prefixlen = sizeof(struct ipv4_lpm_value) * 8;
		memcpy(dest.data.ipv4.addr, &ip->addrs.daddr, sizeof(dest.data.ipv4.addr));
		bpf_printk("IPv4: %d.%d.%d.%d", dest.data.ipv4.addr[0], dest.data.ipv4.addr[1], dest.data.ipv4.addr[2], dest.data.ipv4.addr[3]);
	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ipv6 = NULL;
		ret = parse_ip6hdr(&view, &ipv6);
		if (ret) {
			bpf_printk("Error: Malformed IPv6 header!\n");
			return stats_add_and_ret(XDP_DROP, ctx->data_end - ctx->data);
		}
		// TODO revisit - chain
		ip_proto = ipv6->nexthdr;
	
		// TODO revisit
		dest.prefixlen = sizeof(struct ipv6_lpm_value) * 8;
		memcpy(dest.data.ipv6.addr, &ipv6->addrs.daddr.in6_u.u6_addr8, sizeof(dest.data.ipv6.addr));
	} else {
		bpf_printk("Skip: Not IPvX Header!\n");
		return stats_add_and_ret(XDP_PASS, ctx->data_end - ctx->data);
	}

	if (ip_proto == IPPROTO_UDP) {
		struct udphdr *udp;
		ret = parse_udphdr(&view, &udp);
		if (ret) {
			bpf_printk("Error: Malformed UDP header!\n");
			return stats_add_and_ret(XDP_DROP, ctx->data_end - ctx->data);
		}

		// TODO port
		dest.data.port = udp->dest;
	} else if (ip_proto == IPPROTO_TCP) {
		struct tcphdr *tcp;
		int ret = parse_tcphdr(&view, &tcp);
		if (ret < 0) {
			bpf_printk("Error: Malformed TCP header!\n");
			return stats_add_and_ret(XDP_DROP, ctx->data_end - ctx->data);
		}
		// TODO port
		dest.data.port = tcp->dest;
		
	} else {
		bpf_printk("Skip: Not UDP/TCP header!\n");
		return stats_add_and_ret(XDP_PASS, ctx->data_end - ctx->data);
	}

	unsigned int rx_queue_idx = ctx->rx_queue_index;
	if (bpf_map_lookup_elem(&xsks_map, &rx_queue_idx)) {
		// // Lookup table
		if (eth->h_proto == bpf_htons(ETH_P_IP)) {
			struct ipv4_lpm_value *find = bpf_map_lookup_elem(&ipv4_lpm_map, &dest);
			if (find == NULL) {
				return stats_add_and_ret(XDP_PASS, ctx->data_end - ctx->data);
			}
			if (find->port != dest.data.port) {
				return stats_add_and_ret(XDP_PASS, ctx->data_end - ctx->data);
			}
		} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
			struct ipv6_lpm_value *find = bpf_map_lookup_elem(&ipv6_lpm_map, &dest);
			if (find == NULL) {
				return stats_add_and_ret(XDP_PASS, ctx->data_end - ctx->data);
			}
			if (find->port != dest.data.port) {
				return stats_add_and_ret(XDP_PASS, ctx->data_end - ctx->data);
			}
		}
		// Redirect
		ret = bpf_redirect_map(&xsks_map, rx_queue_idx, 0);
		return stats_add_and_ret(ret, ctx->data_end - ctx->data);
	}

	bpf_printk("Skip: Not interested!\n");
	return stats_add_and_ret(XDP_PASS, ctx->data_end - ctx->data);
}

char _license[] SEC("license") = "GPL";