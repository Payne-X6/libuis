#include "uis.h"

#include <unordered_map>

#include <net/if.h>

#include "bpf.h"
#include "global_ctx.h"
#include "common/defines.h"
#include "common/stats.h"

namespace uis {

int attach(const char *interface)
{
	int ifindex = if_nametoindex("lo");
	if(ifindex < 0) {
		return EXIT_FAILURE;
	}
	return g_ctx().attach(ifindex);
}

void print_stats()
{
	auto map = g_ctx().attach_map<__u32, datarec>("xdp_stats_map");
	datarec prev[XDP_ACTION_MAX], actual[XDP_ACTION_MAX];
	int idx = 0;
	for (auto it = map.begin(); it != map.end(); ++it) {
		actual[idx] = *it;
		idx++;
	}
	for (unsigned rounds = 10; rounds--;) {
		sleep(1);
		int idx = 0;
		for (auto it = map.begin(); it != map.end(); ++it) {
			prev[idx] = actual[idx];
			actual[idx] = *it;
			printf("%lld %lld\n", actual[idx].rx_packets - prev[idx].rx_packets, actual[idx].rx_bytes - prev[idx].rx_bytes);
			idx++;
		}
		printf("-----\n");
	}
}

}