#include "global_ctx.h"

#include <exception>
#include <mutex>
#include <xdp/xsk.h>

#include "common/defines.h"
#include "common/stats.h"
#include "util/xsk_socket.h"

namespace uis {

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	// struct xsk_socket *xsk;

	uint64_t umem_frame_addr[4096];
	uint32_t umem_frame_free;

	uint32_t outstanding_tx;
};

Global_context::Global_context()
{
	filter = bpf::open_and_load();
	if (not filter) {
		throw std::exception();
	}

	int ret = bpf::attach(filter);
	if (ret < 0) {
		bpf::destroy(filter);
		filter = NULL;
		throw std::exception();
	}
}

Global_context::~Global_context()
{
	interfaces.erase(interfaces.begin(), interfaces.end());
	bpf::detach(filter);
	bpf::destroy(filter);
	filter = nullptr;
}

#define INVALID_UMEM_FRAME UINT64_MAX

// #include <poll.h>

int Global_context::attach(int ifindex)
{
	// If already exists
	std::unique_lock rw_lock(mutex);
	if (interfaces.contains(ifindex)) {
		return EXIT_SUCCESS;
	}

	// Attach BPF filter to network interface
	auto link = bpf_program__attach_xdp(filter->progs.xdp_filter, ifindex);
	if (not link) {
		return EXIT_FAILURE;
	}

	// Store interface handle
	interfaces[ifindex] = make_link(link);

	Xsk_Socket sock(filter->obj);

	return EXIT_SUCCESS;
}

Global_context &g_ctx()
{
	static Global_context ctx;
	return ctx;
}

}