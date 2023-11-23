#pragma once

#include <vector>

#include <poll.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>

namespace uis {
class Xsk_Umem {
private:
	xsk_ring_cons cq;
	void *buffer;
public:
	xsk_ring_prod fq;
	xsk_umem *umem;

	Xsk_Umem(size_t size);
	~Xsk_Umem();
};


Xsk_Umem::Xsk_Umem(size_t size)
{
	int ret = posix_memalign(&buffer, getpagesize(), size);
	if (ret) {

	}
	ret = xsk_umem__create(&umem, buffer, size, &fq, &cq, NULL);
	if (ret) {

	}
}

Xsk_Umem::~Xsk_Umem()
{
	xsk_umem__delete(umem);
	free(buffer);
	buffer = nullptr;
}

class Xsk_Socket
{
private:
public:
    Xsk_Socket(const bpf_object *obj);
    ~Xsk_Socket();
};

Xsk_Socket::Xsk_Socket(const bpf_object *obj)
{
    auto xsks_map_fd = bpf_object__find_map_fd_by_name(obj, "xsks_map");
    if (xsks_map_fd < 0) {
		//TODO
	}
    Xsk_Umem umem(4096 * XSK_UMEM__DEFAULT_FRAME_SIZE);
    xsk_ring_prod xsk_rx;
    xsk_ring_cons xsk_tx;

    xsk_socket_config xsk_cfg;
	xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	xsk_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
	// xsk_cfg.xdp_flags = cfg->xdp_flags;
	// xsk_cfg.bind_flags = cfg->xsk_bind_flags;

    xsk_socket *xsk;
	auto ret = xsk_socket__create(&xsk, "lo", 0, umem.umem, &xsk_tx, &xsk_rx, &xsk_cfg);
	if (ret) {
        //TODO
    }
	ret = xsk_socket__update_xskmap(xsk, xsks_map_fd);
	if (ret) {
        //TODO
	}

	uint32_t idx;
	auto uret = xsk_ring_prod__reserve(&umem.fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
	if (uret != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
        //TODO
    }
    
    uint64_t umem_frame_addr[4096];
	for (auto i = 0; i < 4096; i++) {
		umem_frame_addr[i] = i * XSK_UMEM__DEFAULT_FRAME_SIZE;
    }
	auto umem_frame_free = 4096;
	for (auto i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++) {
        uint64_t frame;
	    if (umem_frame_free == 0) {
		    *xsk_ring_prod__fill_addr(&umem.fq, idx++) = UINT64_MAX;
            continue;
        }
        frame = umem_frame_addr[--umem_frame_free];
	    umem_frame_addr[umem_frame_free] = UINT64_MAX;
	    *xsk_ring_prod__fill_addr(&umem.fq, idx++) = frame;
    }

	xsk_ring_prod__submit(&umem.fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);
    struct pollfd fds[1];
	fds[0].fd = xsk_socket__fd(xsk);
	fds[0].events = POLLIN;

	// while(!global_exit) {
	// 	if (cfg->xsk_poll_mode) {
	ret = poll(fds, sizeof(fds)/sizeof(*fds), -1);
	if (ret < 0) {
		printf("error");
        //TODO
    } else if (ret > 0) {
		printf("received");
	}
	// 			continue;
	// 	}
	// 	handle_receive_packets(xsk_socket);
	// }
}

Xsk_Socket::~Xsk_Socket()
{
}

}