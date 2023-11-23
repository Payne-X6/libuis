#include "link.h"

namespace uis {

void Link_deleter::operator() (bpf_link *link) const
{
	int ret = bpf_link__detach(link);
	if (ret < 0) {
		printf("Error: Detach XDP interface handle\n");
	}
	ret = bpf_link__destroy(link);
	if (ret < 0) {
		printf("Error: Destroy XDP interface handle\n");
	}

}

Link make_link(bpf_link *link)
{
    return Link(link, Link_deleter{});
}

}