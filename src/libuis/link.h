#pragma once

#include <memory>
#include <bpf/libbpf.h>

namespace uis {

struct Link_deleter {
void operator() (bpf_link *link) const;
};

using Link = std::shared_ptr<bpf_link>;

Link make_link(bpf_link *link);

}