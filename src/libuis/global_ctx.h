#pragma once

#include <cassert>
#include <memory>
#include <shared_mutex>
#include <unordered_map>

#include "bpf.h"
#include "link.h"
#include "util/bpf_map.h"

namespace uis {

class Global_context final {
private:
    bpf *filter;
    std::unordered_map<int, Link> interfaces;
    std::shared_mutex mutex;
public:
    Global_context();
    Global_context(const Global_context &) = delete;
    Global_context &operator=(const Global_context &) = delete;
    Global_context(Global_context &&) = delete;
    Global_context &operator=(Global_context &&) = delete;
    ~Global_context();

    int attach(int interface);

    template<typename Key, typename V>
    Bpf_Map<Key, V> attach_map(const char *name)
    {
	    auto map_handle = bpf_object__find_map_by_name(filter->obj, name);
	    if (not map_handle) {
		    std::runtime_error("Cannot find map by name");
	    }

        assert(bpf_map__key_size(map_handle) == sizeof(Key));
        assert(bpf_map__value_size(map_handle) == sizeof(V));

        return Bpf_Map<Key, V>(map_handle);
    }
};

Global_context &g_ctx();

}