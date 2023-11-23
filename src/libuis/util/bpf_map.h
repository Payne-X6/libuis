#pragma once

#include <iterator>
#include <utility>
#include <vector>
#include <stdexcept>
#include <bpf/libbpf.h>

namespace uis {

template<typename Key, typename V>
class Bpf_Map {
private:
	bpf_map *obj;
public:
	class ValueRef;
	class Iterator;

	using key_type = Key;
	using mapped_type = V;
	using value_type = std::pair<const Key, V>;
	using reference = ValueRef;
	using const_reference = const ValueRef;
	using iterator = Iterator;
	using const_iterator = const Iterator;
	using node_type = ValueRef;

	class ValueRef {
	private:
		Bpf_Map *map;
		mutable Key key;

	public:
		ValueRef(Bpf_Map* map, const Key& key) : map(map), key(key) {}

		// Conversion operator to get the value when used in expressions
		operator V() const {
			const int ncpus = libbpf_num_possible_cpus();
			std::vector<V> vals;
			vals.resize(ncpus);
			int ret = bpf_map__lookup_elem(map->obj, &key, sizeof(key), vals.data(), sizeof(V) * ncpus, 0);
			if (ret) {
				throw std::runtime_error("Error looking up element in Bpf_Map");
			}
			V val = { 0 };
			for (auto &&tv : vals) {
				val.rx_packets += tv.rx_packets;
				val.rx_bytes += tv.rx_bytes;
			}
			return val;
		}

		// Assignment operator to update the value in the map
		ValueRef& operator=(const V& new_value) {
			int ret = bpf_map__update_elem(map->obj, &key, sizeof(key), &new_value, sizeof(V), 0);
			if (ret) {
				throw std::runtime_error("Error updating element in Bpf_Map");
			}
			return *this;
		}

		friend class Bpf_Map;
	};

	class Iterator {
	private:
		Bpf_Map* map;
		mutable Key key;

	public:
		Iterator() : map(nullptr) {}
		Iterator(Bpf_Map* map, const Key& key) : map(map), key(key) {}

		operator ValueRef() const {
			return ValueRef(map, key);
		}

		// Dereference operator to get the ValueRef
		ValueRef operator*() const {
			return ValueRef(map, key);
		}

		Iterator& operator++() {
			int ret = bpf_map__get_next_key(map->obj, &key, &key, sizeof(key));
			switch (ret) {
				case -ENOENT:
					map = nullptr;
					[[fallthrough]];
				case 0:
					return *this;
				default:
					throw std::runtime_error("Error iterating Bpf_Map");
			}
		}

		bool operator==(const Iterator& other) const {
			if (map == nullptr) {
				return other.map == nullptr;
			}
			return (map == other.map) && (key == other.key);
		}

		bool operator!=(const Iterator& other) const {
			return !(*this == other);
		}

		friend class Bpf_Map;
	};

	Bpf_Map() = delete;
	Bpf_Map(bpf_map* obj) : obj(obj) {}
	Bpf_Map(const Bpf_Map& other) : obj(other.obj) {}
	Bpf_Map& operator=(const Bpf_Map& other) {
		obj = other.obj;
		return *this;
	}
	Bpf_Map(Bpf_Map&& other) noexcept : obj(std::exchange(other.obj, nullptr)) {}
	Bpf_Map& operator=(Bpf_Map&& other) noexcept {
		obj = std::exchange(other.obj, nullptr);
		return *this;
	}

	reference operator[](const key_type& key) const {
		return reference(obj, key);
	}

	iterator begin() {
		Key key;
		int ret = bpf_map__get_next_key(obj, nullptr, &key, sizeof(key));
		switch (ret) {
		case -ENOENT:
			return iterator();
		case 0:
			return iterator(this, key);
		default:
			throw std::runtime_error("Error getting the first key in Bpf_Map");
		}
	}

	iterator end() {
		return iterator();
	}

};

}  // namespace uis