#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string_view>

#include "llvmbpf.hpp"

using namespace bpftime;

namespace {

const unsigned char xdp_counter_bytecode[] = "\x79\x16\x00\x00\x00\x00\x00\x00"
					     "\x79\x17\x08\x00\x00\x00\x00\x00"
					     "\xb7\x01\x00\x00\x00\x00\x00\x00"
					     "\x63\x1a\xfc\xff\x00\x00\x00\x00"
					     "\xbf\xa2\x00\x00\x00\x00\x00\x00"
					     "\x07\x02\x00\x00\xfc\xff\xff\xff"
					     "\x18\x11\x00\x00\x05\x00\x00\x00"
					     "\x00\x00\x00\x00\x00\x00\x00\x00"
					     "\x85\x00\x00\x00\x01\x00\x00\x00"
					     "\xbf\x01\x00\x00\x00\x00\x00\x00"
					     "\xb7\x00\x00\x00\x02\x00\x00\x00"
					     "\x15\x01\x18\x00\x00\x00\x00\x00"
					     "\x61\x11\x00\x00\x00\x00\x00\x00"
					     "\x55\x01\x16\x00\x00\x00\x00\x00"
					     "\x18\x21\x00\x00\x06\x00\x00\x00"
					     "\x00\x00\x00\x00\x00\x00\x00\x00"
					     "\x79\x12\x00\x00\x00\x00\x00\x00"
					     "\x07\x02\x00\x00\x01\x00\x00\x00"
					     "\x7b\x21\x00\x00\x00\x00\x00\x00"
					     "\xb7\x00\x00\x00\x01\x00\x00\x00"
					     "\xbf\x61\x00\x00\x00\x00\x00\x00"
					     "\x07\x01\x00\x00\x0e\x00\x00\x00"
					     "\x2d\x71\x0d\x00\x00\x00\x00\x00"
					     "\x69\x61\x00\x00\x00\x00\x00\x00"
					     "\x69\x62\x06\x00\x00\x00\x00\x00"
					     "\x6b\x26\x00\x00\x00\x00\x00\x00"
					     "\x69\x62\x08\x00\x00\x00\x00\x00"
					     "\x69\x63\x02\x00\x00\x00\x00\x00"
					     "\x6b\x36\x08\x00\x00\x00\x00\x00"
					     "\x6b\x26\x02\x00\x00\x00\x00\x00"
					     "\x69\x62\x0a\x00\x00\x00\x00\x00"
					     "\x69\x63\x04\x00\x00\x00\x00\x00"
					     "\x6b\x36\x0a\x00\x00\x00\x00\x00"
					     "\x6b\x16\x06\x00\x00\x00\x00\x00"
					     "\x6b\x26\x04\x00\x00\x00\x00\x00"
					     "\xb7\x00\x00\x00\x03\x00\x00\x00"
					     "\x95\x00\x00\x00\x00\x00\x00\x00";

uint8_t bpf_mem[] = { 0x11, 0x22, 0x33, 0x44,
		      0x55, 0x66, 0x77, 0x88 };
uint32_t ctl_array[2] = { 0, 0 };
uint64_t cntrs_array[2] = { 0, 0 };
uint64_t lookup_helper_calls = 0;

void *bpf_map_lookup_elem(uint64_t map_handle, void *key)
{
	lookup_helper_calls++;
	const auto index = *reinterpret_cast<uint32_t *>(key);
	if (map_handle == 5 && index < 2) {
		return &ctl_array[index];
	}
	if (map_handle == 6 && index < 2) {
		return &cntrs_array[index];
	}
	return nullptr;
}

uint64_t map_val(uint64_t map_handle)
{
	if (map_handle == 5) {
		return reinterpret_cast<uint64_t>(ctl_array);
	}
	if (map_handle == 6) {
		return reinterpret_cast<uint64_t>(cntrs_array);
	}
	return 0;
}

void reset_state()
{
	ctl_array[0] = 0;
	ctl_array[1] = 0;
	cntrs_array[0] = 0;
	cntrs_array[1] = 0;
	lookup_helper_calls = 0;
}

void warmup(precompiled_ebpf_function func)
{
	for (size_t i = 0; i < 10000; i++) {
		(void)func(bpf_mem, sizeof(bpf_mem));
	}
}

int run_once(bool enable_inline, uint64_t iterations)
{
	reset_state();

	llvmbpf_vm vm;
	if (vm.load_code(xdp_counter_bytecode,
			 sizeof(xdp_counter_bytecode) - 1) != 0) {
		std::cerr << vm.get_error_message() << std::endl;
		return 1;
	}
	if (vm.register_external_function(1, "bpf_map_lookup_elem",
					  (void *)bpf_map_lookup_elem) != 0) {
		std::cerr << vm.get_error_message() << std::endl;
		return 1;
	}
	if (enable_inline) {
		if (vm.register_array_map(array_map_descriptor{
				.map_handle = 5,
				.value_base =
					reinterpret_cast<uint64_t>(ctl_array),
				.value_size = sizeof(uint32_t),
				.value_stride = sizeof(uint32_t),
				.max_entries = 2,
			}) != 0) {
			std::cerr << vm.get_error_message() << std::endl;
			return 1;
		}
	}
	vm.set_lddw_helpers(nullptr, nullptr, map_val, nullptr, nullptr);

	auto func = vm.compile();
	if (!func.has_value()) {
		std::cerr << vm.get_error_message() << std::endl;
		return 1;
	}

	warmup(func.value());
	reset_state();

	const auto start = std::chrono::steady_clock::now();
	uint64_t last_result = 0;
	for (uint64_t i = 0; i < iterations; i++) {
		last_result = func.value()(bpf_mem, sizeof(bpf_mem));
	}
	const auto end = std::chrono::steady_clock::now();
	const auto total_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
		end - start);

	assert(last_result == 1);
	assert(cntrs_array[0] == iterations);

	const double ns_per_iter =
		static_cast<double>(total_ns.count()) / iterations;
	std::cout << "mode=" << (enable_inline ? "inline" : "baseline")
		  << " iterations=" << iterations
		  << " total_ns=" << total_ns.count()
		  << " ns_per_iter=" << ns_per_iter
		  << " helper_calls=" << lookup_helper_calls
		  << " counter=" << cntrs_array[0] << std::endl;
	return 0;
}

} // namespace

int main(int argc, char *argv[])
{
	bool enable_inline = false;
	uint64_t iterations = 5000000;

	for (int i = 1; i < argc; i++) {
		const std::string_view arg(argv[i]);
		if (arg == "--inline") {
			enable_inline = true;
			continue;
		}
		iterations = std::strtoull(argv[i], nullptr, 10);
	}

	if (iterations == 0) {
		std::cerr << "iterations must be non-zero" << std::endl;
		return 1;
	}

	return run_once(enable_inline, iterations);
}
