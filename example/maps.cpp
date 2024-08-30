#include <cstdint>
#include <iostream>
#include <ostream>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>
#include <cassert>
#include "llvmbpf.hpp"

using namespace bpftime;
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

uint8_t bpf_mem[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

uint32_t ctl_array[2] = { 0, 0 };
uint64_t cntrs_array[2] = { 0, 0 };

void *bpf_map_lookup_elem(uint64_t map_fd, void *key)
{
	std::cout << "bpf_map_lookup_elem " << map_fd << std::endl;
	if (map_fd == 5) {
		return &ctl_array[*(uint32_t *)key];
	} else if (map_fd == 6) {
		return &cntrs_array[*(uint32_t *)key];
	} else {
		return nullptr;
	}
	return 0;
}

uint64_t map_by_fd(uint32_t fd)
{
	std::cout << "map_by_fd " << fd << std::endl;
	return fd;
}

uint64_t map_val(uint64_t val)
{
	std::cout << "map_val " << val << std::endl;
	if (val == 5) {
		return (uint64_t)(void *)ctl_array;
	} else if (val == 6) {
		return (uint64_t)(void *)cntrs_array;
	} else {
		return 0;
	}
}

int main(int argc, char *argv[])
{
	auto code = xdp_counter_bytecode;
	size_t code_len = sizeof(xdp_counter_bytecode) - 1;
	uint64_t res = 0;
	llvmbpf_vm vm;
	std::cout << "running ebpf prog, code len: " << code_len << std::endl;

	res = vm.load_code(code, code_len);
	if (res) {
		std::cout << vm.get_error_message() << std::endl;
		exit(1);
	}
	vm.register_external_function(1, "bpf_map_lookup_elem",
				      (void *)bpf_map_lookup_elem);
	// set the lddw helpers for accessing maps
	vm.set_lddw_helpers(map_by_fd, nullptr, map_val, nullptr, nullptr);
	auto func = vm.compile();
	if (!func) {
		std::cout << vm.get_error_message() << std::endl;
		exit(1);
	}
	// Map value (counter) should be 0
	std::cout << "cntrs_array[0] = " << cntrs_array[0] << std::endl;
	int err = vm.exec(&bpf_mem, sizeof(bpf_mem), res);
	assert(err == 0 && cntrs_array[0] == 1);
	std::cout << "\nreturn value = " << res << std::endl;
	// counter should be 1
	std::cout << "cntrs_array[0] = " << cntrs_array[0] << std::endl;

	err = vm.exec(&bpf_mem, sizeof(bpf_mem), res);
	assert(err == 0 && cntrs_array[0] == 2);
	std::cout << "\nreturn value = " << res << std::endl;
	// counter should be 2
	std::cout << "cntrs_array[0] = " << cntrs_array[0] << std::endl;

	// Change the value of the control array can change the return value
	ctl_array[0] = 1;
	err = vm.exec(&bpf_mem, sizeof(bpf_mem), res);
	assert(err == 0);
	std::cout << "\nreturn value = " << res << std::endl;
	return 0;
}
