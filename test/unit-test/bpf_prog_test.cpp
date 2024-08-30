#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <iostream>
#include "llvmbpf.hpp"
#include "bpf_progs.h"

extern "C" uint64_t add_func(uint64_t a, uint64_t b, uint64_t, uint64_t,
			     uint64_t)
{
	return a + b;
}

TEST_CASE("Test aot compilation for extenal function")
{
	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.register_external_function(3, "add", (void *)add_func) == 0);
	REQUIRE(vm.load_code((const void *)bpf_function_call_add,
			     sizeof(bpf_function_call_add) - 1) == 0);
	uint64_t ret = 0;
	uint64_t mem = 0;

	REQUIRE(vm.exec(&mem, sizeof(mem), ret) == 0);
	REQUIRE(ret == 4);
}
