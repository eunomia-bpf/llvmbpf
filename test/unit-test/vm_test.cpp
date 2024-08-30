#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <iostream>
#include "llvmbpf.hpp"

/*

int test()
{
	int a = 1;
	int b = 2;
	if (a + b > 2) {
		return 4;
	} else {
		return 5;
	}
}

0 mov r1, 0x1
1 stxw [r10-8], r1
2 mov r1, 0x2
3 stxw [r10-12], r1
4 ldxw r1, [r10-8]
5 ldxw r2, [r10-12]
6 add r1, r2
7 lsh r1, 0x20
8 arsh r1, 0x20
9 mov r2, 0x3
10 jsgt r2, r1, +4

11 ja +0

12 mov r1, 0x4
13 stxw [r10-4], r1
14 ja +3

15 mov r1, 0x5
16 stxw [r10-4], r1
17 ja +0

18 ldxw r0, [r10-4]
19 exit
20
*/

const unsigned char simple_cond_1[] =
	"\xb7\x01\x00\x00\x01\x00\x00\x00\x63\x1a\xf8\xff\x00\x00\x00\x00\xb7\x01\x00\x00\x02\x00\x00\x00\x63"
	"\x1a\xf4\xff\x00\x00\x00\x00\x61\xa1\xf8\xff\x00\x00\x00\x00\x61\xa2\xf4\xff\x00\x00\x00\x00\x0f\x21"
	"\x00\x00\x00\x00\x00\x00\x67\x01\x00\x00\x20\x00\x00\x00\xc7\x01\x00\x00\x20\x00\x00\x00\xb7\x02\x00"
	"\x00\x03\x00\x00\x00\x6d\x12\x04\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\xb7\x01\x00\x00"
	"\x04\x00\x00\x00\x63\x1a\xfc\xff\x00\x00\x00\x00\x05\x00\x03\x00\x00\x00\x00\x00\xb7\x01\x00\x00\x05"
	"\x00\x00\x00\x63\x1a\xfc\xff\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x61\xa0\xfc\xff\x00\x00"
	"\x00\x00\x95\x00\x00\x00\x00\x00\x00\x00";

// Example test case for simple condition
TEST_CASE("Test simple cond")
{
	bpftime::llvmbpf_vm vm;

	SECTION("Execute without loading code")
	{
		vm.unload_code();
		uint64_t ret = 0;
		uint64_t mem = 0;

		REQUIRE(vm.exec(&mem, sizeof(mem), ret) != 0);
		REQUIRE(vm.get_error_message() ==
			"Unable to compile eBPF program");
	}

	REQUIRE(vm.load_code((const void *)simple_cond_1,
			     sizeof(simple_cond_1) - 1) == 0);

	SECTION("Load valid code and execute")
	{
		uint64_t ret = 0;
		uint64_t mem = 0;

		REQUIRE(vm.exec(&mem, sizeof(mem), ret) == 0);
		REQUIRE(ret == 4);
	}

	SECTION("Load code with invalid length")
	{
		REQUIRE(vm.load_code((const void *)simple_cond_1,
				     sizeof(simple_cond_1) - 2) != 0);
		REQUIRE(vm.get_error_message() ==
			"Code len must be a multiple of 8");
	}

	SECTION("Execute unloading code")
	{
		vm.unload_code();
		uint64_t ret = 0;
		uint64_t mem = 0;

		REQUIRE(vm.exec(&mem, sizeof(mem), ret) != 0);
		REQUIRE(vm.get_error_message() ==
			"Unable to compile eBPF program");
	}
}

TEST_CASE("Test external function registration")
{
	bpftime::llvmbpf_vm vm;

	SECTION("Register valid external function")
	{
		void *dummy_function = (void *)0xdeadbeef;
		REQUIRE(vm.register_external_function(0, "test_func",
						      dummy_function) == 0);
	}

	SECTION("Register external function with out of bounds index")
	{
		void *dummy_function = (void *)0xdeadbeef;
		REQUIRE(vm.register_external_function(MAX_EXT_FUNCS + 1,
						      "test_func",
						      dummy_function) != 0);
		REQUIRE(vm.get_error_message() == "Index too large");
	}

	SECTION("Register external function with existing index")
	{
		void *dummy_function = (void *)0xdeadbeef;
		REQUIRE(vm.register_external_function(0, "test_func",
						      dummy_function) == 0);
		REQUIRE(vm.register_external_function(0, "test_func",
						      dummy_function) != 0);
		REQUIRE(vm.get_error_message() == "Already defined");
	}
}

TEST_CASE("Test AOT compilation and loading")
{
	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.load_code((const void *)simple_cond_1,
			     sizeof(simple_cond_1) - 1) == 0);

	SECTION("AOT compile and load")
	{
		auto object_code_opt = vm.do_aot_compile(true);
		REQUIRE(object_code_opt.has_value()); // Ensure that the
						      // optional contains a
						      // value
		auto &object_code = object_code_opt.value(); // Extract the
							     // vector from the
							     // optional
		REQUIRE(!object_code.empty());

		auto func = vm.load_aot_object(object_code);
		REQUIRE(func.has_value());
	}

	SECTION("Load AOT object after JIT compilation")
	{
		auto object_code_opt = vm.do_aot_compile(false);
		REQUIRE(object_code_opt.has_value());
		auto &object_code = object_code_opt.value();
		REQUIRE(!object_code.empty());

		auto func = vm.load_aot_object(object_code);
		REQUIRE(func.has_value());

		// Attempt to load another object after JIT compilation
		auto another_object_code_opt = vm.do_aot_compile(true);
		REQUIRE(another_object_code_opt.has_value());
		auto &another_object_code = another_object_code_opt.value();
		REQUIRE(!another_object_code.empty());

		auto func2 = vm.load_aot_object(another_object_code);
		REQUIRE(!func2.has_value());
		REQUIRE(vm.get_error_message() == "Already compiled");
	}
}

TEST_CASE("Test loading and executing incorrect code") {
    bpftime::llvmbpf_vm vm;

    // Example of incorrect or malformed eBPF instructions
    const unsigned char wrong_code[] = "\x00\x00\x00\x00\x00\x00\x00\x00";  // Invalid eBPF instruction

    SECTION("Execute without valid code") {
        vm.unload_code();  // Ensure no code is loaded
        uint64_t ret = 0;
        uint64_t mem = 0;

        REQUIRE(vm.exec(&mem, sizeof(mem), ret) != 0);
        REQUIRE(vm.get_error_message() == "Unable to compile eBPF program");  // Assuming this is the error message
    }

    SECTION("Load and execute incorrect code") {
        REQUIRE(vm.load_code((const void *)wrong_code, sizeof(wrong_code) - 1) == 0);

        uint64_t ret = 0;
        uint64_t mem = 0;

        REQUIRE(vm.exec(&mem, sizeof(mem), ret) != 0);  // Execution should fail
        REQUIRE(vm.get_error_message() == "Unable to compile eBPF program");  // Assuming this error message
    }
}
