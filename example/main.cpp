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
#include "bpf_progs.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/TargetSelect.h"
#include "llvmbpf.hpp"

using namespace llvm;
using namespace bpftime;

struct ebpf_inst;

#define sizeof_code(code) (sizeof(code) - 1)

typedef unsigned int (*kernel_fn)(const void *ctx,
				  const struct ebpf_inst *insn);

char *errmsg;

uint64_t ffi_print_func(uint64_t a, uint64_t _b, uint64_t _c, uint64_t _d,
			uint64_t _e)
{
	std::cout << (const char *)a << std::endl;
	return 0;
}
uint64_t ffi_add_func(uint64_t a, uint64_t b, uint64_t _c, uint64_t _d,
		      uint64_t _e)
{
	return a + b;
}

uint64_t ffi_print_integer(uint64_t a, uint64_t b, uint64_t _c, uint64_t _d,
			   uint64_t _e)
{
	std::cout << a << " -> " << b << " | " << std::endl;
	return 0;
}

uint8_t bpf_mem[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

void run_ebpf_prog(const void *code, size_t code_len) {
	uint64_t res = 0;
	bpftime_llvm_jit_vm vm;
	printf("running ebpf prog, code len: %zd\n", code_len);

	res = vm.load_code(code, code_len);
	if (res) {
		fprintf(stderr, "Failed to load: %s\n",
			vm.get_error_message().c_str());
		return;
	}
	vm.register_external_function(2, "print", (void *)ffi_print_func);
	vm.register_external_function(3, "add", (void *)ffi_add_func);
	vm.register_external_function(4, "print_integer",
				      (void *)ffi_print_integer);
	auto func = vm.compile();
	if (!func) {
		fprintf(stderr, "Failed to compile: %s\n",
			vm.get_error_message().c_str());
		return;
	}
	int err = vm.exec(&bpf_mem, sizeof(bpf_mem), res);
	if (err != 0) {
		fprintf(stderr, "Failed to exec: %s\n", errmsg);
		return;
	}
	printf("res = %" PRIu64 "\n", res);
}

int main(int argc, char *argv[])
{	
	run_ebpf_prog(bpf_add_mem_64_bit, sizeof(bpf_add_mem_64_bit));
	run_ebpf_prog(bpf_mul_64_bit, sizeof(bpf_mul_64_bit));
	// here we use string for the code
	run_ebpf_prog(bpf_function_call_print, sizeof(bpf_function_call_print) - 1);
	return 0;
}
