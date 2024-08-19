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
#include "llvmbpf.hpp"

using namespace bpftime;

uint64_t ffi_print_func(uint64_t a, uint64_t _b, uint64_t _c, uint64_t _d,
			uint64_t _e)
{
	std::cout << (const char *)a << std::endl;
	return 0;
}

uint8_t bpf_mem[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

/*
int add_test(struct data *d, int sz) {
	return d->a + d->b;
}
in 64 bit:
*/
const unsigned char bpf_add_mem_64_bit[] = {
	0x7b, 0x1a, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00, 0x63, 0x2a, 0xf4, 0xff,
	0x00, 0x00, 0x00, 0x00, 0x79, 0xa1, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00,
	0x61, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x61, 0x11, 0x04, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x0f, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/*
int mul_test() {
	int a = 1;
	int b = 2;
	int c = a * b;
	return c;
}
in 64 bit: using clang -target bpf -c mul.bpf.c -o mul.bpf.o to compile
*/
const unsigned char bpf_mul_64_bit[] = {
	0xb7, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x63, 0x1a, 0xfc, 0xff,
	0x00, 0x00, 0x00, 0x00, 0xb7, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x63, 0x1a, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00, 0x61, 0xa1, 0xfc, 0xff,
	0x00, 0x00, 0x00, 0x00, 0x61, 0xa2, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00,
	0x2f, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x1a, 0xf4, 0xff,
	0x00, 0x00, 0x00, 0x00, 0x61, 0xa0, 0xf4, 0xff, 0x00, 0x00, 0x00, 0x00,
	0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// static void (*print_bpf)(char *str) = (void *)0x2;
// int print_and_add1(struct data *d, int sz) {
// 	char a[] = "hello";
// 	print_bpf(a);
//  	return 0;
// }
const unsigned char bpf_function_call_print[] =
	"\xb7\x01\x00\x00\x6f\x00\x00\x00"
	"\x6b\x1a\xfc\xff\x00\x00\x00\x00"
	"\xb7\x01\x00\x00\x68\x65\x6c\x6c"
	"\x63\x1a\xf8\xff\x00\x00\x00\x00"
	"\xbf\xa1\x00\x00\x00\x00\x00\x00"
	"\x07\x01\x00\x00\xf8\xff\xff\xff"
	"\x85\x00\x00\x00\x02\x00\x00\x00"
	"\xb7\x00\x00\x00\x00\x00\x00\x00"
	"\x95\x00\x00\x00\x00\x00\x00\x00";

void run_ebpf_prog(const void *code, size_t code_len)
{
	uint64_t res = 0;
	llvmbpf_vm vm;
	printf("running ebpf prog, code len: %zd\n", code_len);

	res = vm.load_code(code, code_len);
	if (res) {
		fprintf(stderr, "Failed to load: %s\n",
			vm.get_error_message().c_str());
		exit(1);
	}
	vm.register_external_function(2, "print", (void *)ffi_print_func);
	auto func = vm.compile();
	if (!func) {
		fprintf(stderr, "Failed to compile: %s\n",
			vm.get_error_message().c_str());
		exit(1);
	}
	int err = vm.exec(&bpf_mem, sizeof(bpf_mem), res);
	if (err != 0) {
		fprintf(stderr, "Failed to exec.");
		exit(1);
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
