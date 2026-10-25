#include "llvmbpf.hpp"
#include <cstdint>

extern "C" __attribute__((visibility("default"))) int llvmbpf_test_run()
{
	// r0 = 42; exit
	const uint8_t code[] = { 0xb7, 0, 0, 0, 42, 0, 0, 0,
				 0x95, 0, 0, 0, 0, 0, 0, 0 };
	try {
		bpftime::llvmbpf_vm jit;
		if (jit.load_code(code, sizeof(code)) != 0)
			return 1;
		uint64_t result = 0;
		if (jit.exec(nullptr, 0, result) != 0 || result != 42)
			return 2;
		bpftime::llvmbpf_vm compiler;
		if (compiler.load_code(code, sizeof(code)) != 0)
			return 3;
		auto object = compiler.do_aot_compile(false);
		if (!object || object->empty())
			return 4;
		bpftime::llvmbpf_vm aot;
		auto fn = aot.load_aot_object(*object);
		if (!fn || (*fn)(nullptr, 0) != 42)
			return 5;
	} catch (...) {
		return 6;
	}
	return 0;
}
