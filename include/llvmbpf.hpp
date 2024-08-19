#ifndef _BPFTIME_VM_LLVM_HPP
#define _BPFTIME_VM_LLVM_HPP

#include <memory>
#include <optional>
#include <vector>
#include <ebpf_inst.h>
#include <string>

namespace bpftime
{

struct external_function {
	std::string name;
	void *fn;
};

class llvm_bpf_jit_context;

// The JITed function signature.
// The JITed function can be called with the memory and memory length directly.
using precompiled_ebpf_function = uint64_t (*)(void *mem, size_t mem_len);

class llvmbpf_vm {
    public:
	llvmbpf_vm();
	~llvmbpf_vm();  // Destructor declared
	std::string get_error_message();
	// register external function, e.g. helper functions for eBPF
	int register_external_function(size_t index, const std::string &name,
				       void *fn);

	// load the eBPF bytecode into the vm
	// The eBPF bytecode now can be JIT/AOT compiled
	// Or executed directly.
	int load_code(const void *code, size_t code_len);

	// unload the bytecode and remove the JIT/AOT compiled results
	void unload_code();

	// execute the eBPF program
	// If the program is JIT compiled, it will be executed directly
	// If not, it will be JIT compiled, cached and executed
	int exec(void *mem, size_t mem_len, uint64_t &bpf_return_value);

	// Do AOT compile and generate the ELF object file
	// The external functions are required to be registered before
	// calling this function. The compile result can be linked with
	// other object files to generate the final executable.
	std::vector<uint8_t> do_aot_compile(bool print_ir = false);

	// Load the AOT object file into the vm and link it with the
	// external functions
	std::optional<precompiled_ebpf_function>
	load_aot_object(const std::vector<uint8_t> &object);

	// Compile the eBPF program into a JITed function
	std::optional<precompiled_ebpf_function> compile();

	// See the spec for details.
	// If the code involve array map access, the map_val function
	// needs to be provided.
	// IF the map_by_fd, map_by_idx, var_addr, code_addr are not provided,
	// The are using imm as the address.
	void set_lddw_helpers(uint64_t (*map_by_fd)(uint32_t),
			      uint64_t (*map_by_idx)(uint32_t),
			      uint64_t (*map_val)(uint64_t),
			      uint64_t (*var_addr)(uint32_t),
			      uint64_t (*code_addr)(uint32_t));

    private:
	// See spec for details
	uint64_t (*map_by_fd)(uint32_t) = nullptr;
	uint64_t (*map_by_idx)(uint32_t) = nullptr;
	uint64_t (*map_val)(uint64_t) = nullptr;
	uint64_t (*var_addr)(uint32_t) = nullptr;
	uint64_t (*code_addr)(uint32_t) = nullptr;

	std::vector<ebpf_inst> instructions;

	std::vector<std::optional<external_function> > ext_funcs;

	std::unique_ptr<llvm_bpf_jit_context> jit_ctx;

	friend class llvm_bpf_jit_context;

	std::string error_msg;

	std::optional<precompiled_ebpf_function> jitted_function;
};

} // namespace bpftime

#endif // _BPFTIME_VM_LLVM_HPP
