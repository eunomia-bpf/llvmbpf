#include "spdlog/spdlog.h"
#include <cerrno>
#include <cstdint>
#include <memory>
#include <ebpf_inst.h>
#include "llvm_jit_context.hpp"

using namespace bpftime;

llvmbpf_vm::llvmbpf_vm() 
	: ext_funcs(MAX_EXT_FUNCS),
	  jit_ctx(std::make_unique<bpftime::llvm_bpf_jit_context>(*this))
{
}

llvmbpf_vm::~llvmbpf_vm() = default;

std::string llvmbpf_vm::get_error_message() noexcept
{
	return error_msg;
}

int llvmbpf_vm::register_external_function(size_t index,
						    const std::string &name,
						    void *fn) noexcept
{
	if (index >= ext_funcs.size()) {
		error_msg = "Index too large";
		return -E2BIG;
	}
	if (ext_funcs[index].has_value()) {
		error_msg = "Already defined";
		return -EEXIST;
	}
	ext_funcs[index] = external_function{ .name = name, .fn = fn };
	return 0;
}

int llvmbpf_vm::load_code(const void *code, size_t code_len) noexcept
{
	if (code_len % 8 != 0) {
		error_msg = "Code len must be a multiple of 8";
		return -EINVAL;
	}
	instructions.assign((ebpf_inst *)code,
			    (ebpf_inst *)code + code_len / 8);
	return 0;
}

void llvmbpf_vm::unload_code() noexcept
{
	instructions.clear();
}

int llvmbpf_vm::exec(void *mem, size_t mem_len,
			      uint64_t &bpf_return_value) noexcept
{
	if (jitted_function) {
		SPDLOG_TRACE("llvm-jit: Called jitted function {:x}",
			     (uintptr_t)jitted_function.value());
		auto ret =
			(*jitted_function)(mem, static_cast<uint64_t>(mem_len));
		SPDLOG_TRACE(
			"LLJIT: called from jitted function {:x} returned {}",
			(uintptr_t)jitted_function.value(), ret);
		bpf_return_value = ret;
		return 0;
	}
	try {
		auto func = compile();
		if (!func) {
			SPDLOG_ERROR("Unable to compile eBPF program");
			return -1;
		}
		jitted_function = func;
		// after compile, run
		return exec(mem, mem_len, bpf_return_value);
	} catch (const std::exception &e) {
		error_msg = e.what();
		return -1;
	}
}

std::optional<bpftime::precompiled_ebpf_function> llvmbpf_vm::compile() noexcept
{
	try {
		auto func = jit_ctx->compile();
		if (!func) {
			error_msg = "Unable to compile eBPF program";
			return {};
		}
		jitted_function = func;
		return func;
	} catch (const std::exception &e) {
		error_msg = e.what();
		return {};
	}
}

void llvmbpf_vm::set_lddw_helpers(uint64_t (*map_by_fd)(uint32_t),
					   uint64_t (*map_by_idx)(uint32_t),
					   uint64_t (*map_val)(uint64_t),
					   uint64_t (*var_addr)(uint32_t),
					   uint64_t (*code_addr)(uint32_t)) noexcept
{
	this->map_by_fd = map_by_fd;
	this->map_by_idx = map_by_idx;
	this->map_val = map_val;
	this->var_addr = var_addr;
	this->code_addr = code_addr;
}

std::optional<std::vector<uint8_t>> llvmbpf_vm::do_aot_compile(bool print_ir) noexcept
{
	try {
		return jit_ctx->do_aot_compile(print_ir);
	} catch (const std::exception &e) {
		error_msg = e.what();
		return {};
	}
}

std::optional<bpftime::precompiled_ebpf_function>
llvmbpf_vm::load_aot_object(const std::vector<uint8_t> &object) noexcept
{
	if (jitted_function) {
		error_msg = "Already compiled";
		return {};
	}
	try {
		if (this->jit_ctx->load_aot_object(object)) {
			error_msg = "Unable to load aot object";
			return {};
		}
		jitted_function = this->jit_ctx->get_entry_address();
	} catch (const std::exception &e) {
		error_msg = e.what();
		return {};
	}
	return jitted_function;
}
