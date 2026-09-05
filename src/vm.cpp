#include "spdlog/spdlog.h"
#include <cerrno>
#include <cstdint>
#include <memory>
#include <ebpf_inst.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Object/SymbolSize.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/MemoryBuffer.h>
#include "llvm_jit_context.hpp"

using namespace bpftime;

namespace {

std::optional<size_t>
resolve_compiled_symbol_size(const std::vector<uint8_t> &object_code,
			      std::string &error_msg)
{
	auto buffer = llvm::MemoryBuffer::getMemBufferCopy(
		llvm::StringRef(reinterpret_cast<const char *>(object_code.data()),
				object_code.size()),
		"llvmbpf_native_object");
	auto object_or_error =
		llvm::object::ObjectFile::createObjectFile(buffer->getMemBufferRef());
	if (!object_or_error) {
		error_msg = llvm::toString(object_or_error.takeError());
		return {};
	}

	for (const auto &[symbol, symbol_size] :
	     llvm::object::computeSymbolSizes(**object_or_error)) {
		auto name_or_error = symbol.getName();
		if (!name_or_error) {
			llvm::consumeError(name_or_error.takeError());
			continue;
		}
		if (*name_or_error != "bpf_main") {
			continue;
		}

		if (symbol_size != 0) {
			return static_cast<size_t>(symbol_size);
		}

		auto section_or_error = symbol.getSection();
		if (!section_or_error) {
			error_msg = llvm::toString(section_or_error.takeError());
			return {};
		}
		if (*section_or_error == (*object_or_error)->section_end()) {
			error_msg = "bpf_main has no backing section";
			return {};
		}

		auto contents_or_error = (*section_or_error)->getContents();
		if (!contents_or_error) {
			error_msg = llvm::toString(contents_or_error.takeError());
			return {};
		}
		return contents_or_error->size();
	}

	error_msg = "Unable to resolve native code size for bpf_main";
	return {};
}

} // namespace

llvmbpf_vm::llvmbpf_vm()
	: ext_funcs(MAX_EXT_FUNCS),
	  jit_ctx(std::make_unique<bpftime::llvm_bpf_jit_context>(*this))
{
}

llvmbpf_vm::~llvmbpf_vm()
{
}

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

int llvmbpf_vm::register_array_map(const array_map_descriptor &map) noexcept
{
	if (jitted_function) {
		error_msg = "Cannot register array map after compile";
		return -EBUSY;
	}
	if (map.key_size != sizeof(uint32_t)) {
		error_msg = "Array map key_size must be 4 bytes";
		return -EINVAL;
	}
	if (map.max_entries == 0) {
		error_msg = "Array map max_entries must be non-zero";
		return -EINVAL;
	}
	const uint32_t stride =
		map.value_stride != 0 ? map.value_stride : map.value_size;
	if (stride == 0) {
		error_msg = "Array map value_size/value_stride must be non-zero";
		return -EINVAL;
	}
	if (array_maps.contains(map.map_handle)) {
		error_msg = "Array map already defined";
		return -EEXIST;
	}
	array_maps.emplace(map.map_handle, map);
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
	if (jitted_function) {
		error_msg = "Already compiled";
		return jitted_function;
	}
	try {
		auto res = jit_ctx->do_jit_compile();
		if (res) {
			LLVMErrorRef llvmError = llvm::wrap(std::move(res));
			error_msg = LLVMGetErrorMessage(llvmError);
			SPDLOG_ERROR("LLVM-JIT: failed to compile: {}",
				     error_msg);
			return {};
		}
		auto func = jit_ctx->get_entry_address();
		jitted_function = func;
		return func;
	} catch (const std::exception &e) {
		error_msg = e.what();
		jitted_function = std::nullopt;
		return {};
	}
}

int llvmbpf_vm::set_optimization_level(int level) noexcept
{
	if (level < 0 || level > 3) {
		error_msg = "Optimization level must be between 0 and 3";
		return -EINVAL;
	}
	if (jitted_function) {
		error_msg = "Cannot change optimization level after compile";
		return -EBUSY;
	}
	optimization_level = level;
	return 0;
}

int llvmbpf_vm::set_target_cpu(const std::string &cpu) noexcept
{
	if (jitted_function) {
		error_msg = "Cannot change target CPU after compile";
		return -EBUSY;
	}
	target_cpu_ = cpu;
	return 0;
}

int llvmbpf_vm::set_target_features(const std::string &features) noexcept
{
	if (jitted_function) {
		error_msg = "Cannot change target features after compile";
		return -EBUSY;
	}
	target_features_ = features;
	return 0;
}

int llvmbpf_vm::set_disabled_passes(
	const std::vector<std::string> &pass_names) noexcept
{
	if (jitted_function)
		return -1;
	disabled_passes_ = pass_names;
	return 0;
}

int llvmbpf_vm::set_log_passes(bool enabled) noexcept
{
	if (jitted_function)
		return -1;
	log_passes_ = enabled;
	return 0;
}

void llvmbpf_vm::set_kernel_compatible_mode(bool enabled) noexcept
{
	kernel_compatible_mode_ = enabled;
}

const std::string &llvmbpf_vm::get_target_cpu() const noexcept
{
	return target_cpu_;
}

const std::string &llvmbpf_vm::get_target_features() const noexcept
{
	return target_features_;
}

const std::vector<std::string> &
llvmbpf_vm::get_disabled_passes() const noexcept
{
	return disabled_passes_;
}

std::optional<compiled_code> llvmbpf_vm::get_compiled_code() noexcept
{
	if (!jitted_function) {
		error_msg = "Not compiled";
		return {};
	}

	auto object_code = do_aot_compile(false);
	if (!object_code) {
		if (error_msg.empty()) {
			error_msg = "Unable to generate native object for code size";
		}
		return {};
	}

	auto native_code_size = resolve_compiled_symbol_size(*object_code, error_msg);
	if (!native_code_size) {
		return {};
	}

	const auto address = reinterpret_cast<uintptr_t>(jitted_function.value());
	return compiled_code {
		.data = reinterpret_cast<const uint8_t *>(address),
		.size = *native_code_size,
	};
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

std::optional<std::vector<uint8_t>>
llvmbpf_vm::do_aot_compile(bool print_ir) noexcept
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
		if (auto res = this->jit_ctx->load_aot_object(object); res) {
			LLVMErrorRef llvmError = llvm::wrap(std::move(res));
			error_msg = LLVMGetErrorMessage(llvmError);
			return {};
		}
		jitted_function = this->jit_ctx->get_entry_address();
	} catch (const std::exception &e) {
		error_msg = e.what();
		return {};
	}
	return jitted_function;
}

std::optional<std::string> llvmbpf_vm::generate_ptx(const char *target_cpu)
{
	return this->jit_ctx->generate_ptx(target_cpu);
}

std::optional<std::vector<uint8_t>>
llvmbpf_vm::generate_spirv(const char *target_env)
{
	return this->jit_ctx->generate_spirv(true, "bpf_main", target_env);
}
