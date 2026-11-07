#include <catch2/catch_test_macros.hpp>
#include "llvmbpf.hpp"
#include <llvm/AsmParser/Parser.h>
#include <llvm/ExecutionEngine/Orc/LLJIT.h>
#include <llvm/ExecutionEngine/Orc/ThreadSafeModule.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Linker/Linker.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_ostream.h>

namespace
{

std::unique_ptr<llvm::Module> parse_ir(const std::string &text,
				       llvm::LLVMContext &context)
{
	llvm::SMDiagnostic diagnostic;
	auto module = llvm::parseAssemblyString(text, diagnostic, context);
	std::string error;
	llvm::raw_string_ostream stream(error);
	if (!module)
		diagnostic.print("IR export test", stream);
	INFO(error);
	REQUIRE(module);
	REQUIRE_FALSE(llvm::verifyModule(*module, &stream));
	return module;
}

uint64_t execute_ir(const std::string &text, const std::string &entry,
		    const std::string &definitions = "", void *mem = nullptr,
		    size_t mem_len = 0)
{
	auto context = std::make_unique<llvm::LLVMContext>();
	auto module = parse_ir(text, *context);
	if (!definitions.empty()) {
		auto helpers = parse_ir(definitions, *context);
		REQUIRE_FALSE(
			llvm::Linker::linkModules(*module, std::move(helpers)));
		REQUIRE_FALSE(llvm::verifyModule(*module));
	}
	auto jit = llvm::orc::LLJITBuilder().create();
	if (!jit)
		FAIL(llvm::toString(jit.takeError()));
	module->setDataLayout((*jit)->getDataLayout());
#if LLVM_VERSION_MAJOR >= 21
	module->setTargetTriple((*jit)->getTargetTriple());
#else
	module->setTargetTriple((*jit)->getTargetTriple().str());
#endif
	auto error = (*jit)->addIRModule(llvm::orc::ThreadSafeModule(
		std::move(module), std::move(context)));
	if (error)
		FAIL(llvm::toString(std::move(error)));
	auto symbol = (*jit)->lookup(entry);
	if (!symbol)
		FAIL(llvm::toString(symbol.takeError()));
	return symbol->toPtr<bpftime::precompiled_ebpf_function>()(mem,
								   mem_len);
}

unsigned callback_calls = 0;
uint64_t host_resolver(uint32_t)
{
	++callback_calls;
	return 0xfeedface;
}
uint64_t host_map_value(uint64_t)
{
	++callback_calls;
	return 0xdeadbeef;
}

} // namespace

TEST_CASE("IR export preserves memory, branches and VM state", "[ir]")
{
	// Return *ctx + len when len >= 8, otherwise return 7.
	const ebpf_inst code[] = {
		{ EBPF_OP_MOV64_IMM, 0, 0, 0, 7 },
		{ EBPF_OP_JLT_IMM, 2, 0, 2, 8 },
		{ EBPF_OP_LDXDW, 0, 1, 0, 0 },
		{ EBPF_OP_ADD64_REG, 0, 2, 0, 0 },
		{ EBPF_OP_EXIT, 0, 0, 0, 0 },
	};
	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.load_code(code, sizeof(code)) == 0);
	auto ir = vm.generate_llvm_ir("probe_entry");
	REQUIRE(ir);
	llvm::LLVMContext context;
	auto module = parse_ir(*ir, context);
	REQUIRE(module->getDataLayoutStr().empty());
#if LLVM_VERSION_MAJOR >= 21
	REQUIRE(module->getTargetTriple().str().empty());
#else
	REQUIRE(module->getTargetTriple().empty());
#endif
	auto *entry = module->getFunction("probe_entry");
	REQUIRE(entry);
	REQUIRE_FALSE(entry->isDeclaration());
	REQUIRE(entry->arg_size() == 2);
	REQUIRE(entry->getReturnType()->isIntegerTy(64));
	REQUIRE(entry->getArg(0)->getType()->isPointerTy());
	REQUIRE(entry->getArg(1)->getType()->isIntegerTy(64));
	REQUIRE_FALSE(entry->hasFnAttribute("target-cpu"));
	REQUIRE_FALSE(entry->hasFnAttribute("target-features"));

	uint64_t mem = 34;
	REQUIRE(execute_ir(*ir, "probe_entry", "", &mem, sizeof(mem)) == 42);
	REQUIRE(execute_ir(*ir, "probe_entry") == 7);
	// Export must not freeze configuration or install a cached JIT
	// function.
	REQUIRE(vm.set_optimization_level(1) == 0);
	REQUIRE(vm.generate_llvm_ir("probe_entry") == ir);
	auto native = vm.compile();
	REQUIRE(native);
	REQUIRE((*native)(&mem, sizeof(mem)) == 42);
	REQUIRE(vm.generate_llvm_ir("probe_entry") == ir);
	REQUIRE(vm.compile() == native);
	auto object = vm.do_aot_compile();
	REQUIRE(object);
	bpftime::llvmbpf_vm aot;
	auto loaded = aot.load_aot_object(*object);
	REQUIRE(loaded);
	REQUIRE((*loaded)(&mem, sizeof(mem)) == 42);
	vm.unload_code();
	REQUIRE_FALSE(vm.generate_llvm_ir());
	REQUIRE(vm.get_error_message() == "No instructions provided");
}

TEST_CASE("IR export links a symbolic helper receiving a stack string", "[ir]")
{
	const ebpf_inst code[] = {
		{ EBPF_OP_STW, 10, 0, -8, 0x006968 }, // "hi\0"
		{ EBPF_OP_MOV64_REG, 1, 10, 0, 0 },
		{ EBPF_OP_ADD64_IMM, 1, 0, 0, -8 },
		{ EBPF_OP_MOV64_IMM, 2, 0, 0, 2 },
		{ EBPF_OP_MOV64_IMM, 3, 0, 0, 3 },
		{ EBPF_OP_MOV64_IMM, 4, 0, 0, 4 },
		{ EBPF_OP_MOV64_IMM, 5, 0, 0, 5 },
		{ EBPF_OP_CALL, 0, 0, 0, 1000 },
		{ EBPF_OP_EXIT, 0, 0, 0, 0 },
	};
	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.load_code(code, sizeof(code)) == 0);
	REQUIRE(vm.register_external_function(1000, "test_string", nullptr) ==
		0);
	auto ir = vm.generate_llvm_ir();
	REQUIRE(ir);
	llvm::LLVMContext context;
	auto module = parse_ir(*ir, context);
	auto *helper = module->getFunction("_bpf_helper_ext_1000");
	REQUIRE(helper);
	REQUIRE(helper->isDeclaration());
	REQUIRE(helper->arg_size() == 5);
	REQUIRE(helper->getReturnType()->isIntegerTy(64));
	for (const auto &arg : helper->args())
		REQUIRE(arg.getType()->isIntegerTy(64));
	REQUIRE_FALSE(module->getFunction("test_string"));
	const std::string definition = R"(
define i64 @_bpf_helper_ext_1000(i64 %str, i64 %b, i64 %c, i64 %d, i64 %e) {
  %p = inttoptr i64 %str to ptr
  %char = load i8, ptr %p
  %first = zext i8 %char to i64
  %sum1 = add i64 %first, %b
  %sum2 = add i64 %sum1, %c
  %sum3 = add i64 %sum2, %d
  %sum4 = add i64 %sum3, %e
  ret i64 %sum4
})";
	REQUIRE(execute_ir(*ir, "bpf_main", definition) == 'h' + 2 + 3 + 4 + 5);
}

TEST_CASE("IR export defers all pseudo LDDW resolvers", "[ir]")
{
	const std::string definitions = R"(
define i64 @__lddw_helper_map_by_fd(i32 %id) {
  %v = zext i32 %id to i64
  %r = add i64 %v, 100
  ret i64 %r
}
define i64 @__lddw_helper_map_by_idx(i32 %id) {
  %v = zext i32 %id to i64
  %r = add i64 %v, 200
  ret i64 %r
}
define i64 @__lddw_helper_var_addr(i32 %id) {
  %v = zext i32 %id to i64
  %r = add i64 %v, 300
  ret i64 %r
}
define i64 @__lddw_helper_code_addr(i32 %id) {
  %v = zext i32 %id to i64
  %r = add i64 %v, 400
  ret i64 %r
}
define i64 @__lddw_helper_map_val(i64 %handle) {
  %r = mul i64 %handle, 10
  ret i64 %r
})";
	const uint64_t expected[] = { 0, 107, 1067, 307, 407, 207, 2067 };
	for (bool with_callbacks : { false, true }) {
		for (uint8_t src = 1; src <= 6; ++src) {
			CAPTURE(with_callbacks, src);
			const ebpf_inst code[] = {
				{ EBPF_OP_LDDW, 0, src, 0, 7 },
				{ 0, 0, 0, 0, -3 },
				{ EBPF_OP_EXIT, 0, 0, 0, 0 },
			};
			bpftime::llvmbpf_vm vm;
			callback_calls = 0;
			if (with_callbacks)
				vm.set_lddw_helpers(host_resolver,
						    host_resolver,
						    host_map_value,
						    host_resolver,
						    host_resolver);
			REQUIRE(vm.load_code(code, sizeof(code)) == 0);
			auto ir = vm.generate_llvm_ir();
			REQUIRE(ir);
			REQUIRE(callback_calls == 0);
			REQUIRE(execute_ir(*ir, "bpf_main", definitions) ==
				expected[src]);
		}
	}
}

TEST_CASE("IR export preserves literal LDDW and kernel pseudo symbols", "[ir]")
{
	bpftime::llvmbpf_vm vm;
	ebpf_inst code[] = {
		{ EBPF_OP_LDDW, 0, 0, 0, 7 },
		{ 0, 0, 0, 0, 1 },
		{ EBPF_OP_EXIT, 0, 0, 0, 0 },
	};
	SECTION("literal immediate")
	{
		REQUIRE(vm.load_code(code, sizeof(code)) == 0);
		auto ir = vm.generate_llvm_ir();
		REQUIRE(ir);
		REQUIRE(execute_ir(*ir, "bpf_main") == 0x100000007ULL);
	}
	SECTION("kernel-compatible pseudo map value")
	{
		code[0].src = 2;
		vm.set_kernel_compatible_mode(true);
		REQUIRE(vm.load_code(code, sizeof(code)) == 0);
		auto ir = vm.generate_llvm_ir("kernel_probe");
		REQUIRE(ir);
		llvm::LLVMContext context;
		auto module = parse_ir(*ir, context);
		REQUIRE(module->getFunction("kernel_probe")->arg_size() == 1);
		REQUIRE(ir->find("__llvmbpf_pseudo_map_value_") !=
			std::string::npos);
		REQUIRE(ir->find("__lddw_helper_") == std::string::npos);
	}
}

TEST_CASE("Exported probes can share a consumer module", "[ir]")
{
	const ebpf_inst code[] = {
		{ EBPF_OP_MOV64_IMM, 0, 0, 0, 21 },
		{ EBPF_OP_EXIT, 0, 0, 0, 0 },
	};
	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.load_code(code, sizeof(code)) == 0);
	auto entry_ir = vm.generate_llvm_ir("entry_probe");
	auto exit_ir = vm.generate_llvm_ir("exit_probe");
	REQUIRE(entry_ir);
	REQUIRE(exit_ir);
	llvm::LLVMContext context;
	auto module = parse_ir(*entry_ir, context);
	auto other = parse_ir(*exit_ir, context);
	REQUIRE_FALSE(llvm::Linker::linkModules(*module, std::move(other)));
	std::string combined;
	llvm::raw_string_ostream stream(combined);
	module->print(stream, nullptr);
	stream.flush();
	const std::string wrapper = R"(
declare i64 @entry_probe(ptr, i64)
declare i64 @exit_probe(ptr, i64)
define i64 @both(ptr %ctx, i64 %len) {
  %a = call i64 @entry_probe(ptr %ctx, i64 %len)
  %b = call i64 @exit_probe(ptr %ctx, i64 %len)
  %sum = add i64 %a, %b
  ret i64 %sum
})";
	REQUIRE(execute_ir(combined, "both", wrapper) == 42);
}

TEST_CASE("IR export reports errors and accepts subsequent valid input", "[ir]")
{
	bpftime::llvmbpf_vm vm;
	REQUIRE_FALSE(vm.generate_llvm_ir());
	REQUIRE(vm.get_error_message() == "No instructions provided");
	const ebpf_inst code[] = {
		{ EBPF_OP_MOV64_IMM, 0, 0, 0, 42 },
		{ EBPF_OP_EXIT, 0, 0, 0, 0 },
	};
	REQUIRE(vm.load_code(code, sizeof(code)) == 0);
	for (const auto *name :
	     { "", "llvm.test", "_bpf_helper_ext_0001", "__lddw_helper_map_val",
	       "__llvmbpf_pseudo_map_fd_1" }) {
		CAPTURE(name);
		REQUIRE_FALSE(vm.generate_llvm_ir(name));
		REQUIRE_FALSE(vm.get_error_message().empty());
	}
	REQUIRE_FALSE(vm.generate_llvm_ir(std::string("bad\0name", 8)));
	REQUIRE(vm.generate_llvm_ir());
	REQUIRE(vm.get_error_message().empty());

	const ebpf_inst missing_helper[] = {
		{ EBPF_OP_CALL, 0, 0, 0, 1234 },
		{ EBPF_OP_EXIT, 0, 0, 0, 0 },
	};
	REQUIRE(vm.load_code(missing_helper, sizeof(missing_helper)) == 0);
	REQUIRE_FALSE(vm.generate_llvm_ir());
	REQUIRE_FALSE(vm.get_error_message().empty());
	const ebpf_inst incomplete_lddw[] = { { EBPF_OP_LDDW, 0, 0, 0, 7 } };
	REQUIRE(vm.load_code(incomplete_lddw, sizeof(incomplete_lddw)) == 0);
	REQUIRE_FALSE(vm.generate_llvm_ir());
	REQUIRE(vm.get_error_message().find("extra pseudo instruction") !=
		std::string::npos);
	// Translation reaches LLVM verification, whose diagnostics must be
	// returned through the API rather than printed to the host's stderr.
	REQUIRE(vm.load_code(code, sizeof(ebpf_inst)) == 0); // Missing exit
	REQUIRE_FALSE(vm.generate_llvm_ir());
	REQUIRE(vm.get_error_message().find("Invalid module generated") !=
		std::string::npos);
	REQUIRE(vm.get_error_message().find("terminator") != std::string::npos);
}
