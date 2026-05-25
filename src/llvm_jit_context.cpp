/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022, eunomia-bpf org
 * All rights reserved.
 */

#include <llvm/ExecutionEngine/Orc/JITTargetMachineBuilder.h>
#ifdef WIN32
#pragma warning(disable : 4141 4244 4291 4146 4267 4275 4624 4800)
#endif

#include <string.h>
#include <fstream>
#include <iostream>
#include <sstream>

#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/ExecutionEngine/ObjectCache.h>
#include <llvm/IR/IRPrintingPasses.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/LegacyPassNameParser.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Linker/Linker.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormattedStream.h>
#include <llvm/Config/llvm-config.h>
#if LLVM_VERSION_MAJOR >= 16
#include <llvm/TargetParser/Host.h>
#else
#include <llvm/Support/Host.h>
#endif
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Transforms/IPO.h>
#if LLVM_VERSION_MAJOR < 17
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#endif
#include <llvm/Transforms/IPO/AlwaysInliner.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/Analysis/TargetTransformInfo.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/Bitcode/BitcodeWriter.h>

#if LLVM_VERSION_MAJOR >= 17
#include <llvm/ExecutionEngine/MCJIT.h>
#include <typeinfo>
#include <llvm-c/ExecutionEngine.h>
#include "llvm/LTO/LTOBackend.h"
#include "llvm/IR/PassInstrumentation.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/CGSCCPassManager.h"
#include "llvm/Analysis/ModuleSummaryAnalysis.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IR/LLVMRemarkStreamer.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Verifier.h"
#include "llvm/LTO/LTO.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Object/ModuleSymbolTable.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/StandardInstrumentations.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/Program.h"
#include "llvm/Support/ThreadPool.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/TargetParser/SubtargetFeature.h"
#include "llvm/Transforms/IPO/WholeProgramDevirt.h"
#include "llvm/Transforms/Scalar/LoopPassManager.h"
#include "llvm/Transforms/Utils/FunctionImportUtils.h"
#include "llvm/Transforms/Utils/SplitModule.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ExecutionEngine/GenericValue.h"
#include "llvm/ExecutionEngine/JITEventListener.h"
#include "llvm/ExecutionEngine/MCJIT.h"
#include "llvm/ExecutionEngine/ObjectCache.h"
#include "llvm/ExecutionEngine/SectionMemoryManager.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Mangler.h"
#include "llvm/IR/Module.h"
#include "llvm/MC/MCContext.h"
#include "llvm/Object/Archive.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Support/DynamicLibrary.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SmallVectorMemoryBuffer.h"
#include "llvm/AsmParser/Parser.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/raw_os_ostream.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Transforms/Scalar/IndVarSimplify.h"
#include "llvm/Transforms/Scalar/LICM.h"
#include "llvm/Transforms/Scalar/LoopAccessAnalysisPrinter.h"
#include "llvm/Transforms/Scalar/LoopDataPrefetch.h"
#include "llvm/Transforms/Scalar/LoopDeletion.h"
#include "llvm/Transforms/Scalar/LoopDistribute.h"
#include "llvm/Transforms/Scalar/LoopFuse.h"
#include "llvm/Transforms/Scalar/LoopIdiomRecognize.h"
#include "llvm/Transforms/Scalar/LoopInstSimplify.h"
#include "llvm/Transforms/Scalar/LoopLoadElimination.h"
#include "llvm/Transforms/Scalar/LoopPassManager.h"
#include "llvm/Transforms/Scalar/LoopPredication.h"
#include "llvm/Transforms/Scalar/LoopRotation.h"
#include "llvm/Transforms/Scalar/LoopSimplifyCFG.h"
#include "llvm/Transforms/Scalar/LoopSink.h"
#include "llvm/Transforms/Scalar/LoopStrengthReduce.h"
#include "llvm/Transforms/Scalar/LoopUnrollAndJamPass.h"
#include "llvm/Transforms/Scalar/LoopUnrollPass.h"
#endif

// Disappears in LLVM 15
#if LLVM_VERSION_MAJOR >= 14
#include <llvm/MC/TargetRegistry.h>
#else
#include <llvm/Support/TargetRegistry.h>
#endif

#if LLVM_VERSION_MAJOR >= 10
#include <llvm/InitializePasses.h>
#include <llvm/Support/CodeGen.h>
#endif

#include "llvm_jit_context.hpp"
#include "compiler_utils.hpp"
#include "spdlog/spdlog.h"
#include <iterator>

#include "llvm/IR/Module.h"
#include <llvm/ExecutionEngine/JITSymbol.h>
#include <llvm/ExecutionEngine/Orc/LLJIT.h>
// Prefer feature-detection over hardcoding LLVM_VERSION_MAJOR here.
// These ORC headers (DynamicLibrarySearchGenerator vs ExecutionUtils) moved
#ifdef BPFTIME_ENABLE_LLVM_PRELOAD
// between LLVM releases. Using __has_include keeps the code resilient across
// minor/packaging differences without forcing a specific version guard.
#if defined(__has_include)
#  if __has_include(<llvm/ExecutionEngine/Orc/DynamicLibrarySearchGenerator.h>)
#    include <llvm/ExecutionEngine/Orc/DynamicLibrarySearchGenerator.h>
#    define BPFTIME_HAVE_ORC_DYNLIB_SEARCH_GEN 1
#  elif __has_include(<llvm/ExecutionEngine/Orc/ExecutionUtils.h>)
#    include <llvm/ExecutionEngine/Orc/ExecutionUtils.h>
#    define BPFTIME_HAVE_ORC_EXECUTIONUTILS 1
#  endif
#endif
#endif
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/Alignment.h>
#ifdef BPFTIME_ENABLE_LLVM_PRELOAD
#include <llvm/Support/DynamicLibrary.h>
#endif
#include <llvm/ExecutionEngine/JITSymbol.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/MC/TargetRegistry.h>
#include <memory>
#include <pthread.h>
#include <stdexcept>
#include <sys/stat.h>
#include <utility>
#include <string>
#include <spdlog/spdlog.h>
#include <tuple>

using namespace llvm;
using namespace llvm::orc;
using namespace bpftime;
using namespace std;

struct spin_lock_guard {
	pthread_spinlock_t *spin;
	spin_lock_guard(pthread_spinlock_t *spin) : spin(spin)
	{
		pthread_spin_lock(spin);
	}
	~spin_lock_guard()
	{
		pthread_spin_unlock(spin);
	}
};

static void optimizeModule(llvm::Module &M, int opt_level,
			   const std::vector<std::string> &disabled_passes,
			   bool log_passes)
{
	// std::cout << "LLVM_VERSION_MAJOR: " << LLVM_VERSION_MAJOR <<
	// std::endl;
#if LLVM_VERSION_MAJOR >= 17
	PassInstrumentationCallbacks PIC;
	if (!disabled_passes.empty()) {
		PIC.registerShouldRunOptionalPassCallback(
			[&disabled_passes](StringRef pass_name, Any) {
				for (const auto &disabled : disabled_passes) {
					if (pass_name.contains(
						    StringRef(disabled))) {
						return false;
					}
				}
				return true;
			});
	}
	if (log_passes) {
		PIC.registerBeforeNonSkippedPassCallback(
			[](StringRef pass_name, Any) {
				llvm::errs() << "[llvmbpf pass] "
					     << pass_name << "\n";
			});
	}

	// =====================
	// Create the analysis managers.
	// These must be declared in this order so that they are destroyed in
	// the correct order due to inter-analysis-manager references.
	LoopAnalysisManager LAM;
	FunctionAnalysisManager FAM;
	CGSCCAnalysisManager CGAM;
	ModuleAnalysisManager MAM;

	// Create the new pass manager builder.
	// Take a look at the PassBuilder constructor parameters for more
	// customization, e.g. specifying a TargetMachine or various debugging
	// options.
	PassBuilder PB(nullptr, PipelineTuningOptions(), std::nullopt, &PIC);

	// Register all the basic analyses with the managers.
	PB.registerModuleAnalyses(MAM);
	PB.registerCGSCCAnalyses(CGAM);
	PB.registerFunctionAnalyses(FAM);
	PB.registerLoopAnalyses(LAM);
	PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

	llvm::OptimizationLevel optimization_level = llvm::OptimizationLevel::O3;
	switch (opt_level) {
	case 0:
		optimization_level = llvm::OptimizationLevel::O0;
		break;
	case 1:
		optimization_level = llvm::OptimizationLevel::O1;
		break;
	case 2:
		optimization_level = llvm::OptimizationLevel::O2;
		break;
	case 3:
	default:
		optimization_level = llvm::OptimizationLevel::O3;
		break;
	}

	ModulePassManager MPM =
		PB.buildPerModuleDefaultPipeline(optimization_level);

	// Optimize the IR!
	MPM.run(M, MAM);
	// =====================================
#else
	(void)disabled_passes;
	(void)log_passes;
	llvm::legacy::PassManager PM;

	llvm::PassManagerBuilder PMB;
	PMB.OptLevel = opt_level;
	PMB.populateModulePassManager(PM);

	PM.run(M);
#endif
}

namespace {

bool is_power_of_two_u32(uint32_t value)
{
	return value != 0 && (value & (value - 1)) == 0;
}

unsigned int ilog2_u32(uint32_t value)
{
	unsigned int shift = 0;
	while (value > 1) {
		value >>= 1;
		shift++;
	}
	return shift;
}

void apply_target_feature_overrides(llvm::SubtargetFeatures &features,
				       const std::string &feature_overrides)
{
	size_t start = 0;
	while (start <= feature_overrides.size()) {
		const size_t comma = feature_overrides.find(',', start);
		std::string token = feature_overrides.substr(
			start,
			comma == std::string::npos ? std::string::npos
						   : comma - start);
		const auto first = token.find_first_not_of(" \t");
		if (first != std::string::npos) {
			const auto last = token.find_last_not_of(" \t");
			token = token.substr(first, last - first + 1);
		} else {
			token.clear();
		}

		if (!token.empty()) {
			bool enable = true;
			if (token.front() == '+' || token.front() == '-') {
				enable = token.front() != '-';
				token.erase(token.begin());
			}
			if (!token.empty()) {
				features.AddFeature(token, enable);
			}
		}

		if (comma == std::string::npos) {
			break;
		}
		start = comma + 1;
	}
}

llvm::Expected<llvm::orc::JITTargetMachineBuilder>
create_host_jit_target_machine_builder(const llvmbpf_vm &vm)
{
	auto jtmb = llvm::orc::JITTargetMachineBuilder::detectHost();
	if (!jtmb) {
		return jtmb.takeError();
	}

	if (!vm.get_target_cpu().empty()) {
		jtmb->setCPU(vm.get_target_cpu());
	}
	if (!vm.get_target_features().empty()) {
		apply_target_feature_overrides(
			jtmb->getFeatures(), vm.get_target_features());
	}
	return std::move(*jtmb);
}

std::unique_ptr<llvm::TargetMachine>
create_host_target_machine_or_throw(const llvmbpf_vm &vm)
{
	auto jtmb = create_host_jit_target_machine_builder(vm);
	if (!jtmb) {
		throw std::runtime_error(llvm::toString(jtmb.takeError()));
	}

	auto target_machine = jtmb->createTargetMachine();
	if (!target_machine) {
		throw std::runtime_error(llvm::toString(target_machine.takeError()));
	}
	return std::move(*target_machine);
}

} // namespace

bool llvm_bpf_jit_context::inline_array_map_lookup_helpers(llvm::Module &module)
{
	if (vm.array_maps.empty()) {
		return false;
	}

	auto *helperFunc = module.getFunction(ext_func_sym(1));
	if (!helperFunc) {
		return false;
	}

	std::vector<llvm::CallInst *> callSites;
	for (auto &function : module) {
		for (auto &block : function) {
			for (auto &inst : block) {
				auto *call = llvm::dyn_cast<llvm::CallInst>(&inst);
				if (!call ||
				    call->getCalledFunction() != helperFunc) {
					continue;
				}
				callSites.push_back(call);
			}
		}
	}

	bool changed = false;
	for (auto *call : callSites) {
		auto *mapHandle =
			llvm::dyn_cast<llvm::ConstantInt>(call->getArgOperand(0));
		if (!mapHandle) {
			continue;
		}

		const auto mapHandleValue = mapHandle->getZExtValue();
		auto mapIter = vm.array_maps.find(mapHandleValue);
		if (mapIter == vm.array_maps.end()) {
			continue;
		}

		const auto &map = mapIter->second;
		if (map.key_size != sizeof(uint32_t) || map.max_entries == 0) {
			continue;
		}
		const uint32_t stride =
			map.value_stride != 0 ? map.value_stride : map.value_size;
		if (stride == 0) {
			continue;
		}

		uint64_t valueBase = map.value_base;
		if (valueBase == 0 && vm.map_val) {
			valueBase = vm.map_val(map.map_handle);
		}
		if (valueBase == 0) {
			continue;
		}

		llvm::IRBuilder<> builder(call);
		auto *keyPtr = builder.CreateIntToPtr(
			call->getArgOperand(1),
			llvm::PointerType::getUnqual(builder.getInt32Ty()),
			"array_lookup.key_ptr");
		auto *index = builder.CreateLoad(builder.getInt32Ty(), keyPtr,
						 "array_lookup.index");
		index->setAlignment(llvm::Align(4));
		auto *inRange = builder.CreateICmpULT(
			index, builder.getInt32(map.max_entries),
			"array_lookup.in_range");
		llvm::Value *offset = builder.CreateZExt(
			index, builder.getInt64Ty(), "array_lookup.index64");
		if (is_power_of_two_u32(stride)) {
			const auto shift = ilog2_u32(stride);
			if (shift != 0) {
				offset = builder.CreateShl(
					offset, builder.getInt64(shift),
					"array_lookup.offset");
			}
		} else {
			offset = builder.CreateMul(
				offset, builder.getInt64(stride),
				"array_lookup.offset");
		}
		auto *address = builder.CreateAdd(
			builder.getInt64(valueBase), offset, "array_lookup.addr");
		auto *result = builder.CreateSelect(
			inRange, address, builder.getInt64(0),
			"array_lookup.result");

		call->replaceAllUsesWith(result);
		call->eraseFromParent();
		changed = true;
	}

	if (changed) {
		SPDLOG_DEBUG("Inlined array map lookup helper calls");
	}
	return changed;
}

#if defined(__arm__) || defined(_M_ARM)
extern "C" void __aeabi_unwind_cpp_pr1();
#endif

static int llvm_initialized = 0;

llvm_bpf_jit_context::llvm_bpf_jit_context(llvmbpf_vm &vm) : vm(vm)
{
	using namespace llvm;
	int zero = 0;
	if (__atomic_compare_exchange_n(&llvm_initialized, &zero, 1, false,
					__ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
		SPDLOG_DEBUG("Initializing llvm");
		llvm::InitializeAllTargetInfos();
		llvm::InitializeAllTargets();
		llvm::InitializeAllTargetMCs();
		llvm::InitializeAllAsmPrinters();
		llvm::InitializeAllAsmParsers();
	}
	compiling = std::make_unique<pthread_spinlock_t>();
	pthread_spin_init(compiling.get(), PTHREAD_PROCESS_PRIVATE);
}

llvm::Error llvm_bpf_jit_context::do_jit_compile()
{
	spin_lock_guard guard(compiling.get());
	auto [jit, extFuncNames, definedLddwHelpers] =
		create_and_initialize_lljit_instance();
	if (!jit) {
		return llvm::make_error<llvm::StringError>(
			"jit initialization failed",
			llvm::inconvertibleErrorCode());
	}
	// Handle the error from generateModule
	auto bpfModuleOrErr =
		generateModule(extFuncNames, definedLddwHelpers, true);
	if (!bpfModuleOrErr) {
		return bpfModuleOrErr.takeError();
	}
	// If successful, get the module
	auto bpfModule = std::move(*bpfModuleOrErr);
	// Optimize the module
	bpfModule.withModuleDo([&](auto &M) {
		optimizeModule(M, vm.optimization_level, vm.disabled_passes_,
			       vm.log_passes_);
		if (inline_array_map_lookup_helpers(M)) {
			optimizeModule(M, vm.optimization_level,
				       vm.disabled_passes_, vm.log_passes_);
		}
	});
	// Handle the error from addIRModule
	if (auto err = jit->addIRModule(std::move(bpfModule))) {
		return err;
	}
	// If everything succeeds, move the JIT instance
	this->jit = std::move(jit);
	return llvm::Error::success();
}
llvm_bpf_jit_context::~llvm_bpf_jit_context()
{
	pthread_spin_destroy(compiling.get());
}

std::vector<uint8_t> llvm_bpf_jit_context::do_aot_compile(
	const std::vector<std::string> &extFuncNames,
	const std::vector<std::string> &lddwHelpers, bool print_ir)
{
	SPDLOG_DEBUG("AOT: start");
	if (auto module = generateModule(extFuncNames, lddwHelpers, false);
	    module) {
		return module->withModuleDo([&](auto &module)
						    -> std::vector<uint8_t> {
			if (print_ir) {
				module.print(llvm::outs(), nullptr);
			}
			optimizeModule(module, vm.optimization_level,
				       vm.disabled_passes_, vm.log_passes_);
			auto targetMachine =
				create_host_target_machine_or_throw(vm);
			#if LLVM_VERSION_MAJOR >= 21
				module.setTargetTriple(targetMachine->getTargetTriple());
			#else
				module.setTargetTriple(targetMachine->getTargetTriple().str());
			#endif
			module.setDataLayout(targetMachine->createDataLayout());
			SmallVector<char, 0> objStream;
			std::unique_ptr<raw_svector_ostream> BOS =
				std::make_unique<raw_svector_ostream>(
					objStream);

			legacy::PassManager pass;
// auto FileType = CGFT_ObjectFile;
#if LLVM_VERSION_MAJOR >= 18
			if (targetMachine->addPassesToEmitFile(
				    pass, *BOS, nullptr,
				    CodeGenFileType::ObjectFile)) {
#elif LLVM_VERSION_MAJOR >= 10
			if (targetMachine->addPassesToEmitFile(
				    pass, *BOS, nullptr, CGFT_ObjectFile)) {
#elif LLVM_VERSION_MAJOR >= 8
			if (targetMachine->addPassesToEmitFile(
				    pass, *BOS, nullptr,
				    TargetMachine::CGFT_ObjectFile)) {
#else
			if (targetMachine->addPassesToEmitFile(
				    pass, *BOS, TargetMachine::CGFT_ObjectFile,
				    true)) {
#endif
				SPDLOG_ERROR(
					"Unable to emit module for target machine");
				throw std::runtime_error(
					"Unable to emit module for target machine");
			}

			pass.run(module);
			SPDLOG_DEBUG("AOT: done, received {} bytes",
				     objStream.size());

			std::vector<uint8_t> result(objStream.begin(),
						    objStream.end());
			return result;
		});
	} else {
		std::string buf;
		raw_string_ostream os(buf);
		os << module.takeError();
		SPDLOG_ERROR("Unable to generate module: {}", buf);
		throw std::runtime_error("Unable to generate llvm module");
	}
}

std::vector<uint8_t> llvm_bpf_jit_context::do_aot_compile(bool print_ir)
{
	std::vector<std::string> extNames, lddwNames;
	for (uint32_t i = 0; i < std::size(vm.ext_funcs); i++) {
		if (vm.ext_funcs[i].has_value()) {
#if LLVM_VERSION_MAJOR >= 16
			extNames.emplace_back(ext_func_sym(i));
#else
			extNames.push_back(ext_func_sym(i));
#endif
		}
	}

	const auto tryDefineLddwHelper = [&](const char *name, void *func) {
		if (func) {
#if LLVM_VERSION_MAJOR >= 16
			lddwNames.emplace_back(name);
#else
			lddwNames.push_back(name);
#endif
		}
	};
	// Only map_val will have a chance to be called at runtime
	if (!vm.kernel_compatible_mode_) {
		tryDefineLddwHelper(LDDW_HELPER_MAP_VAL, (void *)vm.map_val);
	}
	// These symbols won't be used at runtime
	// tryDefineLddwHelper(LDDW_HELPER_MAP_BY_FD, (void *)vm.map_by_fd);
	// tryDefineLddwHelper(LDDW_HELPER_MAP_BY_IDX, (void *)vm.map_by_idx);
	// tryDefineLddwHelper(LDDW_HELPER_CODE_ADDR, (void *)vm.code_addr);
	// tryDefineLddwHelper(LDDW_HELPER_VAR_ADDR, (void *)vm.var_addr);
	return this->do_aot_compile(extNames, lddwNames, print_ir);
}

llvm::Error
llvm_bpf_jit_context::load_aot_object(const std::vector<uint8_t> &buf)
{
	SPDLOG_INFO("LLVM-JIT: Loading aot object");
	if (jit.has_value()) {
		SPDLOG_ERROR("Unable to load aot object: already compiled");
		throw std::runtime_error(
			"Unable to load aot object: already compiled");
	}
	auto buffer = MemoryBuffer::getMemBuffer(
		StringRef((const char *)buf.data(), buf.size()));
	auto [jit, extFuncNames, definedLddwHelpers] =
		create_and_initialize_lljit_instance();
	if (!jit) {
		return llvm::make_error<llvm::StringError>(
			"jit initialization failed",
			llvm::inconvertibleErrorCode());
	}
	if (auto err = jit->addObjectFile(std::move(buffer)); err) {
		SPDLOG_ERROR("Unable to add object file");
		return err;
	}
	this->jit = std::move(jit);
	// Test getting entry function
	this->get_entry_address();
	return llvm::Error::success();
}
std::tuple<std::unique_ptr<llvm::orc::LLJIT>, std::vector<std::string>,
	   std::vector<std::string>>
llvm_bpf_jit_context::create_and_initialize_lljit_instance()
{
	static ExitOnError exitOnErr;
	// Create a JIT builder
	SPDLOG_DEBUG("LLVM-JIT: Creating LLJIT instance");
#ifdef BPFTIME_ENABLE_LLVM_PRELOAD
	// Preload libLLVM before creating LLJIT so that ORC runtime wrapper symbols
	// (e.g. llvm_orc_registerEHFrameSectionWrapper) are visible during create.
	// Allow overriding SONAME via environment variable BPFTIME_LLVM_SONAME.
	{
		const char *envSoname = ::getenv("BPFTIME_LLVM_SONAME");
		const char *candidates[] = {
			envSoname && envSoname[0] ? envSoname :
						    (const char *)nullptr,
			"libLLVM-17.so",
			"libLLVM.so",
			"libLLVM-17.0.6.so",
		};
		for (const char *name : candidates) {
			if (!name) {
				SPDLOG_DEBUG(
					"LLVM-JIT: skipping empty LLVM SONAME candidate");
				continue;
			}
			auto ok =
				llvm::sys::DynamicLibrary::LoadLibraryPermanently(
					name);
			if (!ok) {
				SPDLOG_DEBUG(
					"LLVM-JIT: failed to preload {} for ORC runtime wrappers",
					name);
			}
			if (llvm::sys::DynamicLibrary::
				    SearchForAddressOfSymbol(
					    "llvm_orc_registerEHFrameSectionWrapper")) {
				SPDLOG_DEBUG(
					"LLVM-JIT: preloaded {} for ORC runtime wrappers",
					name);
				break;
			}
		}
	}
#endif
	auto jtmb = create_host_jit_target_machine_builder(vm);
	if (!jtmb) {
		exitOnErr(jtmb.takeError());
		return std::make_tuple(nullptr, std::vector<std::string>{},
				       std::vector<std::string>{});
	}
	LLJITBuilder jit_builder;
	jit_builder.setJITTargetMachineBuilder(std::move(*jtmb));
	auto jit_err = jit_builder.create();
	if (!jit_err) {
		exitOnErr(jit_err.takeError());
		return std::make_tuple(nullptr, std::vector<std::string>{},
				       std::vector<std::string>{});
	}
	auto jit = std::move(*jit_err);

#ifdef BPFTIME_ENABLE_LLVM_PRELOAD
	// Make current process symbols visible to the JIT if supported
#  if BPFTIME_HAVE_ORC_DYNLIB_SEARCH_GEN
	{
		auto &jd = jit->getMainJITDylib();
		auto gen = llvm::cantFail(
			llvm::orc::DynamicLibrarySearchGenerator::GetForCurrentProcess(
				jit->getDataLayout().getGlobalPrefix()));
		jd.addGenerator(std::move(gen));
	}
#  elif BPFTIME_HAVE_ORC_EXECUTIONUTILS
	{
		auto &jd = jit->getMainJITDylib();
		auto gen = llvm::cantFail(
			llvm::orc::DynamicLibrarySearchGenerator::GetForCurrentProcess(
				jit->getDataLayout().getGlobalPrefix()));
		jd.addGenerator(std::move(gen));
	}
#  else
	(void)0;
#  endif
#endif
	auto &mainDylib = jit->getMainJITDylib();
	std::vector<std::string> extFuncNames;
	// insert the helper functions
	SymbolMap extSymbols;
	for (uint32_t i = 0; i < std::size(vm.ext_funcs); i++) {
		if (vm.ext_funcs[i].has_value()) {
			auto sym = JITEvaluatedSymbol::fromPointer(
				vm.ext_funcs[i]->fn);
			auto symName = jit->getExecutionSession().intern(
				ext_func_sym(i));
			sym.setFlags(JITSymbolFlags::Callable |
				     JITSymbolFlags::Exported);

#if LLVM_VERSION_MAJOR < 17
			extSymbols.try_emplace(symName, sym);
			extFuncNames.push_back(ext_func_sym(i));
#else
			auto symbol = ::llvm::orc::ExecutorSymbolDef(
				::llvm::orc::ExecutorAddr(sym.getAddress()),
				sym.getFlags());
			extSymbols.try_emplace(symName, symbol);
			extFuncNames.emplace_back(ext_func_sym(i));
#endif
		}
	}
#if defined(__arm__) || defined(_M_ARM)
	SPDLOG_INFO("Defining __aeabi_unwind_cpp_pr1 on arm32");
	extSymbols.try_emplace(
		jit->getExecutionSession().intern("__aeabi_unwind_cpp_pr1"),
		JITEvaluatedSymbol::fromPointer(__aeabi_unwind_cpp_pr1));
#endif
#ifdef BPFTIME_ENABLE_LLVM_PRELOAD
	if (auto err = mainDylib.define(absoluteSymbols(extSymbols)); err) {
		SPDLOG_DEBUG("LLVM-JIT: failed to define external symbols");
	}
#else
	if (auto err = mainDylib.define(absoluteSymbols(extSymbols)); !err) {
		SPDLOG_DEBUG("LLVM-JIT: failed to define external symbols");
	}
#endif
	// Define lddw helpers
	SymbolMap lddwSyms;
	std::vector<std::string> definedLddwHelpers;
	const auto tryDefineLddwHelper = [&](const char *name, void *func) {
		if (func) {
			SPDLOG_DEBUG("Defining LDDW helper {} with addr {:x}",
				     name, (uintptr_t)func);
			auto sym = JITEvaluatedSymbol::fromPointer(func);
			// printf("The type of sym %s\n", typeid(sym).name());
			sym.setFlags(JITSymbolFlags::Callable |
				     JITSymbolFlags::Exported);

#if LLVM_VERSION_MAJOR < 17
			lddwSyms.try_emplace(
				jit->getExecutionSession().intern(name), sym);
			definedLddwHelpers.push_back(name);
#else
			auto symbol = ::llvm::orc::ExecutorSymbolDef(
				::llvm::orc::ExecutorAddr(sym.getAddress()),
				sym.getFlags());
			lddwSyms.try_emplace(
				jit->getExecutionSession().intern(name),
				symbol);
			definedLddwHelpers.emplace_back(name);
#endif
		}
	};
	// Only map_val will have a chance to be called at runtime, so it's the
	// only symbol to be defined
	tryDefineLddwHelper(LDDW_HELPER_MAP_VAL, (void *)vm.map_val);
	// These symbols won't be used at runtime, because we have already
	// do relocation when loading the eBPF bytecode
	// tryDefineLddwHelper(LDDW_HELPER_MAP_BY_FD, (void *)vm.map_by_fd);
	// tryDefineLddwHelper(LDDW_HELPER_MAP_BY_IDX, (void *)vm.map_by_idx);
	// tryDefineLddwHelper(LDDW_HELPER_CODE_ADDR, (void *)vm.code_addr);
	// tryDefineLddwHelper(LDDW_HELPER_VAR_ADDR, (void *)vm.var_addr);
#ifdef BPFTIME_ENABLE_LLVM_PRELOAD
	bool lddwDefinedOK = true;
	if (auto err = mainDylib.define(absoluteSymbols(lddwSyms)); err) {
		SPDLOG_DEBUG(
			"LLVM-JIT: failed to define lddw helpers symbols");
		lddwDefinedOK = false;
	}
	if (!lddwDefinedOK) {
		definedLddwHelpers.clear();
	}
#else
	if (auto err = mainDylib.define(absoluteSymbols(lddwSyms)); !err) {
		SPDLOG_DEBUG("LLVM-JIT: failed to define lddw helpers symbols");
	}
#endif
	return { std::move(jit), extFuncNames, definedLddwHelpers };
}

precompiled_ebpf_function llvm_bpf_jit_context::get_entry_address()
{
	if (!this->jit.has_value()) {
		SPDLOG_ERROR(
			"Not compiled yet. Unable to get entry func address");
		throw std::runtime_error("Not compiled yet");
	}
	if (auto err = (*jit)->lookup("bpf_main"); !err) {
		std::string buf;
		raw_string_ostream os(buf);
		os << err.takeError();
		SPDLOG_ERROR("Unable to find symbol `bpf_main`: {}", buf);
		throw std::runtime_error("Unable to link symbol `bpf_main`");
	} else {
		auto addr = err->toPtr<precompiled_ebpf_function>();
		SPDLOG_DEBUG("LLVM-JIT: Entry func is {:x}", (uintptr_t)addr);
		return addr;
	}
}

static std::unique_ptr<llvm::TargetMachine>
createNVPTXTargetMachine(const char *target_cpu)
{
	std::string error;
	const llvm::Target *target =
		llvm::TargetRegistry::lookupTarget("nvptx64", error);
	if (!target) {
		throw std::runtime_error("Failed to find NVPTX target: " +
					 error);
	}

	llvm::Triple triple("nvptx64-nvidia-cuda");

	llvm::TargetOptions options;
	options.FloatABIType = llvm::FloatABI::Default;
	auto result = std::unique_ptr<llvm::TargetMachine>(
		target->createTargetMachine(triple.str(), target_cpu, "",
					    options, llvm::Reloc::Static));
	return result;
}
std::optional<std::string>
llvm_bpf_jit_context::generate_ptx(bool main_with_arguments,
				   const std::string &func_name,
				   const char *target_cpu)
{
	static ExitOnError exitOnErr;
	spin_lock_guard guard(compiling.get());
	auto targetMachine = createNVPTXTargetMachine(target_cpu);
	std::vector<std::string> extFuncNames;
	for (uint32_t i = 0; i < std::size(vm.ext_funcs); i++) {
		if (vm.ext_funcs[i].has_value()) {
			extFuncNames.push_back(ext_func_sym(i));
		}
	}
	std::vector<std::string> definedLddwHelpers;
	const auto tryDefineLddwHelper = [&](const char *name, void *func) {
		if (func) {
			SPDLOG_DEBUG("Defining LDDW helper {} with addr {:x}",
				     name, (uintptr_t)func);
			definedLddwHelpers.push_back(name);
		}
	};
	// Only map_val will have a chance to be called at runtime, so it's the
	// only symbol to be defined
	tryDefineLddwHelper(LDDW_HELPER_MAP_VAL, (void *)vm.map_val);
	// These symbols won't be used at runtime, because we have already
	// do relocation when loading the eBPF bytecode
	// tryDefineLddwHelper(LDDW_HELPER_MAP_BY_FD, (void *)vm.map_by_fd);
	// tryDefineLddwHelper(LDDW_HELPER_MAP_BY_IDX, (void *)vm.map_by_idx);
	// tryDefineLddwHelper(LDDW_HELPER_CODE_ADDR, (void *)vm.code_addr);
	// tryDefineLddwHelper(LDDW_HELPER_VAR_ADDR, (void *)vm.var_addr);

	auto bpfModuleOrErr =
		generateModule(extFuncNames, definedLddwHelpers, true,
			       main_with_arguments, func_name, true);
	if (!bpfModuleOrErr) {
		exitOnErr(bpfModuleOrErr.takeError());
		return {};
	}

	// If successful, get the module
	auto bpfModule = std::move(*bpfModuleOrErr);
	// Optimize the module
	return bpfModule.withModuleDo([&](auto &M) {
		M.setDataLayout(targetMachine->createDataLayout());
		optimizeModule(M, vm.optimization_level, vm.disabled_passes_,
			       vm.log_passes_);

		llvm::legacy::PassManager passManager;
#if LLVM_VERSION_MAJOR > 17
		CodeGenFileType fileType = CodeGenFileType::AssemblyFile;
#else
		CodeGenFileType fileType = llvm::CGFT_AssemblyFile;

#endif
		SmallVector<char, 0> objStream;
		std::unique_ptr<raw_svector_ostream> BOS =
			std::make_unique<raw_svector_ostream>(objStream);

		if (targetMachine->addPassesToEmitFile(passManager, *BOS,
						       nullptr, fileType)) {
			throw std::runtime_error(
				"TargetMachine cannot emit a file of this type");
		}

		passManager.run(M);
		std::string result(objStream.begin(), objStream.end());

		return result;
	});
}

static std::unique_ptr<llvm::TargetMachine>
createSPIRVTargetMachine(const char *target_cpu)
{
	std::string error;
	const llvm::Target *target =
		llvm::TargetRegistry::lookupTarget("spirv64", error);
	if (!target) {
		throw std::runtime_error("Failed to find SPIR-V target: " +
					 error);
	}

	llvm::Triple triple("spirv64-unknown-unknown");

	llvm::TargetOptions options;
	options.FloatABIType = llvm::FloatABI::Default;
	auto result = std::unique_ptr<llvm::TargetMachine>(
		target->createTargetMachine(triple.str(), target_cpu, "",
					    options, llvm::Reloc::Static));
	return result;
}

std::optional<std::vector<uint8_t>>
llvm_bpf_jit_context::generate_spirv(bool main_with_arguments,
				     const std::string &func_name,
				     const char *target_env)
{
	// target_env can specify SPIR-V environment (e.g., "opencl2.0", "vulkan1.2")
	// Currently passed to LLVM target machine creation for future extensibility
	static ExitOnError exitOnErr;
	spin_lock_guard guard(compiling.get());
	auto targetMachine = createSPIRVTargetMachine(target_env);
	std::vector<std::string> extFuncNames;
	for (uint32_t i = 0; i < std::size(vm.ext_funcs); i++) {
		if (vm.ext_funcs[i].has_value()) {
			extFuncNames.push_back(ext_func_sym(i));
		}
	}
	std::vector<std::string> definedLddwHelpers;
	const auto tryDefineLddwHelper = [&](const char *name, void *func) {
		if (func) {
			SPDLOG_DEBUG("Defining LDDW helper {} with addr {:x}",
				     name, (uintptr_t)func);
			definedLddwHelpers.push_back(name);
		}
	};
	// Only map_val will have a chance to be called at runtime, so it's the
	// only symbol to be defined
	tryDefineLddwHelper(LDDW_HELPER_MAP_VAL, (void *)vm.map_val);
	// These symbols won't be used at runtime, because we have already
	// do relocation when loading the eBPF bytecode
	// tryDefineLddwHelper(LDDW_HELPER_MAP_BY_FD, (void *)vm.map_by_fd);
	// tryDefineLddwHelper(LDDW_HELPER_MAP_BY_IDX, (void *)vm.map_by_idx);
	// tryDefineLddwHelper(LDDW_HELPER_CODE_ADDR, (void *)vm.code_addr);
	// tryDefineLddwHelper(LDDW_HELPER_VAR_ADDR, (void *)vm.var_addr);

	auto bpfModuleOrErr =
		generateModule(extFuncNames, definedLddwHelpers, true,
			       main_with_arguments, func_name, true);
	if (!bpfModuleOrErr) {
		exitOnErr(bpfModuleOrErr.takeError());
		return {};
	}

	// If successful, get the module
	auto bpfModule = std::move(*bpfModuleOrErr);
	// Optimize the module
	return bpfModule.withModuleDo([&](auto &M) -> std::optional<std::vector<uint8_t>> {
		M.setDataLayout(targetMachine->createDataLayout());

		// Run optimizations to clean up unreachable blocks and simplify code
		optimizeModule(M, vm.optimization_level, vm.disabled_passes_,
			       vm.log_passes_);

		llvm::legacy::PassManager passManager;
#if LLVM_VERSION_MAJOR > 17
		CodeGenFileType fileType = CodeGenFileType::ObjectFile;
#else
		CodeGenFileType fileType = llvm::CGFT_ObjectFile;
#endif
		SmallVector<char, 0> objStream;
		std::unique_ptr<raw_svector_ostream> BOS =
			std::make_unique<raw_svector_ostream>(objStream);

		if (targetMachine->addPassesToEmitFile(passManager, *BOS,
						       nullptr, fileType)) {
			SPDLOG_ERROR(
				"TargetMachine cannot emit a SPIR-V file of this type");
			return {};
		}

		passManager.run(M);
		std::vector<uint8_t> result(objStream.begin(), objStream.end());

		return result;
	});
}
