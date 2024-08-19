#include "spdlog/spdlog.h"
#include "spdlog/cfg/env.h"
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <libelf.h>
#include <string>
#include <unistd.h>
#include <fstream>
#include "llvmbpf.hpp"

extern "C" {
struct bpf_object;
struct bpf_program;
struct bpf_insn;
void bpf_object__close(bpf_object *obj);
bpf_program *bpf_object__next_program(const bpf_object *obj, bpf_program *prog);
const char *bpf_program__name(const bpf_program *prog);
bpf_object *bpf_object__open(const char *path);
const bpf_insn *bpf_program__insns(const bpf_program *prog);
size_t bpf_program__insn_cnt(const bpf_program *prog);
}

using namespace bpftime;

static void print_usage(const std::string &program_name)
{
	std::cerr
		<< "Usage: " << program_name << " <command> [options]\n"
		<< "Commands:\n"
		<< "  build <EBPF_ELF> [-o <output_directory>] [-emit-llvm]\n"
		<< "      Build native ELF(s) from eBPF ELF. Each program in the eBPF ELF will be built into a single native ELF.\n"
		<< "      If -emit-llvm is specified, the LLVM IR will be printed to stdout.\n"
		<< "  run <PATH> [MEMORY]\n"
		<< "      Run a native eBPF program.\n";
}

static std::optional<std::string>
parse_optional_argument(int argc, const char **argv, int &i,
			const std::string &option)
{
	if (std::string(argv[i]) == option && i + 1 < argc) {
		return argv[++i];
	}
	return std::nullopt;
}

static bool has_argument(int argc, const char **argv, const std::string &option)
{
	for (int i = 0; i < argc; ++i) {
		if (std::string(argv[i]) == option) {
			return true;
		}
	}
	return false;
}

static int build_ebpf_program(const std::string &ebpf_elf,
			      const std::filesystem::path &output,
			      bool emit_llvm)
{
	bpf_object *obj = bpf_object__open(ebpf_elf.c_str());
	if (!obj) {
		SPDLOG_CRITICAL("Unable to open BPF ELF: {}", errno);
		return 1;
	}
	std::unique_ptr<bpf_object, decltype(&bpf_object__close)> elf(
		obj, bpf_object__close);
	bpf_program *prog;
	for ((prog) = bpf_object__next_program((elf.get()), __null);
	     (prog) != __null;
	     (prog) = bpf_object__next_program((elf.get()), (prog))) {
		const char *name = bpf_program__name(prog);
		if (!emit_llvm)
			SPDLOG_INFO("Processing program {}", name);
		llvmbpf_vm vm;

		if (vm.load_code((const void *)bpf_program__insns(prog),
				 (uint32_t)bpf_program__insn_cnt(prog) * 8) <
		    0) {
			SPDLOG_ERROR(
				"Unable to load instructions of program {}: {}",
				name, vm.get_error_message());
			return 1;
		}
		// add 1000 pesudo helpers so it can be used with helpers
		for (int i = 0; i < 1000; i++) {
			vm.register_external_function(
				i, "helper_" + std::to_string(i), nullptr);
		}
		auto result = vm.do_aot_compile(emit_llvm);

		auto out_path = output / (std::string(name) + ".o");
		std::ofstream ofs(out_path, std::ios::binary);
		ofs.write((const char *)result.data(), result.size());
		if (!emit_llvm)
			SPDLOG_INFO("Program {} written to {}", name,
				    out_path.c_str());
	}
	return 0;
}

using bpf_func = uint64_t (*)(const void *, uint64_t);

static int run_ebpf_program(const std::filesystem::path &elf,
			    std::optional<std::string> memory)
{
	std::ifstream file(elf, std::ios::binary | std::ios::ate);
	if (!file.is_open()) {
		SPDLOG_CRITICAL("Unable to open ELF file: {}", elf.string());
		return 1;
	}

	auto size = file.tellg();
	std::vector<uint8_t> file_buffer(size);

	file.seekg(0, std::ios::beg);
	if (!file.read((char *)file_buffer.data(), size)) {
		SPDLOG_CRITICAL("Failed to read ELF file: {}", elf.string());
		return 1;
	}

	file.close();

	llvmbpf_vm vm;
	auto func = vm.load_aot_object(file_buffer);
	if (!func) {
		SPDLOG_CRITICAL("Failed to load AOT object from ELF file: {}",
				vm.get_error_message());
		return 1;
	}

	uint64_t return_val;
	if (memory) {
		std::ifstream mem_file(*memory,
				       std::ios::binary | std::ios::ate);
		if (!mem_file.is_open()) {
			SPDLOG_CRITICAL("Unable to open memory file: {}",
					*memory);
			return 1;
		}

		auto mem_size = mem_file.tellg();
		std::vector<uint8_t> mem_buffer(mem_size);

		mem_file.seekg(0, std::ios::beg);
		if (!mem_file.read((char *)mem_buffer.data(), mem_size)) {
			SPDLOG_CRITICAL("Failed to read memory file: {}",
					*memory);
			return 1;
		}

		mem_file.close();

		int res = vm.exec(mem_buffer.data(), mem_buffer.size(),
				  return_val);
		if (res < 0) {
			SPDLOG_CRITICAL("Execution failed: {}",
					vm.get_error_message());
			return 1;
		}
	} else {
		int res = vm.exec(nullptr, 0, return_val);
		if (res < 0) {
			SPDLOG_CRITICAL("Execution failed: {}",
					vm.get_error_message());
			return 1;
		}
	}

	SPDLOG_INFO("Program executed successfully. Return value: {}",
		    return_val);
	return 0;
}

int main(int argc, const char **argv)
{
	spdlog::cfg::load_env_levels();

	// Check for at least one argument (the command)
	if (argc < 2) {
		print_usage(argv[0]);
		return 1;
	}

	std::string command = argv[1];

	if (command == "build") {
		if (argc < 3) {
			print_usage(argv[0]);
			return 1;
		}

		std::string ebpf_elf = argv[2];
		std::string output = ".";

		// Parse optional output argument
		for (int i = 3; i < argc; ++i) {
			auto opt_output =
				parse_optional_argument(argc, argv, i, "-o");
			if (opt_output) {
				output = *opt_output;
			}
		}

		bool emit_llvm = has_argument(argc, argv, "-emit-llvm");

		return build_ebpf_program(ebpf_elf, output, emit_llvm);
	} else if (command == "run") {
		if (argc < 3) {
			print_usage(argv[0]);
			return 1;
		}

		std::filesystem::path elf_path = argv[2];
		std::optional<std::string> memory_file;

		if (argc > 3) {
			memory_file = argv[3];
		}

		return run_ebpf_program(elf_path, memory_file);
	} else {
		std::cerr << "Unknown command: " << command << "\n";
		print_usage(argv[0]);
		return 1;
	}
}
