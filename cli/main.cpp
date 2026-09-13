#include "spdlog/spdlog.h"
#include "spdlog/cfg/env.h"
#include <cstdarg>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <libelf.h>
#include <gelf.h>
#include <map>
#include <string>
#include <unistd.h>
#include <fstream>
#include "llvmbpf.hpp"

/*
 * Forward declarations from libbpf.  We cannot include <bpf/libbpf.h>
 * because linux/bpf.h re-defines the BPF_REG_* enum that ebpf_inst.h
 * already provides.
 */
extern "C" {
struct bpf_object;
struct bpf_program;
struct bpf_insn;
void bpf_object__close(bpf_object *obj);
bpf_program *bpf_object__next_program(const bpf_object *obj, bpf_program *prog);
const char *bpf_program__name(const bpf_program *prog);
const char *bpf_program__section_name(const bpf_program *prog);
bpf_object *bpf_object__open(const char *path);
const bpf_insn *bpf_program__insns(const bpf_program *prog);
size_t bpf_program__insn_cnt(const bpf_program *prog);

struct btf;
struct btf *btf__new(const void *data, uint32_t size);
void btf__free(struct btf *btf);
const char *btf__str_by_offset(const struct btf *btf, uint32_t off);
}

using namespace bpftime;

// BTF is always in host endian, so a plain memcpy is correct.
static inline uint32_t read_u32(const uint8_t *p)
{
	uint32_t v;
	memcpy(&v, p, sizeof(v));
	return v;
}

/*
 * Decode the line_info blob from a BTF.ext section.
 *
 * BTF.ext layout (all u32, host-endian):
 *   [0] magic  [4] hdr_len  [8] func_info_off  [12] func_info_len
 *   [16] line_info_off  [20] line_info_len
 *
 * Line info blob (at hdr_len + line_info_off):
 *   rec_size(4), then per-section blocks of:
 *     sec_name_off(4) num_info(4) records[num_info]
 *   Each record: insn_off(4) file_name_off(4) line_off(4) line_col(4)
 */
static void decode_btf_ext_line_info(
	const uint8_t *ext_data, size_t ext_size, struct btf *btf,
	std::map<std::string, std::vector<btf_line_info_entry>> &out)
{
	if (ext_size < 24)
		return;

	uint32_t hdr_len = read_u32(ext_data + 4);
	uint32_t li_off = read_u32(ext_data + 16);
	uint32_t li_len = read_u32(ext_data + 20);

	if (li_len == 0)
		return;
	if ((uint64_t)hdr_len + li_off + li_len > ext_size)
		return;

	const uint8_t *p = ext_data + hdr_len + li_off;
	uint32_t rec_size = read_u32(p);
	p += 4;
	uint32_t remaining = li_len - 4;

	while (remaining >= 8) {
		uint32_t sec_name_off = read_u32(p);
		uint32_t num_info = read_u32(p + 4);
		const char *sec = btf__str_by_offset(btf, sec_name_off);
		p += 8;
		remaining -= 8;

		std::vector<btf_line_info_entry> entries;
		for (uint32_t i = 0;
		     i < num_info && remaining >= rec_size; i++) {
			uint32_t line_col = read_u32(p + 12);
			uint32_t fname_off = read_u32(p + 4);
			const char *fname = btf__str_by_offset(btf,
							       fname_off);
			entries.push_back({
				.insn_idx = read_u32(p) / 8,
				.file_name = fname ? fname : "",
				.line = line_col >> 10,
				.col = line_col & 0x3FF,
			});
			p += rec_size;
			remaining -= rec_size;
		}
		if (sec)
			out[sec] = std::move(entries);
	}
}

/*
 * Parse BTF.ext line info from an ELF file.  Returns a map keyed by
 * section name.  We parse BTF.ext ourselves because libbpf only
 * populates bpf_program__line_info() after bpf_object__load().
 */
static std::map<std::string, std::vector<btf_line_info_entry>>
parse_btf_ext_line_info(const std::string &elf_path)
{
	std::map<std::string, std::vector<btf_line_info_entry>> result;

	if (elf_version(EV_CURRENT) == EV_NONE)
		return result;

	int fd = open(elf_path.c_str(), O_RDONLY);
	if (fd < 0)
		return result;

	Elf *elf = elf_begin(fd, ELF_C_READ, nullptr);
	if (!elf) {
		close(fd);
		return result;
	}

	size_t shstrndx;
	elf_getshdrstrndx(elf, &shstrndx);

	Elf_Data *btf_data = nullptr, *btf_ext_data = nullptr;
	for (Elf_Scn *scn = nullptr;
	     (scn = elf_nextscn(elf, scn)) != nullptr;) {
		GElf_Shdr shdr;
		if (!gelf_getshdr(scn, &shdr))
			continue;
		const char *name = elf_strptr(elf, shstrndx, shdr.sh_name);
		if (!name)
			continue;
		if (!strcmp(name, ".BTF"))
			btf_data = elf_getdata(scn, nullptr);
		else if (!strcmp(name, ".BTF.ext"))
			btf_ext_data = elf_getdata(scn, nullptr);
	}

	if (btf_data && btf_ext_data) {
		struct btf *btf = btf__new(btf_data->d_buf,
					   btf_data->d_size);
		if (btf) {
			decode_btf_ext_line_info(
				static_cast<const uint8_t *>(
					btf_ext_data->d_buf),
				btf_ext_data->d_size, btf, result);
			btf__free(btf);
		}
	}

	elf_end(elf);
	close(fd);
	return result;
}

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

uint64_t bpftime_trace_printk(uint64_t fmt, uint64_t fmt_size, ...)
{
	const char *fmt_str = (const char *)fmt;
	va_list args;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#pragma GCC diagnostic ignored "-Wvarargs"
	va_start(args, fmt_str);
	long ret = vprintf(fmt_str, args);
#pragma GCC diagnostic pop
	va_end(args);
	return 0;
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

	auto all_line_info = parse_btf_ext_line_info(ebpf_elf);
	bpf_program *prog;
	bool had_failure = false;
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
			had_failure = true;
			continue;
		}
		const char *sec = bpf_program__section_name(prog);
		if (sec) {
			auto it = all_line_info.find(sec);
			if (it != all_line_info.end())
				vm.load_line_info(it->second);
		}
		// add 1000 pesudo helpers so it can be used with helpers
		for (int i = 0; i < 1000; i++) {
			vm.register_external_function(
				i, "helper_" + std::to_string(i), nullptr);
		}
		auto result = vm.do_aot_compile(emit_llvm);
		if (!result) {
			SPDLOG_ERROR("Failed to compile program {}: {}", name,
				     vm.get_error_message());
			had_failure = true;
			continue;
		}
		auto out_path = output / (std::string(name) + ".o");
		std::ofstream ofs(out_path, std::ios::binary);
		if (!ofs.is_open()) {
			SPDLOG_ERROR("Failed to open output file for program {}: {}",
				     name, out_path.string());
			had_failure = true;
			continue;
		}
		ofs.write((const char *)result->data(), result->size());
		if (!ofs.good()) {
			SPDLOG_ERROR("Failed to write output file for program {}: {}",
				     name, out_path.string());
			had_failure = true;
			continue;
		}
		if (!emit_llvm)
			SPDLOG_INFO("Program {} written to {}", name,
				    out_path.c_str());
	}
	return had_failure ? 1 : 0;
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
	vm.register_external_function(6, "bpf_trace_printk",
				      (void *)bpftime_trace_printk);
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
