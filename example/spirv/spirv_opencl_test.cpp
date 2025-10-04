#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Support/Error.h>
#include <llvm_jit_context.hpp>
#include <ebpf_inst.h>
#include <fstream>
#include <vector>

#define CL_TARGET_OPENCL_VERSION 300
#include <CL/cl.h>

using namespace bpftime;
using namespace std;

static llvm::ExitOnError exitOnError;

// SPIR-V opcodes (from SPIR-V specification)
constexpr uint16_t OpMemoryModel = 14;
constexpr uint16_t OpCapability = 17;
constexpr uint16_t OpFunction = 54;
constexpr uint16_t OpDecorate = 71;
constexpr uint32_t LinkageCapability = 5;
constexpr uint32_t LinkageAttributesDecoration = 41;

// Patch SPIR-V binary to add OpEntryPoint for OpenCL kernel
// This converts a regular function into a kernel entry point
std::vector<uint8_t> patch_spirv_add_entry_point(const std::vector<uint8_t>& spirv_in) {
	std::vector<uint8_t> spirv = spirv_in;

	// SPIR-V structure:
	// - Header (5 words)
	// - OpCapability instructions
	// - OpExtInstImport
	// - OpMemoryModel
	// - OpEntryPoint << We need to add this
	// - OpExecutionMode << And this
	// - OpSource
	// - Rest of the module

	// Find the position after OpMemoryModel (opcode 14) and find bpf_main function ID
	size_t insert_pos = 20; // After 5-word header (skip magic, version, generator, bound, schema)
	uint32_t bpf_main_id = 0;
	size_t linkage_cap_pos = 0;
	size_t linkage_attr_pos = 0;

	// First pass: find OpMemoryModel, OpCapability Linkage, OpDecorate LinkageAttributes, and bpf_main function
	size_t scan_pos = 20;
	while (scan_pos < spirv.size()) {
		uint32_t* word = (uint32_t*)&spirv[scan_pos];
		uint16_t opcode = *word & 0xFFFF;
		uint16_t word_count = (*word >> 16) & 0xFFFF;

		if (opcode == OpCapability) {
			uint32_t capability = *(word + 1);
			if (capability == LinkageCapability) {
				linkage_cap_pos = scan_pos;
			}
		}

		if (opcode == OpMemoryModel) {
			insert_pos = scan_pos + word_count * 4;
		}

		// OpDecorate - check if this is LinkageAttributes
		if (opcode == OpDecorate && word_count >= 3) {
			uint32_t decoration = *(word + 2);
			if (decoration == LinkageAttributesDecoration) {
				uint32_t target_id = *(word + 1);
				// We'll check if this is for bpf_main later
				if (linkage_attr_pos == 0 || target_id == bpf_main_id) {
					linkage_attr_pos = scan_pos;
				}
			}
		}

		// OpFunction - check if this is bpf_main
		if (opcode == OpFunction && word_count >= 5) {
			uint32_t function_result_id = *(word + 2);
			// We'll verify this is bpf_main by checking OpName later
			// For now, assume the first OpFunction after OpMemoryModel is bpf_main
			if (bpf_main_id == 0) {
				bpf_main_id = function_result_id;
			}
		}

		scan_pos += word_count * 4;
		if (scan_pos >= spirv.size()) break; // Safety check: prevent out-of-bounds
	}

	if (bpf_main_id == 0) {
		std::cerr << "Warning: Could not find bpf_main function ID, using default" << std::endl;
		bpf_main_id = 5; // Fallback
	}

	// Remove OpCapability Linkage (opcode 17, capability 5)
	if (linkage_cap_pos > 0) {
		uint32_t* word = (uint32_t*)&spirv[linkage_cap_pos];
		uint16_t word_count = (*word >> 16) & 0xFFFF;
		spirv.erase(spirv.begin() + linkage_cap_pos,
		            spirv.begin() + linkage_cap_pos + word_count * 4);

		// Adjust insert_pos if it's after the removed capability
		if (insert_pos > linkage_cap_pos) {
			insert_pos -= word_count * 4;
		}
		// Adjust linkage_attr_pos if it's after the removed capability
		if (linkage_attr_pos > linkage_cap_pos) {
			linkage_attr_pos -= word_count * 4;
		}
	}

	// Remove OpDecorate LinkageAttributes for bpf_main
	if (linkage_attr_pos > 0) {
		uint32_t* word = (uint32_t*)&spirv[linkage_attr_pos];
		uint16_t word_count = (*word >> 16) & 0xFFFF;
		spirv.erase(spirv.begin() + linkage_attr_pos,
		            spirv.begin() + linkage_attr_pos + word_count * 4);

		// Adjust insert_pos if it's after the removed decoration
		if (insert_pos > linkage_attr_pos) {
			insert_pos -= word_count * 4;
		}
	}

	// Create OpEntryPoint instruction
	// OpEntryPoint Kernel %bpf_main "bpf_main"
	// Format: [word_count << 16 | opcode] [execution_model] [entry_point_id] [name...]
	std::string kernel_name = "bpf_main";
	size_t name_words = (kernel_name.length() + 1 + 3) / 4; // +1 for null, round up to word boundary
	uint16_t entry_point_word_count = 3 + name_words;

	std::vector<uint32_t> entry_point_inst;
	entry_point_inst.push_back((entry_point_word_count << 16) | 15); // OpEntryPoint = 15
	entry_point_inst.push_back(6); // Kernel execution model
	entry_point_inst.push_back(bpf_main_id); // %bpf_main function ID (dynamically found)

	// Add kernel name as words
	for (size_t i = 0; i < name_words; i++) {
		uint32_t word = 0;
		for (int j = 0; j < 4 && (i * 4 + j) <= kernel_name.length(); j++) {
			word |= ((uint32_t)kernel_name[i * 4 + j]) << (j * 8);
		}
		entry_point_inst.push_back(word);
	}

	// Insert the OpEntryPoint instruction
	spirv.insert(spirv.begin() + insert_pos,
	             (uint8_t*)entry_point_inst.data(),
	             (uint8_t*)entry_point_inst.data() + entry_point_inst.size() * 4);

	return spirv;
}

static uint64_t test_func(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t)
{
	return 0;
}

#define CL_CHECK(x)                                                            \
	do {                                                                   \
		cl_int err = x;                                                \
		if (err != CL_SUCCESS) {                                       \
			printf("OpenCL error: %s failed with error %d\n", #x,  \
			       err);                                           \
			exit(1);                                               \
		}                                                              \
	} while (0)

/**
 * Simple eBPF program that performs basic arithmetic
 * Input: pointer to int array
 * Reads from arr[0], adds 42, writes to arr[1]
 *
 * Equivalent C code:
 * void bpf_main(int* arr, unsigned long len) {
 *     arr[1] = arr[0] + 42;
 * }
 */
static const struct ebpf_inst test_prog[] = {
	// r6 = r1 (save array pointer)
	{ EBPF_OP_MOV64_REG, 6, 1, 0, 0 },
	// r1 = *(u32 *)(r6 + 0) - load arr[0]
	{ EBPF_OP_LDXW, 1, 6, 0, 0 },
	// r1 += 42
	{ EBPF_OP_ADD64_IMM, 1, 0, 0, 42 },
	// *(u32 *)(r6 + 4) = r1 - store to arr[1]
	{ EBPF_OP_STXW, 6, 1, 4, 0 },
	// exit
	{ EBPF_OP_EXIT, 0, 0, 0, 0 }
};

int main()
{
	// Initialize LLVM components for all targets
	llvm::InitializeAllTargetInfos();
	llvm::InitializeAllTargets();
	llvm::InitializeAllTargetMCs();
	llvm::InitializeAllAsmPrinters();
	llvm::InitializeAllAsmParsers();

	// Verify SPIR-V target is available
	std::string error;
	const llvm::Target *spirv_target =
		llvm::TargetRegistry::lookupTarget("spirv64", error);
	if (!spirv_target) {
		std::cerr << "SPIR-V target not found: " << error << std::endl;
		std::cerr << "This requires LLVM 16+ with SPIR-V backend support"
			  << std::endl;
		return 1;
	}
	std::cout << "SPIR-V target found successfully" << std::endl;

	// Set up llvmbpf VM
	llvmbpf_vm vm;
	vm.register_external_function(1, "test_func", (void *)test_func);

	// Load eBPF program
	if (vm.load_code((void *)test_prog, sizeof(test_prog)) != 0) {
		std::cerr << "Failed to load eBPF code: "
			  << vm.get_error_message() << std::endl;
		return 1;
	}

	// Generate SPIR-V
	std::cout << "Generating SPIR-V from eBPF program..." << std::endl;
	auto spirv_result = vm.generate_spirv("");
	if (!spirv_result) {
		std::cerr << "Failed to generate SPIR-V: "
			  << vm.get_error_message() << std::endl;
		return 1;
	}

	std::vector<uint8_t> spirv_binary = *spirv_result;
	std::cout << "Generated SPIR-V binary: " << spirv_binary.size()
		  << " bytes" << std::endl;

	// Patch SPIR-V to add OpEntryPoint (similar to PTX's .entry patch)
	std::cout << "Patching SPIR-V to add kernel entry point..." << std::endl;
	spirv_binary = patch_spirv_add_entry_point(spirv_binary);
	std::cout << "Patched SPIR-V binary: " << spirv_binary.size()
		  << " bytes" << std::endl;

	// Save SPIR-V to file for inspection
	std::ofstream spirv_file("bpf_program.spv",
				 std::ios::binary | std::ios::out);
	spirv_file.write((char *)spirv_binary.data(), spirv_binary.size());
	spirv_file.close();
	std::cout << "SPIR-V binary saved to bpf_program.spv" << std::endl;

	// Initialize OpenCL
	cl_platform_id platform;
	cl_device_id device;
	cl_context context;
	cl_command_queue queue;
	cl_program program;
	cl_kernel kernel;
	cl_int err;

	// Get all platforms and try to find a device
	cl_uint num_platforms;
	CL_CHECK(clGetPlatformIDs(0, NULL, &num_platforms));
	std::vector<cl_platform_id> platforms(num_platforms);
	CL_CHECK(clGetPlatformIDs(num_platforms, platforms.data(), NULL));

	bool device_found = false;
	for (cl_uint i = 0; i < num_platforms && !device_found; i++) {
		platform = platforms[i];
		char platform_name[128];
		clGetPlatformInfo(platform, CL_PLATFORM_NAME,
				  sizeof(platform_name), platform_name, NULL);

		// Try GPU first
		err = clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 1, &device,
				     NULL);
		if (err == CL_SUCCESS) {
			device_found = true;
			std::cout << "Found GPU on platform: "
				  << platform_name << std::endl;
			break;
		}

		// Try CPU as fallback
		err = clGetDeviceIDs(platform, CL_DEVICE_TYPE_CPU, 1, &device,
				     NULL);
		if (err == CL_SUCCESS) {
			device_found = true;
			std::cout << "Found CPU on platform: "
				  << platform_name << std::endl;
			break;
		}
	}

	if (!device_found) {
		std::cerr << "No OpenCL devices found on any platform!"
			  << std::endl;
		return 1;
	}

	// Get device name
	char device_name[128];
	CL_CHECK(clGetDeviceInfo(device, CL_DEVICE_NAME, sizeof(device_name),
				 device_name, NULL));
	std::cout << "Using OpenCL device: " << device_name << std::endl;

	// Create context
	context = clCreateContext(NULL, 1, &device, NULL, NULL, &err);
	CL_CHECK(err);

	// Create command queue
	queue = clCreateCommandQueueWithProperties(context, device, 0, &err);
	CL_CHECK(err);

	// Create program from SPIR-V binary
	std::cout << "Loading SPIR-V binary into OpenCL..." << std::endl;
	program = clCreateProgramWithIL(context, spirv_binary.data(),
					spirv_binary.size(), &err);
	if (err != CL_SUCCESS) {
		std::cerr
			<< "Failed to create program from SPIR-V (error code: "
			<< err << ")" << std::endl;
		std::cerr
			<< "Your OpenCL implementation may not support SPIR-V IL"
			<< std::endl;
		return 1;
	}

	// Build program
	std::cout << "Building OpenCL program..." << std::endl;
	err = clBuildProgram(program, 1, &device, "", NULL, NULL);
	if (err != CL_SUCCESS) {
		// Get build log
		size_t log_size;
		clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, 0,
				      NULL, &log_size);
		std::vector<char> log(log_size);
		clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG,
				      log_size, log.data(), NULL);
		std::cerr << "Build error:\n" << log.data() << std::endl;
		return 1;
	}

	// Create kernel
	std::cout << "Creating kernel 'bpf_main'..." << std::endl;
	kernel = clCreateKernel(program, "bpf_main", &err);
	if (err != CL_SUCCESS) {
		// Try to get kernel names
		cl_uint num_kernels;
		clCreateKernelsInProgram(program, 0, NULL, &num_kernels);
		std::cerr << "Failed to create kernel. Number of kernels in program: " << num_kernels << std::endl;
	}
	CL_CHECK(err);

	// Prepare input/output data (arr[0] = 100, arr[1] will be set to 100+42=142)
	int data[4] = { 100, 0, 0, 0 };

	// Create buffer for the array (read-write)
	cl_mem buffer = clCreateBuffer(
		context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR,
		sizeof(data), data, &err);
	CL_CHECK(err);

	// Set kernel arguments: (buffer, size)
	uint64_t buffer_size = sizeof(data);
	CL_CHECK(clSetKernelArg(kernel, 0, sizeof(cl_mem), &buffer));
	CL_CHECK(clSetKernelArg(kernel, 1, sizeof(uint64_t), &buffer_size));

	// Execute kernel
	std::cout << "Executing eBPF program on GPU via OpenCL..."
		  << std::endl;
	size_t global_work_size = 1;
	CL_CHECK(clEnqueueNDRangeKernel(queue, kernel, 1, NULL,
					&global_work_size, NULL, 0, NULL,
					NULL));

	// Read result back
	CL_CHECK(clEnqueueReadBuffer(queue, buffer, CL_TRUE, 0,
				     sizeof(data), data, 0, NULL, NULL));

	// Verify result
	std::cout << "Input value (arr[0]): " << data[0] << std::endl;
	std::cout << "Expected output (arr[1]): " << (data[0] + 42) << std::endl;
	std::cout << "Actual output (arr[1]): " << data[1] << std::endl;

	bool success = (data[1] == data[0] + 42);
	if (success) {
		std::cout << "✓ Test PASSED!" << std::endl;
	} else {
		std::cout << "✗ Test FAILED!" << std::endl;
	}

	// Cleanup
	clReleaseMemObject(buffer);
	clReleaseKernel(kernel);
	clReleaseProgram(program);
	clReleaseCommandQueue(queue);
	clReleaseContext(context);

	return success ? 0 : 1;
}
