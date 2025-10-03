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
 * Input: array of integers
 * Output: sum of first element + 42
 *
 * Equivalent C code:
 * int bpf_main(void* ctx, unsigned long len) {
 *     int* arr = (int*)ctx;
 *     return arr[0] + 42;
 * }
 */
static const struct ebpf_inst test_prog[] = {
	// r6 = r1 (save input pointer)
	{ EBPF_OP_MOV64_REG, 6, 1, 0, 0 },
	// r1 = *(u32 *)(r6 + 0) - load first integer
	{ EBPF_OP_LDXW, 1, 6, 0, 0 },
	// r1 += 42
	{ EBPF_OP_ADD64_IMM, 1, 0, 0, 42 },
	// r0 = r1 (set return value)
	{ EBPF_OP_MOV64_REG, 0, 1, 0, 0 },
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

	// Prepare input/output data
	int input_data[4] = { 100, 200, 300, 400 };
	int output_data = 0;

	// Create buffers
	cl_mem input_buffer = clCreateBuffer(
		context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
		sizeof(input_data), input_data, &err);
	CL_CHECK(err);

	cl_mem output_buffer =
		clCreateBuffer(context, CL_MEM_WRITE_ONLY, sizeof(int), NULL,
			       &err);
	CL_CHECK(err);

	// Set kernel arguments
	uint64_t input_size = sizeof(input_data);
	CL_CHECK(clSetKernelArg(kernel, 0, sizeof(cl_mem), &input_buffer));
	CL_CHECK(clSetKernelArg(kernel, 1, sizeof(uint64_t), &input_size));

	// Execute kernel
	std::cout << "Executing eBPF program on GPU via OpenCL..."
		  << std::endl;
	size_t global_work_size = 1;
	CL_CHECK(clEnqueueNDRangeKernel(queue, kernel, 1, NULL,
					&global_work_size, NULL, 0, NULL,
					NULL));

	// Read result
	CL_CHECK(clEnqueueReadBuffer(queue, output_buffer, CL_TRUE, 0,
				     sizeof(int), &output_data, 0, NULL,
				     NULL));

	// Verify result
	std::cout << "Input value: " << input_data[0] << std::endl;
	std::cout << "Expected output: " << (input_data[0] + 42) << std::endl;
	std::cout << "Actual output: " << output_data << std::endl;

	bool success = (output_data == input_data[0] + 42);
	if (success) {
		std::cout << "✓ Test PASSED!" << std::endl;
	} else {
		std::cout << "✗ Test FAILED!" << std::endl;
	}

	// Cleanup
	clReleaseMemObject(input_buffer);
	clReleaseMemObject(output_buffer);
	clReleaseKernel(kernel);
	clReleaseProgram(program);
	clReleaseCommandQueue(queue);
	clReleaseContext(context);

	return success ? 0 : 1;
}
