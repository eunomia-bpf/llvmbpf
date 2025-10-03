# SPIR-V Generation for OpenCL/Vulkan

This example demonstrates how to compile eBPF programs to SPIR-V and execute them on GPUs using OpenCL.

## Overview

SPIR-V (Standard Portable Intermediate Representation - V) is a cross-vendor intermediate language for parallel compute and graphics. Unlike PTX which is NVIDIA-specific, SPIR-V can run on:

- **Intel GPUs** (Intel Compute Runtime)
- **AMD GPUs** (ROCm, clspv)
- **NVIDIA GPUs** (via CUDA/OpenCL)
- **ARM Mali GPUs**
- **Qualcomm Adreno GPUs**
- **CPU implementations** (pocl, Intel OpenCL CPU runtime)

## Requirements

### Build Requirements

- **LLVM 18+** (LLVM 20+ has native SPIR-V backend, LLVM 18-19 requires llvm-spirv translator)
- **OpenCL development files**:
  ```bash
  # Ubuntu/Debian
  sudo apt install opencl-headers ocl-icd-opencl-dev

  # Fedora/RHEL
  sudo dnf install opencl-headers ocl-icd-devel
  ```

### Runtime Requirements

- **OpenCL ICD loader** (usually installed with dev packages)
- **OpenCL driver** for your hardware:
  - **Intel**: `intel-opencl-icd` or Intel Compute Runtime
  - **NVIDIA**: CUDA toolkit provides OpenCL support
  - **AMD**: ROCm or amdgpu-pro drivers
  - **CPU fallback**: `pocl-opencl-icd`

## Building

```bash
# Install LLVM 20 (recommended for native SPIR-V support)
sudo apt install llvm-20-dev

# Configure with SPIR-V support
cmake -B build -DCMAKE_BUILD_TYPE=Release \
    -DLLVMBPF_ENABLE_SPIRV=1 \
    -DLLVM_DIR=/usr/lib/llvm-20/cmake

# Build
cmake --build build --target spirv_opencl_test -j

# Run the example
./build/example/spirv/spirv_opencl_test
```

## Example Program

The test program demonstrates:

1. **eBPF Program Definition**: Simple arithmetic operation
2. **SPIR-V Generation**: Compiling eBPF → LLVM IR → SPIR-V binary
3. **OpenCL Execution**: Loading SPIR-V into OpenCL and running on GPU
4. **Verification**: Comparing GPU results with expected output

### eBPF Program

```c
// Equivalent C code
int bpf_main(void* ctx, unsigned long len) {
    int* arr = (int*)ctx;
    return arr[0] + 42;
}
```

### Expected Output

```
SPIR-V target found successfully
Generating SPIR-V from eBPF program...
Generated SPIR-V binary: XXXX bytes
SPIR-V binary saved to bpf_program.spv
Using OpenCL device: NVIDIA GeForce RTX 3080
Loading SPIR-V binary into OpenCL...
Building OpenCL program...
Executing eBPF program on GPU via OpenCL...
Input value: 100
Expected output: 142
Actual output: 142
✓ Test PASSED!
```

## Validating SPIR-V Output

You can validate the generated SPIR-V binary using the SPIR-V tools:

```bash
# Install SPIR-V tools
sudo apt install spirv-tools

# Validate the binary
spirv-val bpf_program.spv

# Disassemble to human-readable format
spirv-dis bpf_program.spv -o bpf_program.spvasm

# Inspect the assembly
cat bpf_program.spvasm
```

## Architecture Details

### Compilation Pipeline

```
eBPF Bytecode
    ↓
LLVM IR (with target=spirv64)
    ↓
LLVM SPIR-V Backend
    ↓
SPIR-V Binary
    ↓
OpenCL Runtime
    ↓
GPU Execution
```

### SPIR-V vs PTX Comparison

| Feature | SPIR-V | PTX |
|---------|--------|-----|
| **Vendor Support** | Cross-vendor | NVIDIA only |
| **Format** | Binary IR | Text assembly |
| **LLVM Backend** | Native (LLVM 16+) | Native (all versions) |
| **API Support** | OpenCL, Vulkan, Level Zero | CUDA only |
| **Address Spaces** | Explicit required | Implicit |
| **Optimization** | Runtime + JIT | Runtime + JIT |

### Key Differences from PTX

1. **Binary Format**: SPIR-V is binary, making it more compact and faster to parse
2. **Address Spaces**: SPIR-V requires explicit address space qualifiers
3. **Multiple APIs**: Can be used with OpenCL, Vulkan Compute, or Level Zero
4. **Wider Hardware Support**: Works on Intel, AMD, NVIDIA, ARM, etc.

## Troubleshooting

### "SPIR-V target not found"

**Cause**: LLVM installation doesn't include SPIR-V backend (need LLVM 18+, native in LLVM 20+)

**Solution**:
```bash
# Check LLVM version
llvm-config --version  # Should be 18.0 or higher

# Verify SPIR-V target is available (LLVM 20+)
llc-20 --version | grep -i spirv

# Install LLVM 20 with native SPIR-V support
sudo apt install llvm-20-dev
```

### "OpenCL implementation may not support SPIR-V IL"

**Cause**: Your OpenCL driver doesn't support SPIR-V ingestion

**Solutions**:
- Update your GPU driver to latest version
- Use CPU fallback: `sudo apt install pocl-opencl-icd`
- For NVIDIA: Ensure CUDA 12+ is installed
- For Intel: Install latest Intel Compute Runtime

### Build Errors with OpenCL

**Cause**: OpenCL headers not found

**Solution**:
```bash
# Ubuntu/Debian
sudo apt install opencl-headers ocl-icd-opencl-dev

# Also install an ICD loader
sudo apt install ocl-icd-libopencl1
```

### No OpenCL Devices Found

**Cause**: No OpenCL runtime installed

**Solution**:
```bash
# Check available platforms
clinfo

# Install CPU runtime as fallback
sudo apt install pocl-opencl-icd

# For NVIDIA GPUs
# Install CUDA toolkit

# For Intel GPUs
sudo apt install intel-opencl-icd

# For AMD GPUs
# Install ROCm or amdgpu-pro
```

## Advanced Usage

### Using with Vulkan Compute

While this example uses OpenCL, SPIR-V can also be used with Vulkan:

```cpp
// Create Vulkan shader module from SPIR-V binary
VkShaderModuleCreateInfo createInfo{};
createInfo.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
createInfo.codeSize = spirv_binary.size();
createInfo.pCode = reinterpret_cast<const uint32_t*>(spirv_binary.data());

VkShaderModule shaderModule;
vkCreateShaderModule(device, &createInfo, nullptr, &shaderModule);
```

### Helper Functions

For eBPF programs that use helper functions, you'll need to:
1. Inline the helpers at compile time, OR
2. Implement host-device communication (similar to PTX example)

Currently, the simple arithmetic example doesn't require helpers, but this will be needed for more complex programs.

## References

- [SPIR-V Specification](https://www.khronos.org/registry/spir-v/)
- [OpenCL SPIR-V Environment](https://www.khronos.org/registry/OpenCL/specs/3.0-unified/html/OpenCL_Env.html)
- [LLVM SPIR-V Backend](https://llvm.org/docs/SPIRVUsage.html)
- [SPIRV-Tools](https://github.com/KhronosGroup/SPIRV-Tools)
