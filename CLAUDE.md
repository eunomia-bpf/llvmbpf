# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

llvmbpf is a high-performance userspace eBPF VM with LLVM JIT/AOT compiler. It compiles eBPF bytecode to native code via LLVM IR, supports multi-architecture execution (x86, ARM, NVPTX/CUDA), and provides AOT compilation of eBPF programs into standalone native ELF objects.

This is a standalone VM library extracted from the bpftime project, focused solely on compilation and execution without maps, helpers, verifiers, or loaders.

## Build Commands

### Standard Build (Release)
```sh
sudo apt install llvm-15-dev libzstd-dev
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target all -j
```

### Build with AOT CLI Tool
```sh
sudo apt-get install libelf1 libelf-dev
cmake -B build -DBUILD_LLVM_AOT_CLI=1
cmake --build build --target all -j
```

### Build with PTX/CUDA Support
```sh
# Set LLVMBPF_CUDA_PATH to your CUDA installation (e.g., /usr/local/cuda-12.6)
cmake -B build -DCMAKE_BUILD_TYPE=Release -DLLVMBPF_ENABLE_PTX=1 -DLLVMBPF_CUDA_PATH=/usr/local/cuda-12.6
cmake --build build --target all -j
```

### Build with SPIR-V/OpenCL Support
```sh
# Requires LLVM 16+ with SPIR-V backend
sudo apt install llvm-16-dev opencl-headers ocl-icd-opencl-dev
cmake -B build -DCMAKE_BUILD_TYPE=Release -DLLVMBPF_ENABLE_SPIRV=1
cmake --build build --target spirv_opencl_test -j
```

### Build for Development/Testing
```sh
# With unit tests and code coverage
LLVM_DIR=/usr/lib/llvm-15/cmake cmake -B build -DCMAKE_BUILD_TYPE=Debug -DBPFTIME_ENABLE_UNIT_TESTING=1 -DBPFTIME_ENABLE_CODE_COVERAGE=1 -G Ninja
cmake --build build --target all -j
```

## Testing

### Run Unit Tests
```sh
# Build with testing enabled first (see above)
./build/test/unit-test/llvm_jit_tests
```

### Run BPF Conformance Tests
```sh
# Create Python virtual environment
python3.8 -m venv ./test
source test/bin/activate
pip install -r test/requirements.txt

# Run pytest
pytest -v -s test/test_framework
# Or exclude known failures:
pytest -k "test_jit.py and not err-infinite"
```

### Run Example Programs
```sh
./build/vm-llvm-example
./build/maps-example
./build/example/ptx/ptx_test  # If built with PTX support
./build/example/spirv/spirv_opencl_test  # If built with SPIR-V support
```

## Architecture

### Core Components

**VM Layer (`include/llvmbpf.hpp`, `src/vm.cpp`)**
- `llvmbpf_vm`: Main VM class exposing the public API
- `precompiled_ebpf_function`: Function pointer type for JITed code (signature: `uint64_t (*)(void *mem, size_t mem_len)`)
- Key methods: `load_code()`, `compile()`, `exec()`, `do_aot_compile()`, `load_aot_object()`

**JIT/AOT Compiler (`src/llvm_jit_context.cpp`, `src/llvm_jit_context.hpp`)**
- `llvm_bpf_jit_context`: Internal LLVM compilation context
- Uses LLVM OrcJIT for runtime compilation
- Generates LLVM IR from eBPF bytecode, then compiles to native code or PTX

**eBPF → LLVM Translation (`src/compiler.cpp`, `src/compiler_utils.cpp`)**
- `generateModule()`: Converts eBPF instructions to LLVM IR
- Handles eBPF instruction set including LDDW (64-bit immediate loads)
- Implements stack (512 bytes), registers (r0-r10), and external function calls

**Instruction Set (`src/ebpf_inst.h`)**
- Defines eBPF instruction structure and opcodes
- Standard eBPF ISA with support for maps via LDDW helpers

### LDDW Helpers and Maps

The VM supports map access through LDDW (load double-word) helpers that resolve map references:
- `__lddw_helper_map_by_fd`: Resolve map by file descriptor
- `__lddw_helper_map_by_idx`: Resolve map by index
- `__lddw_helper_map_val`: Get map value pointer
- `__lddw_helper_var_addr`: Get variable address
- `__lddw_helper_code_addr`: Get code address

Set these via `vm.set_lddw_helpers()`. Maps can be accessed via helper functions (e.g., `bpf_map_lookup_elem`) or as global variables.

### External Functions

Register eBPF helpers via `register_external_function(index, name, fn_ptr)`. The compiler will generate calls to these external functions when the eBPF program invokes helpers.

### Compilation Modes

**JIT Mode**: `compile()` returns a function pointer that can be called directly
**AOT Mode**: `do_aot_compile()` generates native ELF object files that can be:
- Linked with C code to create standalone binaries
- Loaded back into the VM via `load_aot_object()`
**PTX Mode**: `generate_ptx()` emits CUDA PTX assembly for NVIDIA GPU execution
**SPIR-V Mode**: `generate_spirv()` emits SPIR-V binary for cross-vendor GPU execution (OpenCL, Vulkan)

## CLI Tool Usage

The `bpftime-vm` CLI tool (in `cli/`) provides AOT compilation:

```sh
# Generate LLVM IR
./build/cli/bpftime-vm build program.bpf.o -emit-llvm > program.ll

# AOT compile to native ELF
./build/cli/bpftime-vm build program.bpf.o
# Outputs: program_name.o for each program in the ELF

# Run AOT-compiled program
./build/cli/bpftime-vm run program_name.o input.bin
```

Note: The standalone CLI does not support helpers/maps. For full functionality, use bpftime's tools.

## Key Constraints

- **LLVM Version**:
  - Minimum: LLVM >= 15 for JIT/AOT/PTX
  - SPIR-V: LLVM >= 16 (requires native SPIR-V backend)
- **eBPF Stack Size**: 512 bytes (`EBPF_STACK_SIZE`)
- **Max External Functions**: 8192 (`MAX_EXT_FUNCS`)
- **No Built-in Maps/Helpers**: The library provides hooks but no implementations

## Integration with bpftime

llvmbpf is designed as a component of the larger bpftime project. For loading eBPF from ELF files with proper relocations, or for full userspace eBPF runtime with maps/helpers/verifiers, use bpftime. The bpftime project can dump map definitions and relocated bytecode via `bpftimetool export`, which can then be used to build standalone binaries.

## Examples Directory Structure

- `example/basic.cpp`: Basic VM usage
- `example/maps.cpp`: Map access via helpers and LDDW
- `example/standalone/`: Standalone binary compilation example
- `example/inline/`: Inlining optimization example (merge helper functions into LLVM IR)
- `example/load-llvm-ir/`: Load original LLVM IR instead of eBPF bytecode
- `example/ptx/`: CUDA PTX generation examples (NVIDIA GPUs)
- `example/spirv/`: SPIR-V generation examples (OpenCL, cross-vendor GPUs)
