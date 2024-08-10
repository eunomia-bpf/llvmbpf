# Userspace eBPF VM with LLVM JIT/AOT Compiler

A high-performance, multi-architecture JIT/AOT compiler and virtual machine (VM) based on LLVM.

This component is part of the [bpftime](https://github.com/eunomia-bpf/bpftime) project but focuses solely on the core VM. It offers the following capabilities:

- Operates as `a standalone eBPF VM library` or compiler tool.
- Compiles eBPF bytecode into LLVM IR files.
- Compiles eBPF ELF files into AOTed native code ELF object files, which can be linked like C-compiled objects or loaded into llvmbpf.
- Loads and executes AOT-compiled ELF object files within the eBPF runtime.
- Supports eBPF helpers and maps lddw functions.

This library is optimized for performance, flexibility, and minimal dependencies. It does not include maps, helpers, verifiers, or loaders for eBPF applications, making it suitable as a lightweight, high-performance library.

For a comprehensive userspace eBPF runtime that includes support for maps, helpers, and seamless execution of Uprobe, syscall trace, XDP, and other eBPF programs—similar to kernel functionality but in userspace—please refer to the [bpftime](https://github.com/eunomia-bpf/bpftime) project.

## build

```sh
sudo apt install llvm-15-dev
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target all -j
```

## Use llvmbpf as a library

See [example](example/main.cpp) of how to use the library as a vm:

```cpp
void run_ebpf_prog(const void *code, size_t code_len)
{
    uint64_t res = 0;
    bpftime_llvm_jit_vm vm;

    res = vm.load_code(code, code_len);
    if (res) {
        return;
    }
    vm.register_external_function(2, "print", (void *)ffi_print_func);
    auto func = vm.compile();
    if (!func) {
        return;
    }
    int err = vm.exec(&bpf_mem, sizeof(bpf_mem), res);
    if (err != 0) {
        return;
    }
    printf("res = %" PRIu64 "\n", res);
}
```

## Use llvmbpf as a AOT compiler




## Test with bpf-conformance

- Follow the `build` section to build `llvm-jit`
- Follow the instructions to build bpf_conformance_runner

```bash
sudo apt install libboost-dev
git clone https://github.com/Alan-Jowett/bpf_conformance
cd bpf_conformance
cmake . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target bpf_conformance_runner
```

- Run the tests

```bash
cd bpf_conformance
./build/bin/bpf_conformance_runner  --test_file_directory tests --plugin_path PATH_TO_LLVM_JIT/build/vm-llvm-bpf-test 
```

With `PATH_TO_LLVM_JIT` replaced to the directory of this project

- See the results

If nothing unexpected happens, you will see that `vm-llvm-bpf-test` passes at least 144 tests of the 166 tests. The unpassed tests used features that we haven't supported.

```console
.....
PASS: "tests/stxb-all2.data"
PASS: "tests/stxb-chain.data"
PASS: "tests/stxb.data"
PASS: "tests/stxdw.data"
PASS: "tests/stxh.data"
PASS: "tests/stxw.data"
PASS: "tests/subnet.data"
Passed 165 out of 166 tests.
```
