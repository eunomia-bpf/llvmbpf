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
sudo apt install llvm-15-dev libzstd-dev
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target all -j
```

## Use llvmbpf as a library

See [example](example/main.cpp) of how to use the library as a vm:

```cpp
void run_ebpf_prog(const void *code, size_t code_len)
{
    uint64_t res = 0;
    llvmbpf_vm vm;

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

You can use the cli to generate the LLVM IR from eBPF bytecode:

```console
# ./build/cli/bpftime-vm build .github/assets/sum.bpf.o -emit-llvm > test.bpf.ll
# opt -O3 -S test.bpf.ll -opaque-pointers  -o test.opt.ll
# cat test.opt.ll 
; ModuleID = 'test.bpf.ll'
source_filename = "bpf-jit"

; Function Attrs: nofree norecurse nosync nounwind memory(read, inaccessiblemem: none)
define i64 @bpf_main(ptr %0, i64 %1) local_unnamed_addr #0 {
setupBlock:
  %2 = ptrtoint ptr %0 to i64
  %3 = load i32, ptr %0, align 4
  %4 = icmp slt i32 %3, 1
  br i1 %4, label %bb_inst_30, label %bb_inst_15

bb_inst_15:                                       ; preds = %setupBlock, %bb_inst_15
  %storemerge32 = phi i32 [ %11, %bb_inst_15 ], [ 1, %setupBlock ]
  %stackBegin29.sroa.2.031 = phi i32 [ %10, %bb_inst_15 ], [ 0, %setupBlock ]
  %5 = sext i32 %storemerge32 to i64
  %6 = shl nsw i64 %5, 2
  %7 = add i64 %6, %2
  %8 = inttoptr i64 %7 to ptr
  %9 = load i32, ptr %8, align 4
  %10 = add i32 %9, %stackBegin29.sroa.2.031
  %11 = add i32 %storemerge32, 1
  %12 = icmp sgt i32 %11, %3
  br i1 %12, label %bb_inst_30, label %bb_inst_15

bb_inst_30:                                       ; preds = %bb_inst_15, %setupBlock
  %stackBegin29.sroa.2.0.lcssa = phi i32 [ 0, %setupBlock ], [ %10, %bb_inst_15 ]
  %13 = zext i32 %stackBegin29.sroa.2.0.lcssa to i64
  ret i64 %13
}

attributes #0 = { nofree norecurse nosync nounwind memory(read, inaccessiblemem: none) }
```

AOT Compile a eBPF program:

```console
# ./build/cli/bpftime-vm build .github/assets/sum.bpf.o
[2024-08-10 14:54:06.453] [info] [main.cpp:56] Processing program test
[2024-08-10 14:54:06.479] [info] [main.cpp:69] Program test written to ./test.o
```

Load and run a AOTed eBPF program:

```console
# echo "AwAAAAEAAAACAAAAAwAAAA==" | base64 -d > test.bin
# ./build/cli/bpftime-vm run test.o test.bin
[2024-08-10 14:57:16.986] [info] [llvm_jit_context.cpp:392] LLVM-JIT: Loading aot object
[2024-08-10 14:57:16.991] [info] [main.cpp:136] Program executed successfully. Return value: 6
```

## Test with bpf-conformance

See the CI in [.github/workflows/bpf_conformance.yml](.github/workflows/bpf_conformance.yml) for how to run the bpf-conformance tests.

The test result can be found in <https://eunomia-bpf.github.io/llvmbpf/bpf_conformance_results.txt>

## License

MIT
