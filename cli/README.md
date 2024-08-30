# bpftime-vm cli tool

```console
# bpftime-vm
Usage: bpftime-vm [--help] [--version] {build,run}

Optional arguments:
  -h, --help     shows help message and exits 
  -v, --version  prints version information and exits 

Subcommands:
  build         Build native ELF(s) from eBPF ELF. Each program in the eBPF ELF will be built into a single native ELF
  run           Run an native eBPF program
```

A CLI compiler for AOT of llvm-jit.

It can build ebpf ELF into native elf, or execute compiled native ELF. **Helpers and relocations are not supported. For helpers and maps, please use bpftime aot cli in the [bpftime/tools](https://github.com/eunomia-bpf/bpftime)**

