bpftime_add_executable(vm-llvm-example
    ./basic.cpp
)

add_dependencies(vm-llvm-example llvmbpf_vm spdlog::spdlog)
target_link_libraries(vm-llvm-example llvmbpf_vm)

bpftime_add_executable(maps-example
    ./maps.cpp
)

add_dependencies(maps-example llvmbpf_vm spdlog::spdlog)
target_link_libraries(maps-example llvmbpf_vm)
