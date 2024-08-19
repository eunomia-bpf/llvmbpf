add_executable(
    bpftime-vm-cli
    main.cpp
)

set_target_properties(bpftime-vm-cli PROPERTIES OUTPUT_NAME "bpftime-vm")

target_include_directories(bpftime-vm-cli 
    PRIVATE 
    ${SPDLOG_INCLUDE} 
    ${argparse_INCLUDE} 
    ${CMAKE_CURRENT_SOURCE_DIR}/../llvm-jit/src 
    ${CMAKE_CURRENT_SOURCE_DIR}/../llvm-jit/include 
    ${CMAKE_CURRENT_SOURCE_DIR}/../include 
    ${LIBBPF_INCLUDE_DIRS}
)

include(ExternalProject)
ExternalProject_Add(
    libbpf_project
    PREFIX ${CMAKE_BINARY_DIR}/libbpf
    GIT_REPOSITORY https://github.com/libbpf/libbpf.git
    GIT_TAG v1.2.0 # Replace with the version you need
    CONFIGURE_COMMAND ""
    BUILD_COMMAND make -C src -j
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS ${CMAKE_BINARY_DIR}/libbpf/src/libbpf.a
)

ExternalProject_Get_Property(libbpf_project source_dir)
set(LIBBPF_INCLUDE_DIRS ${source_dir}/src)
set(LIBBPF_LIBRARIES ${source_dir}/src/libbpf.a)

# Ensure libbpf is built before your target
add_dependencies(bpftime-vm-cli libbpf_project)

include_directories(${LIBBPF_INCLUDE_DIRS})

add_dependencies(bpftime-vm-cli spdlog::spdlog llvmbpf_vm)
target_link_libraries(bpftime-vm-cli 
            PRIVATE spdlog::spdlog llvmbpf_vm 
            ${LIBBPF_LIBRARIES} 
            elf 
            z
)
set_property(TARGET bpftime-vm-cli PROPERTY CXX_STANDARD 20)

target_compile_definitions(bpftime-vm-cli PRIVATE _GNU_SOURCE)
install(TARGETS bpftime-vm-cli CONFIGURATIONS Release Debug RelWithDebInfo DESTINATION ~/.bpftime)
