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

set(LIBBPF_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libbpf_project)

include(ExternalProject)
ExternalProject_Add(
    libbpf_project
    GIT_REPOSITORY https://github.com/libbpf/libbpf.git
    GIT_TAG v1.2.0 # Replace with the version you need
    CONFIGURE_COMMAND ""
    BUILD_COMMAND make -C src -j
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS ${LIBBPF_SOURCE_DIR}/src/libbpf.a
    SOURCE_DIR ${LIBBPF_SOURCE_DIR}
)

set(LIBBPF_INCLUDE_DIRS ${LIBBPF_SOURCE_DIR}/src)
set(LIBBPF_LIBRARIES ${LIBBPF_SOURCE_DIR}/src/libbpf.a)
# Ensure libbpf is built before your target

include_directories(${LIBBPF_INCLUDE_DIRS})

add_dependencies(bpftime-vm-cli spdlog::spdlog llvmbpf_vm libbpf_project)
target_link_libraries(bpftime-vm-cli 
            PRIVATE spdlog::spdlog llvmbpf_vm 
            ${LIBBPF_LIBRARIES} 
            elf 
            z
)
set_property(TARGET bpftime-vm-cli PROPERTY CXX_STANDARD 20)

target_compile_definitions(bpftime-vm-cli PRIVATE _GNU_SOURCE)
install(TARGETS bpftime-vm-cli CONFIGURATIONS Release Debug RelWithDebInfo DESTINATION ~/.bpftime)
