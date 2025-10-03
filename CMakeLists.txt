cmake_minimum_required(VERSION 3.16)
cmake_policy(SET CMP0079 NEW)
project(
    "llvm-bpf-jit"
    LANGUAGES C CXX
    VERSION 0.1.0
)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug")
endif()

if(NOT DEFINED SPDLOG_ACTIVE_LEVEL)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_definitions(SPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_TRACE)
    else()
        add_compile_definitions(SPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_INFO)
    endif()
endif()

function(bpftime_setup_target target)
    set_property(TARGET ${target} PROPERTY CXX_STANDARD 20)
    target_include_directories(${target}
        PUBLIC src "include")
    set_target_properties(${target} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
endfunction()

function(bpftime_add_executable target)
    add_executable(${target} ${ARGN})
    bpftime_setup_target(${target})
endfunction()

function(bpftime_add_library target)
    add_library(${target} ${ARGN})
    bpftime_setup_target(${target})
endfunction()

bpftime_add_library(llvmbpf_vm
    src/llvm_jit_context.cpp
    src/compiler.cpp
    src/compiler_utils.cpp
    src/vm.cpp
)

set_target_properties(llvmbpf_vm PROPERTIES ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/../")

find_package(LLVM REQUIRED CONFIG)

message(STATUS "Checking LLVM_VERSION_MAJOR macro value...")
message(STATUS "LLVM_VERSION_MAJOR is: ${LLVM_VERSION_MAJOR}")

if(${LLVM_PACKAGE_VERSION} VERSION_LESS 15)
    message(FATAL_ERROR "LLVM version must be >=15")
endif()

option(ENABLE_LLVM_SHARED "Link shared library of LLVM" NO)
option(BUILD_LLVM_AOT_CLI "Build AOT cli, which rely on libbpf" NO)

if(ENABLE_LLVM_SHARED)
    list(PREPEND LLVM_LIBS LLVM)
else()
    set(LLVM_COMPONENTS
      ${LLVM_TARGETS_TO_BUILD}
        Core
        Support
        Target
        Analysis
        ipo
        TransformUtils
        BitReader
        AsmParser
        Linker
        MC
        MCParser
        MCDisassembler
        Object
        ExecutionEngine
        RuntimeDyld
        OrcJIT
        MCJIT
        # X86
        X86CodeGen
        X86Desc
        X86Info
        X86AsmParser
        # NVPTX
        NVPTXCodeGen
        NVPTXDesc
        NVPTXInfo
        # AArch64
        AArch64CodeGen
        AArch64Desc
        AArch64Info
        AArch64AsmParser
    )

    # Add SPIR-V components only if SPIR-V is enabled and LLVM version supports it
    if(LLVMBPF_ENABLE_SPIRV AND ${LLVM_VERSION_MAJOR} GREATER_EQUAL 18)
        list(APPEND LLVM_COMPONENTS
            SPIRVCodeGen
            SPIRVDesc
            SPIRVInfo
        )
        message(STATUS "Adding SPIR-V LLVM components (LLVM ${LLVM_VERSION_MAJOR})")
    endif()

    llvm_map_components_to_libnames(LLVM_LIBS ${LLVM_COMPONENTS})
endif()
include(FetchContent)

if(NOT DEFINED SPDLOG_INCLUDE)
    message(STATUS " Adding spdlog seperately..")

    # spdlog
    # Fetch spdlog
    FetchContent_Declare(
        spdlog
        GIT_REPOSITORY https://github.com/gabime/spdlog.git
        GIT_TAG v1.15.2 # Specify the version you want to use
    )

    # Make the spdlog target available
    FetchContent_MakeAvailable(spdlog)
endif()

# if BPFTIME_LLVM_JIT is set, then it's built in the bpftime project.
# If not, it's built as a standalone library.
if(${BPFTIME_LLVM_JIT})
    add_subdirectory(cli)
else()
    if(${BUILD_LLVM_AOT_CLI})
        add_subdirectory(cli)
    endif()


    if(${BPFTIME_ENABLE_UNIT_TESTING})
        if(NOT TARGET Catch2)
            message(STATUS "Adding Catch2 by FetchContent at llvmbpf")
            FetchContent_Declare(
                Catch2
                GIT_REPOSITORY https://github.com/catchorg/Catch2.git
                GIT_TAG v3.4.0 # Specify the version you want to use
            )

            # Make the Catch2 target available
            FetchContent_MakeAvailable(Catch2)
        endif()
    endif()
endif()

message(STATUS "LLVM_LIBS=${LLVM_LIBS}")

target_link_libraries(llvmbpf_vm PRIVATE ${LLVM_LIBS} PRIVATE spdlog::spdlog)
target_include_directories(llvmbpf_vm
    PRIVATE ${LLVM_INCLUDE_DIRS} ${SPDLOG_INCLUDE} ${Boost_INCLUDE} ../include include # LLVM jit also used these headers
)
add_dependencies(llvmbpf_vm spdlog::spdlog)

# SPIR-V support requires LLVM 18+ (native backend in LLVM 20+)
if(LLVMBPF_ENABLE_SPIRV)
    if(${LLVM_VERSION_MAJOR} LESS 18)
        message(FATAL_ERROR "SPIR-V support requires LLVM 18 or higher. Current version: ${LLVM_VERSION_MAJOR}.${LLVM_VERSION_MINOR}")
    endif()
    if(${LLVM_VERSION_MAJOR} GREATER_EQUAL 20)
        message(STATUS "SPIR-V: Using native LLVM backend (LLVM ${LLVM_VERSION_MAJOR})")
    elseif(${LLVM_VERSION_MAJOR} GREATER_EQUAL 18)
        message(STATUS "SPIR-V: LLVM ${LLVM_VERSION_MAJOR} detected. Native backend available in LLVM 20+")
        message(STATUS "SPIR-V: Consider upgrading to LLVM 20 for native support")
    endif()
    target_compile_definitions(llvmbpf_vm PRIVATE LLVMBPF_HAS_SPIRV=1)
endif()

if(BPFTIME_ENABLE_CODE_COVERAGE)
    target_compile_options(llvmbpf_vm PUBLIC -O0 -g -fprofile-arcs -ftest-coverage)
    target_link_options(llvmbpf_vm PUBLIC -fprofile-arcs -ftest-coverage)
    message(DEBUG "Code coverage is enabled and provided with GCC.")
endif()

if(BPFTIME_ENABLE_UNIT_TESTING)
    message(STATUS "Build unit tests for the project. Tests should always be found in the test folder\n")
    add_subdirectory(test)
endif()

add_subdirectory(example)


option(LLVMBPF_ENABLE_PTX "Whether build the ptx demo program, which requires CUDA" OFF)
option(LLVMBPF_ENABLE_SPIRV "Whether build the SPIR-V demo program, which requires OpenCL" OFF)

if(LLVMBPF_ENABLE_PTX)
    add_subdirectory(example/ptx)
endif()

if(LLVMBPF_ENABLE_SPIRV)
    add_subdirectory(example/spirv)
endif()
