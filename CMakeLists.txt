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

if(${LLVM_PACKAGE_VERSION} VERSION_LESS 15)
    message(FATAL_ERROR "LLVM version must be >=15")
endif()

option(ENABLE_LLVM_SHARED "Link shared library of LLVM" NO)
option(BUILD_LLVM_AOT_CLI "Build AOT cli, which rely on libbpf" NO)

if(ENABLE_LLVM_SHARED)
    set(LLVM_LIBS LLVM)
else()
    llvm_map_components_to_libnames(LLVM_LIBS
        Core
        OrcJIT
        mcjit
        Support
        nativecodegen
    )
endif()

include(FetchContent)

if(NOT DEFINED SPDLOG_INCLUDE)
    message(INFO " Adding spdlog seperately..")

    # spdlog
    # Fetch spdlog
    FetchContent_Declare(
        spdlog
        GIT_REPOSITORY https://github.com/gabime/spdlog.git
        GIT_TAG v1.14.1 # Specify the version you want to use
    )

    # Make the spdlog target available
    FetchContent_MakeAvailable(spdlog)
endif()

# if BPFTIME_LLVM_JIT is set, then it's built in the bpftime project.
# If not, it's built as a standalone library.
if(${BPFTIME_LLVM_JIT})
    # build cli in the main project because it relies on libbpf
    add_subdirectory(cli)
else()
    if(${BUILD_LLVM_AOT_CLI})
        add_subdirectory(cli)
    endif()

    if(${BPFTIME_ENABLE_UNIT_TESTING} AND NOT TARGET Catch2)
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

message(STATUS "LLVM_LIBS=${LLVM_LIBS}")

target_link_libraries(llvmbpf_vm PUBLIC ${LLVM_LIBS} PRIVATE spdlog::spdlog)
target_include_directories(llvmbpf_vm
    PUBLIC ${LLVM_INCLUDE_DIRS} ${SPDLOG_INCLUDE} ${Boost_INCLUDE} ../include include # LLVM jit also used these headers
)
add_dependencies(llvmbpf_vm spdlog::spdlog)

if(BPFTIME_ENABLE_UNIT_TESTING)
    message(STATUS "Build unit tests for the project. Tests should always be found in the test folder\n")
    add_subdirectory(test)
endif()

add_subdirectory(example)
