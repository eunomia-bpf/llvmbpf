# Have to fetch Catch2
if(${BPFTIME_ENABLE_UNIT_TESTING} AND NOT TARGET Catch2)
    message(STATUS "Adding Catch2 by FetchContent at llvmbpf/test/unit-test")
    Include(FetchContent)
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.4.0
    )
    FetchContent_MakeAvailable(Catch2)
endif()

set(TEST_SOURCES
    bpf_prog_test.cpp
    vm_test.cpp
)

add_executable(llvm_jit_tests ${TEST_SOURCES})
set_property(TARGET llvm_jit_tests PROPERTY CXX_STANDARD 20)
add_dependencies(llvm_jit_tests llvmbpf_vm)
target_link_libraries(llvm_jit_tests PRIVATE llvmbpf_vm Catch2::Catch2WithMain ${LIBBPF_LIBRARIES})
target_include_directories(llvm_jit_tests PRIVATE ${Catch2_INCLUDE} ${CMAKE_CURRENT_SOURCE_DIR}/../include ${CMAKE_CURRENT_SOURCE_DIR}/../src ${LIBBPF_INCLUDE_DIRS} ${LIBBPF_INCLUDE_DIRS}/uapi)
add_test(NAME llvm_jit_tests COMMAND llvm_jit_tests)

if("NVPTX" IN_LIST LLVM_TARGETS_TO_BUILD)
    target_compile_definitions(llvm_jit_tests PRIVATE LLVMBPF_TEST_HAS_NVPTX=1)
endif()

# Exercise ORC's runtime symbol lookup with LLVM hidden inside a loaded DSO,
# as in bpftime-agent. The loader itself deliberately does not link LLVM.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set_target_properties(llvmbpf_vm PROPERTIES POSITION_INDEPENDENT_CODE ON)
    if(TARGET spdlog)
        set_target_properties(spdlog PROPERTIES POSITION_INDEPENDENT_CODE ON)
    endif()
    add_library(llvm_jit_test_module MODULE jit_shared.cpp)
    target_link_libraries(llvm_jit_test_module PRIVATE llvmbpf_vm)
    target_compile_features(llvm_jit_test_module PRIVATE cxx_std_20)
    target_link_options(llvm_jit_test_module PRIVATE -Wl,-z,defs
        "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/jit_shared.version")
    set_target_properties(llvm_jit_test_module PROPERTIES
        LINK_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/jit_shared.version")
    add_executable(llvm_jit_dlopen_test jit_dlopen.cpp)
    target_link_libraries(llvm_jit_dlopen_test PRIVATE ${CMAKE_DL_LIBS})
    add_dependencies(llvm_jit_dlopen_test llvm_jit_test_module)
    add_test(NAME llvm_jit_dlopen_test
        COMMAND llvm_jit_dlopen_test $<TARGET_FILE:llvm_jit_test_module>)
endif()
