add_executable(spirv_opencl_test spirv_opencl_test.cpp)

# spdlog is provided by parent CMakeLists.txt via FetchContent
if(NOT TARGET spdlog::spdlog)
    find_package(spdlog REQUIRED)
endif()

# Find OpenCL
find_package(OpenCL REQUIRED)
if(NOT OpenCL_FOUND)
    message(FATAL_ERROR "OpenCL not found. Please install OpenCL development files (e.g., opencl-headers, ocl-icd-opencl-dev)")
endif()

message(STATUS "OpenCL found: ${OpenCL_INCLUDE_DIRS}")
message(STATUS "OpenCL libraries: ${OpenCL_LIBRARIES}")

set(LLVM_LINK_COMPONENTS
  ${LLVM_TARGETS_TO_BUILD}
)

target_link_libraries(spirv_opencl_test
            PRIVATE
            ${LLVM_LIBS}
            llvmbpf_vm
            OpenCL::OpenCL
            spdlog::spdlog)

add_dependencies(spirv_opencl_test llvmbpf_vm spdlog::spdlog)
target_include_directories(spirv_opencl_test
    PRIVATE
    ${LLVM_INCLUDE_DIRS}
    include
    src
    ${OpenCL_INCLUDE_DIRS}
    ${SPDLOG_INCLUDES})
