add_executable(ptx_test ptx_test.cpp)

# spdlog is provided by parent CMakeLists.txt via FetchContent
if(NOT TARGET spdlog::spdlog)
    find_package(spdlog REQUIRED)
endif()

option(LLVMBPF_CUDA_PATH "Path where CUDA installs")
message(STATUS "LLVMBPF_CUDA_PATH=${LLVMBPF_CUDA_PATH}")
if(NOT LLVMBPF_CUDA_PATH)
    message(FATAL_ERROR "Please set LLVMBPF_CUDA_PATH if you want to build ptx_test, otherwise set LLVMBPF_ENABLE_PTX to NO")
endif()
set(LLVM_LINK_COMPONENTS 
  ${LLVM_TARGETS_TO_BUILD}
  )
target_link_directories(ptx_test PRIVATE ${LLVMBPF_CUDA_PATH}/lib64 ${LLVMBPF_CUDA_PATH}/lib64/stubs)

find_library(NVPTXCOMPILER_LIB 
    NAMES 
    nvptxcompiler_static 
    PATHS 
    ${LLVMBPF_CUDA_PATH}/lib64 
    ${LLVMBPF_CUDA_PATH}/lib64/stubs 
    NO_DEFAULT_PATH)
if(NOT NVPTXCOMPILER_LIB)
    message(FATAL_ERROR "nvptxcompiler_static library not found in ${LLVMBPF_CUDA_PATH}/lib64 or ${LLVMBPF_CUDA_PATH}/lib64/stubs")
endif()
target_link_libraries(ptx_test 
            PRIVATE 
            ${LLVM_LIBS} 
            llvmbpf_vm 
            cuda 
            ${NVPTXCOMPILER_LIB} 
            spdlog::spdlog)
  
add_dependencies(ptx_test llvmbpf_vm spdlog::spdlog)
target_include_directories(ptx_test PRIVATE ${LLVM_INCLUDE_DIRS} include src ${LLVMBPF_CUDA_PATH}/include ${SPDLOG_INCLUDES})
