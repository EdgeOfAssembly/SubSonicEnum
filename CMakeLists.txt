cmake_minimum_required(VERSION 3.20)
project(SubSonicEnum LANGUAGES C CXX CUDA)

# Find CUDA Toolkit
find_package(CUDAToolkit REQUIRED)

# Function to detect NVIDIA GPU compute capability
function(detect_cuda_architectures OUTPUT_VARIABLE)
    set(DETECT_SRC "${CMAKE_BINARY_DIR}/detect_cuda_arch.cu")
    file(WRITE "${DETECT_SRC}" "
#include <cuda_runtime.h>
#include <stdio.h>
int main() {
    int deviceCount;
    cudaError_t err = cudaGetDeviceCount(&deviceCount);
    if (err != cudaSuccess || deviceCount == 0) {
        fprintf(stderr, \"CUDA error: %s\\n\", cudaGetErrorString(err));
        printf(\"\");
        return 1;
    }
    int device;
    cudaGetDevice(&device);
    cudaDeviceProp prop;
    err = cudaGetDeviceProperties(&prop, device);
    if (err != cudaSuccess) {
        fprintf(stderr, \"CUDA error: %s\\n\", cudaGetErrorString(err));
        printf(\"\");
        return 1;
    }
    printf(\"%d%d\", prop.major, prop.minor);
    return 0;
}
")
    execute_process(
        COMMAND ${CMAKE_CUDA_COMPILER} -o "${CMAKE_BINARY_DIR}/detect_cuda_arch" "${DETECT_SRC}"
        RESULT_VARIABLE COMPILE_RESULT
        OUTPUT_VARIABLE COMPILE_OUTPUT
        ERROR_VARIABLE COMPILE_ERROR
    )
    if(COMPILE_RESULT EQUAL 0)
        execute_process(
            COMMAND "${CMAKE_BINARY_DIR}/detect_cuda_arch"
            OUTPUT_VARIABLE CUDA_ARCH
            ERROR_VARIABLE RUN_ERROR
            RESULT_VARIABLE RUN_RESULT
        )
        if(RUN_RESULT EQUAL 0 AND CUDA_ARCH)
            string(STRIP "${CUDA_ARCH}" CUDA_ARCH)
            set(${OUTPUT_VARIABLE} "${CUDA_ARCH}" PARENT_SCOPE)
            message(STATUS "Detected CUDA architecture: ${CUDA_ARCH}")
        else()
            message(WARNING "Failed to run CUDA architecture detection: ${RUN_ERROR}")
            set(${OUTPUT_VARIABLE} "61" PARENT_SCOPE)
        endif()
    else()
        message(WARNING "Failed to compile CUDA architecture detection: ${COMPILE_ERROR}")
        set(${OUTPUT_VARIABLE} "61" PARENT_SCOPE)
    endif()
endfunction()

# Detect CUDA architecture
detect_cuda_architectures(DETECTED_CUDA_ARCH)

# Set default build type to Release
if(NOT CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "")
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build, options are: Debug Release" FORCE)
endif()
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# Define the executable
add_executable(subsonicenum
    src/core/subsonic_kernel.cu
    src/dns/dns.c
)

# Set include directories
target_include_directories(subsonicenum PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

# Link CUDA runtime
target_link_libraries(subsonicenum PRIVATE CUDA::cudart)

# Set properties for CUDA and C++ compilation
set_target_properties(subsonicenum PROPERTIES
    CUDA_SEPARABLE_COMPILATION ON
    CXX_STANDARD 17
    CUDA_ARCHITECTURES ${DETECTED_CUDA_ARCH}
)

# Ensure C files are compiled with C compiler
set_source_files_properties(src/dns/dns.c PROPERTIES LANGUAGE C)

# Ensure CUDA files are compiled with proper options
target_compile_options(subsonicenum PRIVATE
    $<$<COMPILE_LANGUAGE:CUDA>:--expt-relaxed-constexpr>
    $<$<COMPILE_LANGUAGE:CUDA>:--extended-lambda>
)

# Set NDEBUG for non-Debug builds
if(NOT CMAKE_BUILD_TYPE MATCHES Debug)
    target_compile_definitions(subsonicenum PRIVATE NDEBUG)
    message(STATUS "NDEBUG defined for ${CMAKE_BUILD_TYPE} build")
endif()

# Allow toggling debug mode via CMake option
option(ENABLE_DEBUG "Enable debug output (disables NDEBUG)" OFF)
if(ENABLE_DEBUG)
    target_compile_definitions(subsonicenum PRIVATE -UNDEBUG)
    message(STATUS "Debug output enabled (NDEBUG undefined)")
endif()