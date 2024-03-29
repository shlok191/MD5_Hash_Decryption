message(STATUS "==== Building MD5 Hash Components ====")

add_library(hash_kernels SHARED)

target_link_libraries(hash_kernels
    PUBLIC CUDA::cudart
    PUBLIC CUDA::nvrtc
    ${PYTHON_LIBRARIES}
    pybind11::headers
    )

message("Linked CUDA libraries...")

set(hash_headers 
    ${CMAKE_CURRENT_SOURCE_DIR}/Hash_Decryptor.cuh
    ${CMAKE_CURRENT_SOURCE_DIR}/md5-hard.cuh
    ${CMAKE_CURRENT_SOURCE_DIR}/md5-medium.cuh
    ${CMAKE_CURRENT_SOURCE_DIR}/md5-weak.cuh
    ${CMAKE_CURRENT_SOURCE_DIR}/md5-non-parallel.cuh
    ${CMAKE_CURRENT_SOURCE_DIR}/md5.cuh
    )

set(hash_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/Hash_Decryptor.cu
    ${CMAKE_CURRENT_SOURCE_DIR}/md5-hard.cu
    ${CMAKE_CURRENT_SOURCE_DIR}/md5-medium.cu
    ${CMAKE_CURRENT_SOURCE_DIR}/md5-weak.cu
    ${CMAKE_CURRENT_SOURCE_DIR}/md5-non-parallel.cu
    ${CMAKE_CURRENT_SOURCE_DIR}/md5.cu
)

target_sources(hash_kernels 
    PUBLIC ${hash_headers} 
    PRIVATE ${hash_sources}
)

message("Added all source files...")

set_target_properties(
    hash_kernels PROPERTIES
    LINKER_LANGUAGE CUDA
)

install(TARGETS hash_kernels
    LIBRARY 
    DESTINATION ${CMAKE_CURRENT_SOURCE_DIR})

pybind11_add_module(HashClass ${hash_headers} ${hash_sources})

message(STATUS "==== Built MD5 Hash Components Successfully ====")
