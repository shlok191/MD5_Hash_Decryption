cmake_minimum_required(VERSION 3.18)

project(MD5_hash LANGUAGES CUDA CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)

# -------------------------------------------------- #
#  CUDA SUPPORT
# -------------------------------------------------- #

# Find CUDA package

find_package(CUDAToolkit REQUIRED)
find_package(pybind11 CONFIG)
find_package(CUDA REQUIRED)
find_package(PythonLibs REQUIRED)

include_directories(${PYTHON_INCLUDE_DIRS})

enable_language(CUDA)

message("${CMAKE_INSTALL_LIBDIR}")

# Global fix for CUDA language bug
include_directories(${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES})

# -------------------------------------------------- #
#  ADDING SUBDIRECTORIES
# -------------------------------------------------- #

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/brute_force_kernels)

# -------------------------------------------------- #
#  DEFINING EXECUTABLE
# -------------------------------------------------- #


add_executable(main main.cpp)
set_source_files_properties(main.cpp PROPERTIES LANGUAGE CUDA)

target_link_libraries(main CUDA::cudart)
target_link_libraries(main CUDA::cuda_driver)
target_link_libraries(main hash_kernels)
