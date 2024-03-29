// -------------------------------------------------------------
//
// Author: Shlok Sabarwal
//
// CUDA kernel implementation of the non parallel brute-force
// attack on given password digest. Used to compare parallel
// vs non-parallel GPU performance
//
// --------------------------------------------------------------

#include <cuda.h>

#ifndef non_parallel_CUH
#define non_parallel_CUH

__device__ void hash_gen_device_non_parallel(char *password, char *hash);

__global__ void non_parallel_non_parallel(char *hash_digest, char *password);

#endif