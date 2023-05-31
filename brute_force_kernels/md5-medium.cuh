// -------------------------------------------------------------
//
// Author: Shlok Sabarwal
//
// CUDA kernel implementation of parallel brute-force
// attack on given password digest. Used to compare parallel
// vs non-parallel GPU performance
//
// * Characters considered: [a-z][A-Z]
//
// * INFORMATION USED TO CALCULATE BEGINNING AND ENDING INDEX *
//
// Each thread checks 500 passwords
// Threads / Block: 512
// Words / Block: 256,000
// Total Blocks: (Total combinations) / 256,000
//
// --------------------------------------------------------------

#include <cuda.h>

#ifndef medium_parallel_CUH
#define medium_parallel_CUH

__device__ void hash_gen_device_medium(char *password, char *hash);

__device__ void calculateWord_medium(char *placeholder, long long index);

__device__ int calcWordLength_medium(long long index);

__global__ void medium_parallel_medium(char *hash_digest, char *return_val, bool *match);

#endif