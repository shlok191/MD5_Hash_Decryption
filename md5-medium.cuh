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

#ifndef medium_parallel_CUH
#define medium_parallel_CUH

__device__ void hash_gen_device(char *password, char *hash);

__device__ void calculateWord(char *placeholder, long long index);

__device__ int calcWordLength(long long index);

__global__ void medium_parallel(char *hash_digest, char *return_val, bool *match);


#endif