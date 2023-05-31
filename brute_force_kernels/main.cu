#include <iostream>
#include <cuda.h>
#include <random>
#include <string>
#include "md5.cuh"
#include "md5-hard.cuh"

using namespace std;

int main(int argc, char *argv[])
{

    char *password = new char[10];
    char *hash = new char[32];
    char *device_password;
    char *device_hash;
    char *returned_d_password;

    bool *match = new bool(false);
    bool *d_match;

    int p_len = 0;

    /* Accept password for conversion from user */
    if (argc > 1)
    {

        password = argv[1];
    }

    while (password[p_len] != '\0')
    {
        p_len++;
    }

    char *returned_password = new char[p_len];

    /* Calculating total combinations */
    long long combinations = 0;

    for (int i = 1; i <= p_len; i++)
    {

        combinations += pow(62, i);
    }

    long long blocks = (combinations / 256000);

    if (combinations % 256000 != 0)
        blocks++;

    cudaMalloc((void **)&device_password, p_len * sizeof(char));
    cudaMalloc((void **)&device_hash, 32 * sizeof(char));

    cudaMalloc((void **)&returned_d_password, p_len * sizeof(char));
    cudaMalloc(&d_match, sizeof(bool));

    cudaMemcpy(d_match, match, sizeof(bool), cudaMemcpyHostToDevice);
    cudaMemcpy(device_password, password, p_len * sizeof(char), cudaMemcpyHostToDevice);

    /* Call hash function and output generated hash from given password */
    hash_gen<<<1, 1>>>(device_password, device_hash);
    cudaDeviceSynchronize();

    cudaMemcpy(hash, device_hash, 32 * sizeof(char), cudaMemcpyDeviceToHost);

    cudaEvent_t start;
    cudaEvent_t stop;

    cudaEventCreate(&start);
    cudaEventCreate(&stop);

    /* Record start time */
    cudaEventRecord(start);

    hard_parallel<<<blocks, 512>>>(device_hash, returned_d_password, d_match);
    cudaDeviceSynchronize();
    std::cout << "Final error: " << cudaGetLastError() << endl;

    /* Record stop time */
    cudaEventRecord(stop);
    cudaEventSynchronize(stop);

    cudaMemcpy(returned_password, returned_d_password, p_len * sizeof(char), cudaMemcpyDeviceToHost);

    /* Get the elapsed time in milliseconds */
    float ms;
    cudaEventElapsedTime(&ms, start, stop);

    std::cout << "Total time taken: " << ms << " Original Password: " << returned_password << endl;

    return 0;
}
