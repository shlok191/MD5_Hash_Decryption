#include <iostream>
#include <cuda.h>
#include <random>
#include <cstring>
#include "Hash_Decryptor.cuh"
#include "md5.cuh"
#include "md5-hard.cuh"
#include "md5-medium.cuh"
#include "md5-weak.cuh"
#include "md5-non-parallel.cuh"

using namespace std;

string Hash_Decryptor::generate_hash(string password)
{

    char *hash = new char[32];

    char *device_password;
    char *device_hash;

    int pass_len = password.length();
    char *password_arr = new char[pass_len + 1];

    strcpy(password_arr, password.c_str());
    password_arr[pass_len] = '\0';

    /* Defining memory space for device password and hash */
    cudaMalloc((void **)&device_password, (pass_len + 1) * sizeof(char));
    cudaMalloc((void **)&device_hash, 32 * sizeof(char));

    cudaMemcpy(device_password, password_arr, pass_len * sizeof(char), cudaMemcpyHostToDevice);

    hash_gen<<<1, 1>>>(device_password, device_hash);

    cudaMemcpy(hash, device_hash, 32 * sizeof(char), cudaMemcpyDeviceToHost);

    string str_hash(hash);

    return str_hash;
}

string Hash_Decryptor::non_parallel_func(string hash)
{

    int p_len = 7;

    char *hash_arr = new char[32];
    char *password = new char[p_len];

    bool *match = new bool(false);

    // Converting provided string to character array
    strcpy(hash_arr, hash.c_str());

    char *d_password;
    char *d_hash_arr;
    bool *d_match;

    cudaMalloc((void **)&d_password, p_len * sizeof(char));
    cudaMalloc((void **)&d_hash_arr, 32 * sizeof(char));
    cudaMalloc((void **)&d_match, sizeof(bool));

    cudaMemcpy(d_match, match, sizeof(bool), cudaMemcpyHostToDevice);
    cudaMemcpy(d_hash_arr, hash_arr, sizeof(char) * 32, cudaMemcpyHostToDevice);

    non_parallel_non_parallel<<<1, 1>>>(d_hash_arr, d_password);

    // Copying back obtained values into host memory

    cudaMemcpy(match, d_match, sizeof(bool), cudaMemcpyDeviceToHost);
    cudaMemcpy(password, d_password, sizeof(char) * p_len, cudaMemcpyDeviceToHost);

    if (match)
    {
        return password;
    }

    else
    {
        string not_found = "Inconclusive attack.";
        return not_found;
    }
}

string Hash_Decryptor::weak_parallel_func(string hash)
{
    int p_len = 7;

    char *hash_arr = new char[32];
    char *password = new char[p_len];

    bool *match = new bool(false);

    /* Calculating total combinations of passwords */
    long long combinations = 0;

    for (int i = 1; i <= p_len; i++)
    {
        combinations += pow(26, i);
    }

    long long blocks = (combinations / 256000);

    // Converting provided string to character array
    strcpy(hash_arr, hash.c_str());

    char *d_password;
    char *d_hash_arr;
    bool *d_match;

    cudaMalloc((void **)&d_password, p_len * sizeof(char));
    cudaMalloc((void **)&d_hash_arr, 32 * sizeof(char));
    cudaMalloc((void **)&d_match, sizeof(bool));

    cudaMemcpy(d_match, match, sizeof(bool), cudaMemcpyHostToDevice);
    cudaMemcpy(d_hash_arr, hash_arr, sizeof(char) * 32, cudaMemcpyHostToDevice);

    weak_parallel_weak<<<blocks, 512>>>(d_hash_arr, d_password, d_match);

    // Copying back obtained values into host memory

    cudaMemcpy(match, d_match, sizeof(bool), cudaMemcpyDeviceToHost);
    cudaMemcpy(password, d_password, sizeof(char) * p_len, cudaMemcpyDeviceToHost);

    if (match)
    {
        return password;
    }

    else
    {
        string not_found = "Inconclusive attack.";
        return not_found;
    }
}

string Hash_Decryptor::medium_parallel_func(string hash)
{
    int p_len = 7;

    char *hash_arr = new char[32];
    char *password = new char[p_len];

    bool *match = new bool(false);

    /* Calculating total combinations of passwords */
    long long combinations = 0;

    for (int i = 1; i <= p_len; i++)
    {
        combinations += pow(52, i);
    }

    long long blocks = (combinations / 256000);

    // Converting provided string to character array
    strcpy(hash_arr, hash.c_str());

    char *d_password;
    char *d_hash_arr;
    bool *d_match;

    cudaMalloc((void **)&d_password, p_len * sizeof(char));
    cudaMalloc((void **)&d_hash_arr, 32 * sizeof(char));
    cudaMalloc((void **)&d_match, sizeof(bool));

    cudaMemcpy(d_match, match, sizeof(bool), cudaMemcpyHostToDevice);
    cudaMemcpy(d_hash_arr, hash_arr, sizeof(char) * 32, cudaMemcpyHostToDevice);

    medium_parallel_medium<<<blocks, 512>>>(d_hash_arr, d_password, d_match);

    // Copying back obtained values into host memory

    cudaMemcpy(match, d_match, sizeof(bool), cudaMemcpyDeviceToHost);
    cudaMemcpy(password, d_password, sizeof(char) * p_len, cudaMemcpyDeviceToHost);

    if (match)
    {
        return password;
    }

    else
    {
        string not_found = "Inconclusive attack.";
        return not_found;
    }
}

string Hash_Decryptor::hard_parallel_func(string hash)
{
    int p_len = 7;

    char *hash_arr = new char[32];
    char *password = new char[p_len];

    bool *match = new bool(false);

    /* Calculating total combinations of passwords */
    long long combinations = 0;

    for (int i = 1; i <= p_len; i++)
    {
        combinations += pow(62, i);
    }

    long long blocks = (combinations / 256000);

    // Converting provided string to character array
    strcpy(hash_arr, hash.c_str());

    char *d_password;
    char *d_hash_arr;
    bool *d_match;

    cudaMalloc((void **)&d_password, p_len * sizeof(char));
    cudaMalloc((void **)&d_hash_arr, 32 * sizeof(char));
    cudaMalloc((void **)&d_match, sizeof(bool));

    cudaMemcpy(d_match, match, sizeof(bool), cudaMemcpyHostToDevice);
    cudaMemcpy(d_hash_arr, hash_arr, sizeof(char) * 32, cudaMemcpyHostToDevice);

    hard_parallel_hard<<<blocks, 512>>>(d_hash_arr, d_password, d_match);

    // Copying back obtained values into host memory

    cudaMemcpy(match, d_match, sizeof(bool), cudaMemcpyDeviceToHost);
    cudaMemcpy(password, d_password, sizeof(char) * p_len, cudaMemcpyDeviceToHost);

    if (match)
    {
        return password;
    }

    else
    {
        string not_found = "Inconclusive attack.";
        return not_found;
    }
}
