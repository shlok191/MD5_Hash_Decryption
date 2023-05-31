#ifndef HASH_DECRYPTOR_H
#define HASH_DECRYPTOR_H

#include <iostream>
#include <cuda.h>
#include <random>
#include <cstring>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "md5.cuh"
#include "md5-hard.cuh"
#include "md5-medium.cuh"
#include "md5-weak.cuh"
#include "md5-non-parallel.cuh"
#include "Hash_Decryptor.cuh"

using namespace std;

/* Defining class to generate passwords and execute brute force attacks */

class Hash_Decryptor
{
public:
    Hash_Decryptor();
    /**
     *
     * Method: generate_hash
     *
     * Definition: Accesses password from user and utilizes MD5 hash to
     * convert it into a 32-length hash
     *
     * @param password: User specified password in string format
     * @return string: Returns string format for MD-5 hash
     *
     */

    const std::string generate_hash(const std::string &password);

    /**
     *
     * Method: non_parallel
     * Definition: Performs non-parallel hash decryption on GPU
     *
     * @param hash: User provided MD-5 hash
     * @return string: Returns the original input string
     *
     */

    string non_parallel(const std::string &hash);

    /**
     *
     * Method: weak_parallel
     * Definition: Performs parallel hash decryption on GPU on weak passwords
     *
     * @param hash: User provided MD-5 hash
     * @return string: Returns the original input string
     *
     */

    string weak_parallel(const std::string &hash);

    /**
     *
     * Method: medium_parallel
     * Definition: Performs parallel hash decryption on GPU on medium level passwords
     *
     * @param hash: User provided MD-5 hash
     * @return string: Returns the original input string
     *
     */

    string medium_parallel(const std::string &hash);

    /**
     *
     * Method: hard_parallel
     * Definition: Performs parallel hash decryption on GPU on hard level passwords
     *
     * @param hash: User provided MD-5 hash
     * @return string: Returns the original input string
     *
     */

    string hard_parallel(const std::string &hash);
};

#endif
