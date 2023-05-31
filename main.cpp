#include "brute_force_kernels/Hash_Decryptor.cuh"
#include <iostream>

int main()
{

    Hash_Decryptor decryptor;
    string output = decryptor.generate_hash("Shlok");

    std::cout << output << endl;
    return 0;
}
