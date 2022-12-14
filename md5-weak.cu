// -------------------------------------------------------------
//
// Author: Shlok Sabarwal
// 
// CUDA kernel implementation of parallel brute-force 
// attack on given password digest. Used to compare parallel
// vs non-parallel GPU performance 
//
// * Characters considered: [a-z]
//  
// * INFORMATION USED TO CALCULATE BEGINNING AND ENDING INDEX *
//  
// Each thread checks 500 passwords
// Threads / Block: 1024
// Words / Block: 512,000
// Total Blocks: (Total combinations) / 512,000
//
// --------------------------------------------------------------

#include <iostream>
#include "md5-weak.cuh"
#include "md5.cuh"

using namespace std;

/* 
    Definition:  
    
        Kernel to generate hash from given password 
    
    Parameters:

        1. char *password: password to be converted
        2. char *hash: reference to string pointer to store hash value
*/

__device__ void hash_gen_device(char *password, char *hash){

    /* Defining shift amounts */
    unsigned int s[4][4] = { 
            
        {7, 12, 17, 22}, {5,  9, 14, 20},
        {4, 11, 16, 23}, {6, 10, 15, 21}};

    /* Reporting k values */
    unsigned int K[64] = 
            
    {   0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 
        0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 
        0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 
        0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 
        0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    };

    /* Defining addition vectors */
    unsigned int M[4] = {1, 5, 3, 7};
    unsigned int T[4] = {0, 1, 5, 0};

    // ------------------------- 
    // Defining needed variables 
    // -------------------------

    union {

        unsigned word_chunk[16];
        unsigned char original_chunk[64];
    }   
    block_union;

    int len = 0;

    while(password[len] != '\0')
        len++;
    

    int b_index = len;
    
    /* Converting bytes to bits, and then dividing by 512 (chunk size) */
    int t_chunks = (((len + 1) * 64) / 512) + 1;

    /* we need 64 bytes == 512 bits per chunk, giving us total mem need of t_chunks * 64*/
    /* Defining bit array of password with precise memory */

    char *bit_array = new char[t_chunks * 64];

    /* Defining buffers A, B, C, D */
    unsigned int buffers[4] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 };

    // ---------------------------
    // Pre-processing input string
    // ---------------------------

    /* Adding initial password to bit_array */
    for(int i = 0; i < len; i++) bit_array[i] = password[i];

    /* Adding indicative char showing end of password and beginning of padding */
    bit_array[len] = (unsigned char)0x80;
    b_index++;

    /* Adding padding of bits to make array length to (length % 512) == 448 */
    int multiple = t_chunks*64;

    while(b_index < multiple){

        bit_array[b_index] = 0;
        b_index++;
    }
    
    /* Adding length of original password into remaining bit array */
    
    unsigned temp_len_holder = (8*len);
    b_index -= 8;

    MD5_break_down var;
    var.word = temp_len_holder;
    
    for(int i = 0; i < 4; i++, b_index++) bit_array[b_index] = var.chunks[i];
    
    // ----------------------------------------------------------
    // Processing bit_array (processed password) into hash digest
    // ----------------------------------------------------------

    for(int i = 0; i < t_chunks; i++){
        
        /* Copying 64*8 = 512 bits of first block into block_union's 64 byte member */
        
        memcpy(block_union.original_chunk, bit_array + (i*64), 64);

        unsigned int buff_copy[4];
        
        buff_copy[0] = buffers[0];
        buff_copy[1] = buffers[1];
        buff_copy[2] = buffers[2];
        buff_copy[3] = buffers[3];

        for(int j = 0; j < 4; j++){

            unsigned int M_addition = M[j];
            unsigned int T_addition = T[j]; 
    
            for(int k = 0; k < 16; k++){
                
                unsigned int F = 0;
                int G = ((M_addition*k) + T_addition) % 16;
                int func_index = ((j*16)+k);

                if(func_index >= 0 && func_index <= 15){
                    
                    F = (buff_copy[1] & buff_copy[2]) | (~buff_copy[1] & buff_copy[3]);
                }

                else if(func_index >= 16 && func_index <= 31){

                    F = (buff_copy[3] & buff_copy[1]) | (~buff_copy[3] & buff_copy[2]);
                }

                else if(func_index >= 32 && func_index <= 47){

                    F = (buff_copy[1] ^ buff_copy[2] ^ buff_copy[3]);
                }

                else if(func_index >= 48 && func_index <= 63){

                    F = (buff_copy[2] ^ (buff_copy[1] | ~buff_copy[3]));
                }

                F = F + buff_copy[0] + K[func_index] + block_union.word_chunk[G];
                F = (F << s[j][k%4]) | (F >> (32 - s[j][k%4]));
                
                buff_copy[0] = buff_copy[3];
                buff_copy[3] = buff_copy[2];
                buff_copy[2] = buff_copy[1];
                buff_copy[1] = buff_copy[1] + F;     
            }
        }

        for(int j = 0; j < 4; j++){

            buffers[j] += buff_copy[j];
        }
    }
    // ----------------------------------------------
    // Converting unsigned integers into hexadecimals
    // ----------------------------------------------
    
    MD5_break_down final_buffer;
    char const hex_chars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    int hash_count = 0;

    for(int i = 0; i < 4; i++){

        final_buffer.word = buffers[i];
        
        for(int j = 0; j < 4; j++){
            
            char const byte = final_buffer.chunks[j];

            hash[hash_count] += hex_chars [ ( byte & 0xF0 ) >> 4 ];
            hash_count++;

            hash[hash_count] += hex_chars [ ( byte & 0x0F ) >> 0 ];
            hash_count++;
        }
    }

    delete []bit_array;
}

__device__ int calcWordLength(long long index){
    
    int len = 1;
    
    while(index > pow(26, len)){

        index -= pow(26, len);    
        len++;
    }

    return len;
}

__device__ void calculateWord(char *placeholder, long long index){
    int len = 1;
    
    while(index > pow(26, len)){

        index -= pow(26, len);    
        len++;
    }

    for(int i = 0; i < len; i++) placeholder[i] = 'a';

    for(int i = 0; i < len; i++){

        while(pow(26, len-i-1) < index){

            placeholder[i] = (char)((int)placeholder[i] + 1);
            index -= pow(26, len-1-i);
        }
    }

    placeholder[len] = '\0';
}

__global__ void weak_parallel(char *hash_digest, char *return_val, bool *match){

    // ------------------------- 
    // Defining needed variables 
    // -------------------------

    /* Hash will be used to store */
    char* hash = new char[32];

    /* Calculates index of permutation of password thread begins work on  */
    long long beginIndex = (blockIdx.x*512000) + (threadIdx.x*500);
    
    /* Stores the beginning char array */
    
    int beginLen = calcWordLength(beginIndex);
    char *begin = new char[beginLen+1];
    
    calculateWord(begin, beginIndex);
    
    // -------------------------------
    // Iterating accross all passwords
    // -------------------------------

    int count = 0;

    while(1){
        
        /* Break each thread's execution if match turns true */
        
        if(*match == true){
            
            delete []hash;
            delete []begin;

            return;
        }

        for(int i = 0; i < 32; i++)
            hash[i] = NULL;       
        
        // ----------------------------------------------
        // Comparing MD5 hash of iteration to hash_digest
        // ----------------------------------------------

        /* Calculate the hash of iteration */
        hash_gen_device(begin, hash);
        
        /* Comparing hash generated to given password's hash */
        
        int i;
        for(i = 0; i < 32; i++){
            if(hash[i] != hash_digest[i]) break;
        }

        /* Found a match! */
        if(i == 32){

            for(int i = 0; i < beginLen; i++) return_val[i] = begin[i];
            *match = true;

            delete []hash;
            delete []begin;

            return;
        }

        /* We must break out of loop after reaching the final possible password iteration */
        
        if(count >= 500){

            delete []hash;
            delete []begin;

            return;
        }

        /* Locating the character to replace */
        
        for(i = (beginLen-1); i >= 0; i--){    
        
            if(begin[i] != 'z')     
                break;

            begin[i] = 'a';  
        }

        /* All characters equal to z, include new char to begin and set all chars to 'a' */

        if(i == (-1)){
            
            beginLen++;
            char *temp = new char[beginLen+1];

            for(int i = 0; i < beginLen; i++){
                temp[i] = 'a';
            }

            temp[beginLen] = '\0';
            
            /* Now, begin points to newly created char array */
            delete []begin;
            begin = temp;
        }

        else{

            /* Increment char to next value */
            begin[i] = (char)((int)begin[i] + 1);
        }

        count++;
    }

    delete []hash;
    delete []begin;
}