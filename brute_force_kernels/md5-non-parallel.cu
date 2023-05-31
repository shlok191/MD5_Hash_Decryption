#include <iostream>
#include "md5-non-parallel.cuh"
#include "md5.cuh"

using namespace std;

/*
    Definition:

        Kernel to generate hash from given password

    Parameters:

        1. char *password: password to be converted
        2. char *hash: reference to string pointer to store hash value
*/

__device__ void hash_gen_device_non_parallel(char *password, char *hash)
{

    // -------------------------
    // Defining needed variables
    // -------------------------

    int len = 0;

    union
    {

        unsigned word_chunk[16];
        unsigned char original_chunk[64];
    } block_union;

    while (password[len] != '\0')
        len++;

    /* Defining shift amounts */
    unsigned int s[4][4] = {

        {7, 12, 17, 22}, {5, 9, 14, 20}, {4, 11, 16, 23}, {6, 10, 15, 21}};

    /* Reporting k values */
    unsigned int K[64] =

        {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
         0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
         0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
         0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
         0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
         0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
         0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
         0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
         0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
         0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
         0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

    /* Defining addition vectors */
    unsigned int M[4] = {1, 5, 3, 7};
    unsigned int T[4] = {0, 1, 5, 0};

    int b_index = len;

    /* Converting bytes to bits, and then dividing by 512 (chunk size) */
    int t_chunks = (((len + 1) * 64) / 512) + 1;

    /* we need 64 bytes == 512 bits per chunk, giving us total mem need of t_chunks * 64*/
    /* Defining bit array of password with precise memory */

    char *bit_array = new char[t_chunks * 64];

    /* Defining buffers A, B, C, D */
    unsigned int buffers[4] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476};

    // ---------------------------
    // Pre-processing input string
    // ---------------------------

    /* Adding initial password to bit_array */
    for (int i = 0; i < len; i++)
        bit_array[i] = password[i];

    /* Adding indicative char showing end of password and beginning of padding */
    bit_array[len] = (unsigned char)0x80;
    b_index++;

    /* Adding padding of bits to make array length to (length % 512) == 448 */
    int multiple = t_chunks * 64;

    while (b_index < multiple)
    {

        bit_array[b_index] = 0;
        b_index++;
    }

    /* Adding length of original password into remaining bit array */

    unsigned temp_len_holder = (8 * len);
    b_index -= 8;

    MD5_break_down var;
    var.word = temp_len_holder;

    for (int i = 0; i < 4; i++, b_index++)
        bit_array[b_index] = var.chunks[i];

    // ----------------------------------------------------------
    // Processing bit_array (processed password) into hash digest
    // ----------------------------------------------------------

    for (int i = 0; i < t_chunks; i++)
    {

        /* Copying 64*8 = 512 bits of first block into block_union's 64 byte member */

        memcpy(block_union.original_chunk, bit_array + (i * 64), 64);

        unsigned int buff_copy[4];

        buff_copy[0] = buffers[0];
        buff_copy[1] = buffers[1];
        buff_copy[2] = buffers[2];
        buff_copy[3] = buffers[3];

        for (int j = 0; j < 4; j++)
        {

            unsigned int M_addition = M[j];
            unsigned int T_addition = T[j];

            for (int k = 0; k < 16; k++)
            {

                unsigned int F = 0;
                int G = ((M_addition * k) + T_addition) % 16;
                int func_index = ((j * 16) + k);

                if (func_index >= 0 && func_index <= 15)
                {

                    F = (buff_copy[1] & buff_copy[2]) | (~buff_copy[1] & buff_copy[3]);
                }

                else if (func_index >= 16 && func_index <= 31)
                {

                    F = (buff_copy[3] & buff_copy[1]) | (~buff_copy[3] & buff_copy[2]);
                }

                else if (func_index >= 32 && func_index <= 47)
                {

                    F = (buff_copy[1] ^ buff_copy[2] ^ buff_copy[3]);
                }

                else if (func_index >= 48 && func_index <= 63)
                {

                    F = (buff_copy[2] ^ (buff_copy[1] | ~buff_copy[3]));
                }

                F = F + buff_copy[0] + K[func_index] + block_union.word_chunk[G];
                F = (F << s[j][k % 4]) | (F >> (32 - s[j][k % 4]));

                buff_copy[0] = buff_copy[3];
                buff_copy[3] = buff_copy[2];
                buff_copy[2] = buff_copy[1];
                buff_copy[1] = buff_copy[1] + F;
            }
        }

        for (int j = 0; j < 4; j++)
        {

            buffers[j] += buff_copy[j];
        }
    }
    // ----------------------------------------------
    // Converting unsigned integers into hexadecimals
    // ----------------------------------------------

    MD5_break_down final_buffer;
    char const hex_chars[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    int hash_count = 0;

    for (int i = 0; i < 4; i++)
    {

        final_buffer.word = buffers[i];

        for (int j = 0; j < 4; j++)
        {

            char const byte = final_buffer.chunks[j];

            hash[hash_count] += hex_chars[(byte & 0xF0) >> 4];
            hash_count++;

            hash[hash_count] += hex_chars[(byte & 0x0F) >> 0];
            hash_count++;
        }
    }

    delete[] bit_array;
}

__global__ void non_parallel_non_parallel(char *hash_digest, char *password)
{

    // -----------------------------
    // Defining all needed variables
    // -----------------------------

    /* Hash will be used to store */
    char *hash = new char[32];

    /* Iteration will store current password iteration */
    char *iteration = new char[1];

    iteration[0] = '`';
    int iter_len = 1;

    // -------------------------------
    // Iterating accross all passwords
    // -------------------------------

    while (1)
    {

        for (int i = 0; i < 32; i++)
            hash[i] = NULL;

        /* We must break out of loop after reaching the final possible password iteration */

        if (iter_len == 7)
        {

            int i;
            for (i = 0; i < 7; i++)
            {

                if (iteration[i] != 'z')
                    break;
            }

            if (i == 7)
            {
                return;
            }
        }

        /* Locating the character to replace */

        int i;

        for (i = (iter_len - 1); i >= 0; i--)
        {

            if (iteration[i] != 'z')
                break;

            iteration[i] = 'a';
        }

        /* All characters equal to z, include new char to begin and set all chars to 'a' */

        if (i == (-1))
        {

            iter_len++;
            char *temp = new char[iter_len + 1];

            for (int i = 0; i < iter_len; i++)
            {
                temp[i] = 'a';
            }

            temp[iter_len] = '\0';

            /* Now, begin points to newly created char array */
            delete[] iteration;
            iteration = temp;
        }

        else
        {

            /* Increment char to next value */
            iteration[i] = (char)((int)iteration[i] + 1);
        }

        // ----------------------------------------------
        // Comparing MD5 hash of iteration to hash_digest
        // ----------------------------------------------

        /* Calculate the hash of iteration */
        hash_gen_device_non_parallel(iteration, hash);

        /* Comparing hash generated to given password's hash */
        for (i = 0; i < 32; i++)
        {
            if (hash[i] != hash_digest[i])
                break;
        }

        /* Found a match! */
        if (i == 32)
        {
            for (int i = 0; i < iter_len; i++)
                password[i] = iteration[i];
            return;
        }
    }
}