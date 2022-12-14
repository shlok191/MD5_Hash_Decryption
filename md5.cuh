// -------------------------------------------------------------
//
// Author: Shlok Sabarwal
// Reference: https://en.wikipedia.org/wiki/MD5
//
// For the implementation of the MD5 function, reference from the 
// stated MD5 algorithm on the linked Wikipedia page was taken.
//
// --------------------------------------------------------------

#ifndef MD5_CUH
#define MD5_CUH

/* Union to assist in conversion of final unsigned integers to hexadecimals */

typedef union break_down {

    unsigned word;
    unsigned char chunks[4];

} MD5_break_down;


/* 
    Definition:  
    
        Kernel to generate hash from given password 
    
    Parameters:

        1. std::string password: password to be converted
        2. std::string hash: reference to string pointer to store hash value
*/

__global__ void hash_gen(char* password, char *hash);

#endif
