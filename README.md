# CUDA-Enabled GPU Based Parallel MD5 Hash Decryption Project

This project was implemented for my final project submission to UW-Madison's graduate course Computer Science 759: High Performance Computing Applications in Engineering! In This project, to demonstrate the efficiency differences between CPU and GPU computations, I attempt to decrypt an MD5 hash encryption of a user specified password! Through this project, a difference of approx. 1000% was observed between standard CPU computations and a highly optimized GPU computation (with specific optimizations for GPU hardware structure!). To read more, please view the project's associated report here: [CS759ShlokSabarwalReport](./CS759ShlokSabarwal.pdf)


This was a really intensive for me considering it was my first proper usage of the CUDA frameworks for non-textbook related problems with neat answers, and I would really appreciate any and all constructive feedback for improvements! One of the major algorithmic challenges I faced in this project was dividing and correctly sequencing all possible permutations of the password sequences with equal workloads across all threads across all warps (all happening, in parallel, all at once!). I have included my undertaken mathematical permutation approach in my final report for curious readers!

**UPDATE** 
For assisting in my research lab's official software, I began experimenting with Pybind11 for this project to test how various python wrappers work around C++ and device-level CUDA code! To that end, I have successfully added a python wrapper library for MD5 that a user can use to implement all functions of C++ via python for ease of use!
  
# How to Implement

To use this model via C++:

1. Install CMake and CUDA v. >= 11.0
2. Create a temporary build folder in root directory.
3. After `cd build`, run the following command to build the project: `cmake .. -G Ninja` followed by `make` and `make install`.

To use this model via Python:

1. Simply run pip install . from the root directory and an MD5 named python library will be added to your site-packages!
2. This project -- via pybind11 -- further demonstrates how effectively pybind11 can work with GPU-enabled code along with comparisions between GPU and CPU processing!
   
