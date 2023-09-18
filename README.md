# CUDA-Enabled GPU Based Parallel MD5 Hash Decryption Project

This project was implemented for my final project submission to UW-Madison's graduate course Computer Science 759: High Performance Computing Applications in Engineering! In This project, to demonstrate the efficiency differences between CPU and GPU computations, I attempt to decrypt an MD5 hash encryption of a user specified password! Through this project, a difference of approx. 1000% was observed between standard CPU computations and a highly optimized GPU computation (with specific optimizations for GPU hardware structure!). To read more, please view the project's associated report here: 

This project builds a custom UNet architecture from scratch using PyTorch and OpenCV and implements multi-class instance segmentation on the Landcover.ai dataset of satellite images collected over Poland with masks provided for 4 class labels - forestry, roads, buildings, farmland. The Landcover.ai dataset can be accessed here: [Landcover.ai homepage](https://landcover.ai.linuxpolska.com/). The following diagram describes the implemented neural network: 


<p align="center"><img src="https://github.com/shlok191/PyTorch_Terrain_Segmentation/blob/main/data/unet-description/u-net-architecture.png" width="50%"></p>

The UNet deep learning structure first downscales all input features into smaller sizes before upscaling all features and converting given input channels to the required output channels (each channel representing one class label's pixels!) in order to accurately classify each pixel as a class unique class object. The process is accomplished by 2 implemented `nn.moduleLists` representing the curves of the "U" structure. Each moduleList consists of 2 custom implemented `DoubleConv` convolution class objects and 1 pooling operation each stage to get desired numbers of channels at each stage.

The following output images were obtained after 15 epochs of training!

<p align="center"><img src="https://github.com/shlok191/PyTorch_Terrain_Segmentation/blob/main/data/results.png" width="50%"></p>

The observed model had an accuracy of 82.2%. Due to a lack of newer GPUs in my tech stack, I did not pursue to train the model beyond 10-15 epochs. However, I am quite confident that increasing the epochs to ~ 40 would show a drastic improvevemnt giving us close to ~ 90% of accuracy as seen in the work done for the lunar rover project! Additionally, I will be looking into developing RNNs from scratch as well as a learning exercise and to further develop my expertise in the exciting world of computer vision!
