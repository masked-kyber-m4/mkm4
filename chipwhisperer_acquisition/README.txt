INSTALLATION

1) Clone the MKM4 repository
git clone https://github.com/masked-kyber-m4/mkm4.git


2) Remove the hal-cw.c file
rm mkm4/common/hal-cw.c

2) Download the libopencm3 submodule
cd mkm4
git submodule init
git submodule update


3) Compile the libopencm3 submodule
cd libopencm3
make

4) Include the cw folder with Chipwhisperer code for this project in the mkm4 folder (cw/common and cw/crypto_kem are symlinked from the mkm4 folder)
mv ../../cw ../


5) Copy the libopencm3 directory to the cw directory
cp -r include/libopencm3 ../cw


**The included mkm4 folder has steps 1-5 done already**


5) Download the Chipwhisperer project and place in the same directory as the mkm4 folder and rename to "chipwhisperer"
https://github.com/newaetech/chipwhisperer/tree/master


COMPILATION - run from the cw folder

Because of missing implementations in libopencm3 library, the compilation is run in 2 steps. Step 1 (compile for STM32F4):
make PLATFORM="CW308_STM32F4" CRYPTO_TARGET=NONE

(this generates the required .o files)

Step 2 (compile for STM32F4 using the .o files from step 1):
make PLATFORM="CWLITEARM"


RUNNING
There are example files simpleserial-kyber.c and test_communication.py provided. After calling the target.simpleserial_write('p', text) in the Python file, contents of the text variable can be found in uint8_t* pt in the .c file. The speed is EXTREMELY dependent on the amount of communication, the number of bytes sent back can be set by calling target.output_len = X in Python and calling simpleserial_put('r', X, pt); in c.

python test_communication.py
