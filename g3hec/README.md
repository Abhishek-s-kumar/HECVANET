# Library for HECC genus 3

Based on [libg2hec](https://github.com/syncom/libg2hec/tree/master).

Using NTL library (tested on version 5.5).

Methods for genus 3 divisor addition and doubling based on algorithms 14.52 and 14.53 of 
[Handbook of Elliptic and Hyperelliptic Curve Cryptography](https://blkcipher.pl/assets/pdfs/Handbook_of_Elliptic_and_Hyperelliptic_Curve_Cryptography.pdf).

Scalar multiplication methods are implemented on libg2hec.

Minor changes on other methods were made to adapt to genus 3 curves and divisors.

## How-To build and link

To build the code as a static library edit *NTL_PATH* variable in *build_static_run_example.sh* with the correct path of the NTL library and run the script. Inside *build* folder there will be the static library file *g3hcurve.a*. Also a simple example of an ElGamal signature based on HECC genus 3 with a secure curve of 198-bit security level will be built and ran.

To link the library add *-L"your_g3hcurve_path"* and add *g3hcurve.a* on the libraries while compiling.