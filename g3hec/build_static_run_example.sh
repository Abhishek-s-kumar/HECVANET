#!/bin/bash

NTL_PATH="/home/el18018/Desktop"

mkdir build
cd build
g++ -I$NTL_PATH/include -L$NTL_PATH/lib -c ../g3hcurve.C -lm -lntl
ar rvs g3hcurve.a g3hcurve.o
g++ -I$NTL_PATH/include -L$NTL_PATH/lib -L. -o sig_test ../sig_test.C g3hcurve.a -lm -lntl

./sig_test

cd ..