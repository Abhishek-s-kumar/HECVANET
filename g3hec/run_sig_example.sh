#!/bin/bash

NTL_PATH="/home/el18018/Desktop"

g++ -I$NTL_PATH/include -L$NTL_PATH/lib -L. -o sig_test sig_test.C g3hcurve.a -lm -lntl

./sig_test

rm sig_test