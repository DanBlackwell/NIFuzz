#!/bin/bash

# pushd ../../../
#   cargo build --release
# popd
# 
# set -e
# 
# CFLAGS="-Wl,--wrap=malloc -Wl,--wrap=free -Werror -Wall"
# 
# gcc -O3 -c ../../memory.c -o m.o
# 
# EXTRA_FILES="m.o"
# 
# CC=$PWD/../../../target/release/libafl_cc
# $CC -Wall $CFLAGS fuzz_harness.c m.o -I../../ -o fuzz
# 
# rm -f *.o

goto-cc cbmc_harness.c -I../../CBMC_utils -o model_check
