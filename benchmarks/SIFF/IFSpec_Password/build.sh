#!/bin/bash

set -e

# pushd ../../../
#   cargo build --release
# popd
# 
# CC=$PWD/../../../target/release/libafl_cc
# $CC -O0 -Wall $CFLAGS fuzz_harness.c -I../../ -o fuzz

CBMC=goto-cc
$CBMC -v cbmc_harness.c -I../../CBMC_utils -o model_check
