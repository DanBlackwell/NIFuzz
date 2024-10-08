#!/bin/bash

set -e

if [[ "$1" == "fuzz" ]]; then
  pushd ../../../
    cargo build --release
  popd
  
  CC=$PWD/../../../target/release/libafl_cc
  $CC -O0 -Wall $CFLAGS reviewers.c -I../../ -o fuzz

elif [[ "$1" == "CBMC" || "$1" == "cbmc" ]]; then
  goto-cc -D CHECK_LEAKAGE=CHECK_2_BITS_LEAKAGE cbmc_harness.c -I$CBMC_DEFS_DIR -o model_check

else
  echo "Usage: $0 [CBMC|fuzz]"
  exit
fi
