#!/bin/bash

set -e

if [[ "$1" == "fuzz" ]]; then
  pushd ../../../
    cargo build --release
  popd
  
  CC=$PWD/../../../target/release/libafl_cc
  $CC -O0 -Wall $CFLAGS fuzz_harness.c -I../../ -o fuzz
  
  rm -f *.o

elif [[ "$1" == "CBMC" || "$1" == "cbmc" ]]; then
  goto-cc -D CHECK_LEAKAGE=CHECK_2_BITS_LEAKAGE cbmc_harness.c -I$CBMC_DEFS_DIR -o model_check

elif [[ "$1" == "leakiest" || "$1" == "LeakiEst" ]]; then
  gcc leakiest_harness.c -I../../ -DSAMPLES=1000000 -DREPS=10 -o leakiest

else
  echo "Usage: $0 [CBMC|fuzz|LeakiEst]"
  exit
fi
