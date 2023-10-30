#!/bin/bash

set -e

if [[ "$1" == "fuzz" ]]; then
  pushd ../../../
    cargo build --release
  popd
  
  CFLAGS="-Wl,--wrap=malloc -Wl,--wrap=free -Werror -Wall"
  
  gcc -O3 -c ../../memory.c -o m.o
  
  EXTRA_FILES="m.o"
  
  CC=$PWD/../../../target/release/libafl_cc
  $CC -Wall $CFLAGS fuzz_harness.c m.o -I../../ -o fuzz
  
  rm -f *.o

elif [[ "$1" == "CBMC" || "$1" == "cbmc" ]]; then
  goto-cc -D CHECK_LEAKAGE=CHECK_2_BITS_LEAKAGE cbmc_harness.c -I$CBMC_DEFS_DIR -o model_check

else
  echo "Usage: $0 [CBMC|fuzz]"
  exit
fi
