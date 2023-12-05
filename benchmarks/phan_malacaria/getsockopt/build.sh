#!/bin/bash

set -e

if [[ "$1" == "fuzz" ]]; then
  pushd ../../../
    cargo build --release
  popd
  
  CFLAGS="-Wl,--wrap=malloc -Wl,--wrap=free -Wl,--wrap=realloc -Wall"
  
  gcc -O3 -c ../../memory.c -o m.o
  
  EXTRA_FILES="m.o"
  
  CC=$PWD/../../../target/release/libafl_cc
  $CC -O0 -Wall $CFLAGS fuzz_harness.c m.o -I../../ -o fuzz
  
  rm -f *.o

elif [[ "$1" == "CBMC" || "$1" == "cbmc" ]]; then
  goto-cc -D CHECK_LEAKAGE=CHECK_2_BITS_LEAKAGE cbmc_harness.c -I$CBMC_DEFS_DIR -o model_check

elif [[ "$1" == "LeakiEst" || "$1" == "leakiest" ]]; then
  CFLAGS="-Wl,--wrap=malloc -Wl,--wrap=free -Wl,--wrap=realloc -Wall"
  gcc -O3 -c ../../memory.c -o m.o
  
  gcc -O0 -Wall $CFLAGS leakiest_harness.c m.o -DSAMPLES=10000 -DREPS=1 -I../../ -o leakiest
  
  rm -f *.o
  
else
  echo "Usage: $0 [CBMC|fuzz|LeakiEst]"
  exit
fi
