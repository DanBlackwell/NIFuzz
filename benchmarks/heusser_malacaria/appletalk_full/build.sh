#!/bin/bash

pushd ../../../
  cargo build --release
popd

CFLAGS="-Wl,--wrap=malloc -Wl,--wrap=free"

gcc -O3 -c ../memory.c -o m.o

EXTRA_FILES="m.o"

CC=$PWD/../../../target/release/libafl_cc
$CC -O0 -Wall $CFLAGS atalk.c m.o -I../ -o fuzz

rm -f *.o
