#!/bin/bash

pushd ../
  cargo build --release
popd

EXTRA_FILES=""
CFLAGS="-Wl,--wrap=malloc -g"

# gcc -O3 -c memory.c -o m.o
gcc -c memory.c -o m.o

EXTRA_FILES="m.o"

CC=../target/release/libafl_cc
$CC $CFLAGS $EXTRA_FILES atalk.c -o fuzz

rm -f *.o
