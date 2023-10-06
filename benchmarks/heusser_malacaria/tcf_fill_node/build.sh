#!/bin/bash

CFLAGS="-Wl,--wrap=malloc"

gcc -O3 -c ../memory.c -o m.o

EXTRA_FILES="m.o"

CC=$PWD/../../../target/release/libafl_cc
$CC -Wall $CFLAGS tcf_fill_node.c m.o -I../ -o fuzz

rm -f *.o
