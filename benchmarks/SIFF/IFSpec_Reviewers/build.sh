#!/bin/bash

set -e

pushd ../../../
  cargo build --release
popd

CC=$PWD/../../../target/release/libafl_cc
$CC -O0 -Wall $CFLAGS reviewers.c -I../../ -o fuzz
