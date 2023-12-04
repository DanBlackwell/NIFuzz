#!/bin/bash

set -e
rm -f queue/* violations/* crashes/*
../../../target/release/forkserver_libafl_cc ./fuzz ./corpus/ -t 1000
