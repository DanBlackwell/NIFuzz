#!/bin/bash

set -e
rm -f queue/* crashes/* violations/*
../../../target/release/forkserver_libafl_cc ./fuzz ./corpus/ -t 1000 --cmi
