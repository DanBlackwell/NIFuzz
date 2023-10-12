#!/bin/bash

set -e
../../../target/release/forkserver_libafl_cc ./fuzz ./corpus/ -t 5000
