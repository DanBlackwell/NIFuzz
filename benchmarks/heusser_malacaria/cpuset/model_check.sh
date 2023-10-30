#!/usr/bin/env bash

EXAMPLE="CBMC_DEFS_DIR=../../CBMC_utils/ RESULTS_DIR=results ./model_check.sh"

if [[ "$CBMC_DEFS_DIR" == "" ]]; then
  echo "Set env \$CBMC_DEFS_DIR (pointing to dir containing definitions.h) before running (e.g. $EXAMPLE)"
  exit 1
fi

if [[ "$RESULTS_DIR" == "" ]]; then
  echo "Set env \$RESULTS_DIR before running (e.g. $EXAMPLE)"
  exit 1
fi

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
echo "Storing output in $RESULTS_DIR/$(basename $SCRIPT_DIR)"
mkdir -p "$RESULTS_DIR/$(basename $SCRIPT_DIR)"
RESULTS_DIR="$RESULTS_DIR/$(basename $SCRIPT_DIR)"

for BITS_CHECKED in $(seq 1 8); do
  echo " Checking for $BITS_CHECKED bits of leakage"
  goto-cc -D CHECK_LEAKAGE=CHECK_${BITS_CHECKED}_BITS_LEAKAGE cbmc_harness.c -I$CBMC_DEFS_DIR -o model_check
  cbmc model_check --object-bits 16 --unwind 64 > $RESULTS_DIR/${BITS_CHECKED}_bits.out 2>&1

  LEAKED=$(grep -e "main.*Leak bound .*\: FAILURE" $RESULTS_DIR/${BITS_CHECKED}_bits.out)
  if [[ $LEAKED == "" ]]; then

    EXECUTED=$(grep -e "main.*Leak bound " $RESULTS_DIR/${BITS_CHECKED}_bits.out)
    if [[ $EXECUTED == "" ]]; then
      echo "Failed to complete execution checking for $BITS_CHECKED bits of leakage"
    else
      echo "Less than or equal to $BITS_CHECKED bits of leakage (ground truth: $BITS_LEAKED)"
    fi
    break
  fi
done
