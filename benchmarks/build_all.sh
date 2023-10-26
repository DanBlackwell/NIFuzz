#!/usr/bin/env bash

if [[ "$1" == "CBMC" || "$1" == "cbmc" ]]; then
  CBMC=1
elif [ "$1" == "fuzz" ]; then
  FUZZ=1
else
  echo "Usage: $0 [CBMC|fuzz]"
  exit
fi

for COLLECTION in SIFF heusser_malacaria; do
  pushd $COLLECTION
    for DIR in */; do
      pushd $DIR
        ./build.sh $1 2>&1 | tee build.log
        if [[ $# != 0 ]]; then
          echo "Failed to build $COLLECTION/$DIR - full output in build.log"
  	exit 1
        fi
      popd
    done
  popd
done
