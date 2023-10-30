#!/bin/bash



for COLLECTION in SIFF heusser_malacaria; do
    pushd $COLLECTION;
        for DIR in */; do
            pushd $DIR;
                OUTPUT_DIR="$RESULTS_DIR/$(basename $DIR)"
                mkdir -p $OUTPUT_DIR
                echo "outputting to $OUTPUT_DIR/fuzz.out"
                if ! [ -z $RUNTIME ]; then
                    timeout $RUNTIME ./fuzz.sh > $OUTPUT_DIR/fuzz.out &
                fi
            popd;
        done;
    popd;
done;
wait
