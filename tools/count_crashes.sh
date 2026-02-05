#!/bin/bash

set -e

if [ "$#" -eq 1 ]; then
    EXP_ID="$1"
elif [ -n "$EXP_ID" ]; then
    EXP_ID="$EXP_ID"
else
    echo "Usage: $0 <experiment_id>"
    echo "Please provide an experiment ID as the first argument or set the EXP_ID environment variable."
    exit 1
fi

DEFAULT=${DEFAULT:-0}

BASE_DIR=$(realpath "$(dirname $(readlink -f $0))/../")
PROJECT_NAME=$(grep "^$EXP_ID," $BASE_DIR/experiments/ossfuzz_target_mapping.csv | cut -d',' -f2)


LOCAL_OUTPUT_DIR="/aijon/oss_fuzz_results/$PROJECT_NAME"
LOCAL_FUZZING_OUTPUT_DIR="$LOCAL_OUTPUT_DIR/fuzzing"
if [ "$DEFAULT" -eq 1 ]; then
    LOCAL_FUZZING_OUTPUT_DIR="/oss-fuzz/build/out/$PROJECT_NAME"
fi

if [ ! -d "$LOCAL_FUZZING_OUTPUT_DIR" ]; then
    # echo "No fuzzing output directory found for project $PROJECT_NAME. Exiting."
    exit 0
fi

THING=$(find "$LOCAL_FUZZING_OUTPUT_DIR" -type f -name fuzzer_stats)
if [ -z "$THING" ]; then
    # echo "Fuzzing not started for project $PROJECT_NAME. Exiting."
    exit 0
fi

echo "-------------------- $PROJECT_NAME --------------------"
find "$LOCAL_FUZZING_OUTPUT_DIR" -type f -name fuzzer_stats | while read -r line; do
    HARNESS_OUT_DIR=$(basename $(dirname $(dirname "$line")))
    HARNESS_NAME=${HARNESS_OUT_DIR%_afl_address_out}
    NUM_CRASHES=$(grep 'saved_crashes' "$line" | awk -F':' '{print $2}')
    if [ "$NUM_CRASHES" -eq 0 ]; then
        continue
    fi
    echo "$HARNESS_NAME : $NUM_CRASHES"
done
