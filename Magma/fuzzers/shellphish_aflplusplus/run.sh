#!/bin/bash

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
# - env TARGET: path to target work dir
# - env OUT: path to directory where artifacts are stored
# - env SHARED: path to directory shared with host (to store results)
# - env PROGRAM: name of program to run (should be found in $OUT)
# - env ARGS: extra arguments to pass to the program
# - env FUZZARGS: extra arguments to pass to the fuzzer
##

mkdir -p "$SHARED/findings"

# flag_cmplog=(-m none -c "$OUT/cmplog/$PROGRAM")
flag_cmplog=""

TIMEOUT=${TIMEOUT:-24h}
TIMEOUT_SECONDS=$(( $(echo $TIMEOUT | sed 's/h/*3600+/;s/m/*60+/;s/s/*1+/;s/+$//') ))

export AFL_SKIP_CPUFREQ=1
export AFL_NO_AFFINITY=1
export AFL_NO_UI=1
export AFL_MAP_SIZE=256000
export AFL_DRIVER_DONT_DEFER=1
export AFL_IGNORE_SEED_PROBLEMS=1

ORIGINAL_TARGET="$TARGET-orig"
"$FUZZER/repo/afl-fuzz" -M aflpp -t 10000+ -V $TIMEOUT_SECONDS -i "$TARGET/corpus/$PROGRAM" -o "$SHARED/findings" \
    $FUZZARGS -- "$OUT/afl-orig/$PROGRAM" $ARGS 2>&1 &

"$FUZZER/repo/afl-fuzz" -S aflpp1 -t 10000+ -i "$TARGET/corpus/$PROGRAM" -o "$SHARED/findings" \
    $FUZZARGS -- "$OUT/afl/$PROGRAM" $ARGS 2>&1
