#!/bin/bash

set -e
set -x

if [ "$#" -ge 1 ]; then
    TARGET="$1"
elif [ -n "$TARGET" ]; then
    TARGET="$TARGET"
else
    echo "Usage: $0 <experiment_id>"
    echo "Please provide a TARGET name as the first argument or set the TARGET environment variable."
    exit 1
fi

if [ "$#" -ge 2 ]; then
    HARNESS="$2"
elif [ -n "$HARNESS" ]; then
    HARNESS="$HARNESS"
else
    echo "Usage: $0 <experiment_id> <harness>"
    echo "Please provide a HARNESS name as the second argument or set the HARNESS environment variable."
    exit 1
fi

MODE=""
NFS_DIR="/shared/aijon_stuff"

# MAGMA_RESULTS_DIR="$NFS_DIR/results/magma_dataset/$TARGET/afl_fuzzing"
# MAGMA_RESULTS_DIR="$NFS_DIR/results/magma_dataset/$TARGET/minfuzzing${MODE}"
MAGMA_RESULTS_DIR="$NFS_DIR/results/magma_dataset/$TARGET/fuzzing${MODE}"
sudo mkdir -p "$MAGMA_RESULTS_DIR"
MAGMA_RESULT_FILE="$MAGMA_RESULTS_DIR/$HARNESS.json"
MAGMA_FUZZING_RESULT_FILE="$MAGMA_RESULTS_DIR/fuzzing_${HARNESS}.tar.gz"

BASE_DIR=$(realpath "$(dirname $(readlink -f $0))")
sudo chown -R ubuntu:ubuntu "$BASE_DIR"
CAPTAINRC_PATH="$BASE_DIR/tools/captain/captainrc"

# Replace the TARGET
# sed -i "s/shellphish_aflplusplus_TARGETS=(libpng)/shellphish_aflplusplus_TARGETS=($TARGET)/" "$CAPTAINRC_PATH"
sed -i "s/shellphish_aijon_TARGETS=(libpng)/shellphish_aijon_TARGETS=($TARGET)/" "$CAPTAINRC_PATH"

# Replace the HARNESS
# sed -i "s/shellphish_aflplusplus_libpng_PROGRAMS=(libpng_read_fuzzer)/shellphish_aflplusplus_${TARGET}_PROGRAMS=($HARNESS)/" "$CAPTAINRC_PATH"
sed -i "s/shellphish_aijon_libpng_PROGRAMS=(libpng_read_fuzzer)/shellphish_aijon_${TARGET}_PROGRAMS=($HARNESS)/" "$CAPTAINRC_PATH"

cd "$BASE_DIR/tools/captain"

# Prebuild the images
# ISAN=1 FUZZER=shellphish_aflplusplus TARGET="$TARGET" ./build.sh
ISAN=1 FUZZER=shellphish_aijon TARGET="$TARGET" ./build.sh

# Start fuzzing
cat "$CAPTAINRC_PATH"
./run.sh

echo "Fuzzing for target $TARGET with harness $HARNESS completed."
WORKDIR="$BASE_DIR/tools/captain/workdir"
if [ ! -d "$WORKDIR" ]; then
    echo "Captain workdir $WORKDIR does not exist."
    exit 1
fi

echo "Processing results..."
"$BASE_DIR/tools/benchd/exp2json.py" "$WORKDIR" result.json
jq '.results' < result.json | sudo tee "$MAGMA_RESULT_FILE"

echo "Results saved to $MAGMA_RESULT_FILE"

chown -R 1000:1000 "$WORKDIR"
tar -czf /magma/fuzzing.tar.gz -C "$WORKDIR" .
sudo cp /magma/fuzzing.tar.gz "$MAGMA_FUZZING_RESULT_FILE"
echo "Fuzzing artifacts saved to $MAGMA_FUZZING_RESULT_FILE"

# sleep 1d
