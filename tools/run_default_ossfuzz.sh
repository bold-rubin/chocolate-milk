#!/bin/bash

set -e
set -x


if [ "$#" -eq 1 ]; then
    EXP_ID="$1"
elif [ -n "$EXP_ID" ]; then
    EXP_ID="$EXP_ID"
else
    echo "Usage: $0 <experiment_id>"
    echo "Please provide an experiment ID as the first argument or set the EXP_ID environment variable."
    exit 1
fi

TRIAL=${TRIAL:-1}

OSS_FUZZ_PROJECT_DIR="/oss-fuzz"
if [ ! -d "$OSS_FUZZ_PROJECT_DIR" ]; then
    git clone https://github.com/google/oss-fuzz.git /oss-fuzz
fi

NFS_DIR="/shared//aijon_stuff"
if [ ! -d "$NFS_DIR" ]; then
    echo "NFS mounted directory $NFS_DIR does not exist."
    exit 1
fi

BASE_DIR=$(realpath "$(dirname $(readlink -f $0))/../")
PROJECT_NAME=$(grep "^$EXP_ID," $BASE_DIR/experiments/ossfuzz_target_mapping.csv | cut -d',' -f2)
grep "^$EXP_ID," $BASE_DIR/experiments/ossfuzz_target_mapping.csv | tr ',' '\n' | tail -n +3 > /tmp/actual_harnesses.txt

if [ -z "$PROJECT_NAME" ]; then
    echo "No project name found for experiment ID $EXP_ID."
    exit 1
fi

DIR_PATH="$OSS_FUZZ_PROJECT_DIR/projects/$PROJECT_NAME"
if [ ! -d "$DIR_PATH" ]; then
    echo "Experiment directory $DIR_PATH does not exist."
    exit 1
fi

HELPER_SCRIPT="$OSS_FUZZ_PROJECT_DIR/infra/helper.py"
if [ ! -f "$HELPER_SCRIPT" ]; then
    echo "Helper script $HELPER_SCRIPT does not exist."
    exit 1
fi

OUTPUT_DIR="$NFS_DIR/aflplusplus_results/$PROJECT_NAME/trial_$TRIAL"
FUZZING_OUTPUT_DIR="$OUTPUT_DIR/fuzzing"

mkdir -p "$FUZZING_OUTPUT_DIR"

LOCAL_OUTPUT_DIR="$OSS_FUZZ_PROJECT_DIR/build/out"
LOCAL_FUZZING_OUTPUT_DIR="$LOCAL_OUTPUT_DIR/$PROJECT_NAME"

docker pull gcr.io/oss-fuzz-base/base-builder:latest
docker pull gcr.io/oss-fuzz-base/base-runner:latest

python3 "$HELPER_SCRIPT" build_image --pull "$PROJECT_NAME"
python3 "$HELPER_SCRIPT" build_fuzzers --engine afl --sanitizer address "$PROJECT_NAME"

chown -R 1000:1000 "$LOCAL_OUTPUT_DIR"

parallel --lb \
  'timeout 1d python3 {1} run_fuzzer \
      --engine afl \
      --sanitizer address \
      {2} {3}' \
  ::: "$HELPER_SCRIPT" \
  ::: "$PROJECT_NAME" \
  :::: /tmp/actual_harnesses.txt || true

docker rm -f $(docker ps -aq) || true

while read -r HARNESS; do
    tar -czf "$LOCAL_FUZZING_OUTPUT_DIR.tar.gz" -C "$LOCAL_FUZZING_OUTPUT_DIR" .
    mv "$LOCAL_FUZZING_OUTPUT_DIR.tar.gz" "$FUZZING_OUTPUT_DIR/fuzzing_${HARNESS}.tar.gz"
done < /tmp/actual_harnesses.txt

chown -R 1000:1000 "$FUZZING_OUTPUT_DIR"
