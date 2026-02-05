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

if [ -z "$OPENAI_API_KEY" ]; then
    echo "OPENAI_API_KEY is not set. Please set it before running the script."
    exit 1
fi
if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "ANTHROPIC_API_KEY is not set. Please set it before running the script."
    exit 1
fi

TIMEOUT=${TIMEOUT:-86400}
NO_CACHE=${NO_CACHE:-0}

NFS_DIR="/shared//aijon_stuff"
if [ ! -d "$NFS_DIR" ]; then
    echo "NFS mounted directory $NFS_DIR does not exist."
    exit 1
fi
export IDA_PATH="/idapro-9.0"
rsync -raz "$NFS_DIR/idapro-9.0/" "$IDA_PATH"

export USE_LLM_API=0

pushd $IDA_PATH
./idapyswitch --auto-apply
mkdir -p ~/.idapro
cp ida.reg ~/.idapro/
popd

BASE_DIR=$(realpath "$(dirname $(readlink -f $0))/../")
DATASET=$(grep "^$EXP_ID," experiments/experiment_mapping.csv | cut -d',' -f2)
EXP_PATH=$(grep "^$EXP_ID," experiments/experiment_mapping.csv | cut -d',' -f3)

if [ -z "$DATASET" ]; then
    echo "Experiment ID $EXP_ID not found in experiments/experiment_mapping.csv."
    exit 1
fi

if [ -z "$EXP_PATH" ]; then
    echo "Experiment path for ID $EXP_ID not found in experiments/experiment_mapping.csv."
    exit 1
fi

DIR_PATH=$BASE_DIR/experiments/$DATASET/$EXP_PATH
if [ ! -d "$DIR_PATH" ]; then
    echo "Experiment directory $DIR_PATH does not exist."
    exit 1
fi

OUTPUT_DIR="$NFS_DIR/results/$DATASET/$EXP_PATH"
LOG_OUTPUT_DIR="$OUTPUT_DIR/logs"
WORK_OUTPUT_DIR="$OUTPUT_DIR/work"
INSTRUMENTATION_OUTPUT_DIR="$OUTPUT_DIR/instrumentation"
BUILD_OUTPUT_DIR="$OUTPUT_DIR/build"
FUZZING_OUTPUT_DIR="$OUTPUT_DIR/fuzzing"

mkdir -p "$LOG_OUTPUT_DIR"
mkdir -p "$WORK_OUTPUT_DIR"
mkdir -p "$INSTRUMENTATION_OUTPUT_DIR"
mkdir -p "$BUILD_OUTPUT_DIR"
mkdir -p "$FUZZING_OUTPUT_DIR"

LOCAL_OUTPUT_DIR="/aijon/results/$DATASET/$EXP_PATH"
LOCAL_LOG_OUTPUT_DIR="$LOCAL_OUTPUT_DIR/logs"
LOCAL_WORK_OUTPUT_DIR="$LOCAL_OUTPUT_DIR/work"
LOCAL_INSTRUMENTATION_OUTPUT_DIR="$LOCAL_OUTPUT_DIR/instrumentation"
LOCAL_BUILD_OUTPUT_DIR="$LOCAL_OUTPUT_DIR/build"
LOCAL_FUZZING_OUTPUT_DIR="$LOCAL_OUTPUT_DIR/fuzzing"

mkdir -p "$LOCAL_LOG_OUTPUT_DIR"
mkdir -p "$LOCAL_WORK_OUTPUT_DIR"
mkdir -p "$LOCAL_INSTRUMENTATION_OUTPUT_DIR"
mkdir -p "$LOCAL_BUILD_OUTPUT_DIR"
mkdir -p "$LOCAL_FUZZING_OUTPUT_DIR"

chown -R 1000:1000 "$LOCAL_OUTPUT_DIR"

rsync -raz "$INSTRUMENTATION_OUTPUT_DIR/" "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/"
tar -xf "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/instrumentation.tar.gz" -C "$LOCAL_INSTRUMENTATION_OUTPUT_DIR" || true

rsync -raz "$WORK_OUTPUT_DIR/" "$LOCAL_WORK_OUTPUT_DIR/"
tar -xf "$LOCAL_WORK_OUTPUT_DIR/work.tar.gz" -C "$LOCAL_WORK_OUTPUT_DIR" || true
rsync -raz "$LOCAL_WORK_OUTPUT_DIR/" "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/"

chown -R $USER:$USER "$LOCAL_INSTRUMENTATION_OUTPUT_DIR"

# rsync -raz "$FUZZING_OUTPUT_DIR/" "$LOCAL_FUZZING_OUTPUT_DIR/"

docker pull gcr.io/oss-fuzz-base/base-builder:latest
docker pull gcr.io/oss-fuzz-base/base-runner:latest

mkdir -p /aijon/logs

if [[ ! -f "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/aijon_instrumentation/aijon_instrumentation.patch" ]] || [[ $NO_CACHE -eq 1 ]]; then
    uv run main.py --target "$DIR_PATH" \
        --crash_report "$DIR_PATH/stderr" \
        --destination "$LOCAL_INSTRUMENTATION_OUTPUT_DIR" \
        --clang_indexer_output_dir "$LOCAL_INSTRUMENTATION_OUTPUT_DIR" \
        --arvo \
        --diff_only
fi
rsync -raz /aijon/logs/ "$LOCAL_LOG_OUTPUT_DIR/"
chown -R 1000:1000 "$LOCAL_OUTPUT_DIR"

rm -rf "$LOCAL_WORK_OUTPUT_DIR/out" || true
rm -rf "$LOCAL_WORK_OUTPUT_DIR/src" || true
rm -rf "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/work.tar.gz" || true
rm -rf "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/instrumentation.tar.gz" || true
mv "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/out" "$LOCAL_WORK_OUTPUT_DIR/"
mv "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/src" "$LOCAL_WORK_OUTPUT_DIR/"
tar -czf "$LOCAL_WORK_OUTPUT_DIR.tar.gz" -C "$LOCAL_WORK_OUTPUT_DIR" .
rsync -raz "$LOCAL_WORK_OUTPUT_DIR.tar.gz" "$WORK_OUTPUT_DIR/"

tar -czf "$LOCAL_INSTRUMENTATION_OUTPUT_DIR.tar.gz" -C "$LOCAL_INSTRUMENTATION_OUTPUT_DIR" .
rsync -raz "$LOCAL_INSTRUMENTATION_OUTPUT_DIR.tar.gz" "$INSTRUMENTATION_OUTPUT_DIR/"
rsync -raz "$LOCAL_LOG_OUTPUT_DIR/" "$LOG_OUTPUT_DIR/"

rsync -raz "$LOCAL_WORK_OUTPUT_DIR/" "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/"

uv run builder.py --target "$DIR_PATH" \
    --destination "$LOCAL_FUZZING_OUTPUT_DIR" \
    --target_source "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/src" \
    --patch_path "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/aijon_instrumentation/aijon_instrumentation.patch" \
    --allow_list "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/aijon_instrumentation/aijon_allowlist.txt" \
    --arvo
rsync -raz /aijon/logs/ "$LOCAL_LOG_OUTPUT_DIR/"

chown -R 1000:1000 "$LOCAL_OUTPUT_DIR"
tar -czf "$LOCAL_BUILD_OUTPUT_DIR.tar.gz" -C "$LOCAL_FUZZING_OUTPUT_DIR" .
rsync -raz "$LOCAL_BUILD_OUTPUT_DIR.tar.gz" "$BUILD_OUTPUT_DIR/"
rsync -raz "$LOCAL_LOG_OUTPUT_DIR/" "$LOG_OUTPUT_DIR/"

if [ "$DATASET" == "google_fuzzer_test_suite" ]; then
    uv run fuzz.py --target "$DIR_PATH" \
        --output "$LOCAL_FUZZING_OUTPUT_DIR/out" \
        --timeout "${TIMEOUT}" \
        --harness fuzzer \
        --arvo
else
    uv run fuzz.py --target "$DIR_PATH" \
        --output "$LOCAL_FUZZING_OUTPUT_DIR/out" \
        --timeout "${TIMEOUT}" \
        --harness fuzzer \
        --no_runner \
        --arvo
fi
rsync -raz /aijon/logs/ "$LOCAL_LOG_OUTPUT_DIR/"

chown -R 1000:1000 "$LOCAL_OUTPUT_DIR"
tar -czf "$LOCAL_FUZZING_OUTPUT_DIR.tar.gz" -C "$LOCAL_FUZZING_OUTPUT_DIR" .
rsync -raz "$LOCAL_FUZZING_OUTPUT_DIR.tar.gz" "$FUZZING_OUTPUT_DIR/"
rsync -raz "$LOCAL_LOG_OUTPUT_DIR/" "$LOG_OUTPUT_DIR/"
