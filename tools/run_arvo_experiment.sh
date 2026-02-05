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
CRAZY_MODE=${CRAZY_MODE:-0}

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
PROJECT_NAME=$(grep "^$EXP_ID," $BASE_DIR/experiments/arvo_experiment_mapping.csv | cut -d',' -f2)
HARNESS=$(grep "^$EXP_ID," $BASE_DIR/experiments/arvo_experiment_mapping.csv | cut -d',' -f3)

if [ -z "$PROJECT_NAME" ]; then
    echo "No project name found for experiment ID $EXP_ID."
    exit 1
fi

if [ -z "$HARNESS" ]; then
    echo "No harness found for experiment ID $EXP_ID."
    exit 1
fi

DATASET="arvo_dataset"
DIR_PATH=$BASE_DIR/experiments/$DATASET/$EXP_ID
if [ ! -d "$DIR_PATH" ]; then
    echo "Experiment directory $DIR_PATH does not exist."
    exit 1
fi

ARVO_POI_DIR="$BASE_DIR/experiments/$DATASET/$EXP_ID/cpv_info/cpv1/"
ARVO_POI_PATH="$ARVO_POI_DIR/stderr"
if [ ! -f "$ARVO_POI_PATH" ]; then
    echo "Optimal targets file $ARVO_POI_PATH does not exist."
    exit 1
fi

OUTPUT_DIR="$NFS_DIR/arvo_results/$EXP_ID"
LOG_OUTPUT_DIR="$OUTPUT_DIR/logs"
INSTRUMENTATION_OUTPUT_DIR="$OUTPUT_DIR/instrumentation"
BUILD_OUTPUT_DIR="$OUTPUT_DIR/build"
FUZZING_OUTPUT_DIR="$OUTPUT_DIR/fuzzing"

mkdir -p "$LOG_OUTPUT_DIR"
mkdir -p "$INSTRUMENTATION_OUTPUT_DIR"
mkdir -p "$BUILD_OUTPUT_DIR"
mkdir -p "$FUZZING_OUTPUT_DIR"

LOCAL_OUTPUT_DIR="/aijon/arvo_results/$DATASET/$EXP_ID"
LOCAL_LOG_OUTPUT_DIR="$LOCAL_OUTPUT_DIR/logs"
LOCAL_INSTRUMENTATION_OUTPUT_DIR="$LOCAL_OUTPUT_DIR/instrumentation"
LOCAL_BUILD_OUTPUT_DIR="$LOCAL_OUTPUT_DIR/build"
LOCAL_FUZZING_OUTPUT_DIR="$LOCAL_OUTPUT_DIR/fuzzing"

mkdir -p "$LOCAL_LOG_OUTPUT_DIR"
mkdir -p "$LOCAL_INSTRUMENTATION_OUTPUT_DIR"
mkdir -p "$LOCAL_BUILD_OUTPUT_DIR"
mkdir -p "$LOCAL_FUZZING_OUTPUT_DIR"

chown -R 1000:1000 "$LOCAL_OUTPUT_DIR"

rsync -raz "$INSTRUMENTATION_OUTPUT_DIR/" "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/"
tar -xf "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/instrumentation.tar.gz" -C "$LOCAL_INSTRUMENTATION_OUTPUT_DIR" || true
chown -R $USER:$USER "$LOCAL_INSTRUMENTATION_OUTPUT_DIR"

# rsync -raz "$FUZZING_OUTPUT_DIR/" "$LOCAL_FUZZING_OUTPUT_DIR/"

docker pull gcr.io/oss-fuzz-base/base-builder:latest
docker pull gcr.io/oss-fuzz-base/base-runner:latest

mkdir -p /aijon/logs

if [ $CRAZY_MODE -eq 1 ]; then
	EXTRA_ARGS="--crazy_mode"
else
	EXTRA_ARGS=""
fi

if [[ ! -f "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/aijon_instrumentation/aijon_instrumentation.patch" ]] || [[ $NO_CACHE -eq 1 ]]; then
    uv run main.py --target "$DIR_PATH" \
        --crash_report "$ARVO_POI_PATH" \
        --destination "$LOCAL_INSTRUMENTATION_OUTPUT_DIR" \
        --clang_indexer_output_dir "$LOCAL_INSTRUMENTATION_OUTPUT_DIR" \
        --arvo \
        --diff_only \
        --harness "$HARNESS" "$EXTRA_ARGS"
fi
rsync -raz /aijon/logs/ "$LOCAL_LOG_OUTPUT_DIR/"

chown -R 1000:1000 "$LOCAL_OUTPUT_DIR"
tar -czf "$LOCAL_INSTRUMENTATION_OUTPUT_DIR.tar.gz" -C "$LOCAL_INSTRUMENTATION_OUTPUT_DIR" .
rsync -raz "$LOCAL_INSTRUMENTATION_OUTPUT_DIR.tar.gz" "$INSTRUMENTATION_OUTPUT_DIR/"
rsync -raz "$LOCAL_LOG_OUTPUT_DIR/" "$LOG_OUTPUT_DIR/"

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

uv run fuzz.py --target "$DIR_PATH" \
    --output "$LOCAL_FUZZING_OUTPUT_DIR/out" \
    --timeout "${TIMEOUT}" \
    --harness "$HARNESS" \
    --arvo

rsync -raz /aijon/logs/ "$LOCAL_LOG_OUTPUT_DIR/"

chown -R 1000:1000 "$LOCAL_OUTPUT_DIR"
tar -czf "$LOCAL_FUZZING_OUTPUT_DIR.tar.gz" -C "$LOCAL_FUZZING_OUTPUT_DIR" .
rsync -raz "$LOCAL_FUZZING_OUTPUT_DIR.tar.gz" "$FUZZING_OUTPUT_DIR/"
rsync -raz "$LOCAL_LOG_OUTPUT_DIR/" "$LOG_OUTPUT_DIR/"
