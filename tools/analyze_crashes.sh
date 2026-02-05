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
# export IDA_PATH="/idapro-9.0"
# rsync -raz "$NFS_DIR/idapro-9.0/" "$IDA_PATH"

export USE_LLM_API=0

# pushd $IDA_PATH
# ./idapyswitch --auto-apply
# mkdir -p ~/.idapro
# cp ida.reg ~/.idapro/
# popd

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
FUZZING_OUTPUT_DIR="$OUTPUT_DIR/fuzzing"
CRASH_ANALYSIS_OUTPUT_DIR="$OUTPUT_DIR/crash_analysis"

mkdir -p "$LOG_OUTPUT_DIR"
mkdir -p "$WORK_OUTPUT_DIR"
mkdir -p "$INSTRUMENTATION_OUTPUT_DIR"
mkdir -p "$FUZZING_OUTPUT_DIR"
mkdir -p "$CRASH_ANALYSIS_OUTPUT_DIR"

LOCAL_OUTPUT_DIR="/aijon/results/$DATASET/$EXP_PATH"
LOCAL_LOG_OUTPUT_DIR="$LOCAL_OUTPUT_DIR/logs"
LOCAL_WORK_OUTPUT_DIR="$LOCAL_OUTPUT_DIR/work"
LOCAL_INSTRUMENTATION_OUTPUT_DIR="$LOCAL_OUTPUT_DIR/instrumentation"
LOCAL_FUZZING_OUTPUT_DIR="$LOCAL_OUTPUT_DIR/fuzzing"
LOCAL_CRASH_ANALYSIS_OUTPUT_DIR="$LOCAL_OUTPUT_DIR/crash_analysis"

mkdir -p "$LOCAL_LOG_OUTPUT_DIR"
mkdir -p "$LOCAL_WORK_OUTPUT_DIR"
mkdir -p "$LOCAL_INSTRUMENTATION_OUTPUT_DIR"
mkdir -p "$LOCAL_FUZZING_OUTPUT_DIR"
mkdir -p "$LOCAL_CRASH_ANALYSIS_OUTPUT_DIR"

chown -R 1000:1000 "$LOCAL_OUTPUT_DIR"

rsync -raz "$INSTRUMENTATION_OUTPUT_DIR/" "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/"
tar -xf "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/instrumentation.tar.gz" -C "$LOCAL_INSTRUMENTATION_OUTPUT_DIR"

rsync -raz "$WORK_OUTPUT_DIR/" "$LOCAL_WORK_OUTPUT_DIR/"
tar -xf "$LOCAL_WORK_OUTPUT_DIR/work.tar.gz" -C "$LOCAL_WORK_OUTPUT_DIR" || true
rsync -raz "$LOCAL_WORK_OUTPUT_DIR/" "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/"

chown -R $USER:$USER "$LOCAL_INSTRUMENTATION_OUTPUT_DIR"

rsync -raz "$FUZZING_OUTPUT_DIR/" "$LOCAL_FUZZING_OUTPUT_DIR/"
tar -xf "$LOCAL_FUZZING_OUTPUT_DIR/fuzzing.tar.gz" -C "$LOCAL_FUZZING_OUTPUT_DIR"
chown -R $USER:$USER "$LOCAL_FUZZING_OUTPUT_DIR"

docker pull gcr.io/oss-fuzz-base/base-builder:latest
docker pull gcr.io/oss-fuzz-base/base-runner:latest

mkdir -p /aijon/logs

if [ ! -d "$LOCAL_INSTRUMENTATION_OUTPUT_DIR" ]; then
    echo "Instrumentation output directory $LOCAL_INSTRUMENTATION_OUTPUT_DIR does not exist."
    exit 1
fi

if [ ! -d "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/aijon_instrumentation" ]; then
    echo "AIJON instrumentation directory $LOCAL_INSTRUMENTATION_OUTPUT_DIR/aijon_instrumentation does not exist."
    exit 1
fi

if [ ! -d "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/src" ];then
    echo "Source directory $LOCAL_INSTRUMENTATION_OUTPUT_DIR/src does not exist."
    exit 1
fi

if [ "$DATASET" == "google_fuzzer_test_suite" ]; then
    FUZZER_RESULT_DIRECTORY="$LOCAL_FUZZING_OUTPUT_DIR/out/fuzzer_afl_address_out"
else
    FUZZER_RESULT_DIRECTORY="$LOCAL_FUZZING_OUTPUT_DIR/out/result"
fi

if [ ! -d "$FUZZER_RESULT_DIRECTORY" ]; then
    echo "Fuzzer result directory $FUZZER_RESULT_DIRECTORY does not exist."
    exit 1
fi

ORIGINAL_BUILD_DIRECTORY=$(mktemp -d /tmp/original_build_XXXX)
# Build the original version without patches
uv run builder.py --target "$DIR_PATH" \
    --destination "$ORIGINAL_BUILD_DIRECTORY" \
    --target_source "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/src" \
    --patch_path "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/aijon_instrumentation/aijon_instrumentation.patch" \
    --allow_list "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/aijon_instrumentation/aijon_allowlist.txt" \
    --arvo --skip_patch

count=$(ls "$FUZZER_RESULT_DIRECTORY/default/crashes" | wc -l)
if [ "$count" -eq 0 ]; then
    echo "No crashes found in $FUZZER_RESULT_DIRECTORY/default/crashes."
    exit 0
fi

# Run the crashing inputs against the target
for crash_file in "$FUZZER_RESULT_DIRECTORY/default/crashes"/*; do
    filename=$(basename "$crash_file")
    if [ "$filename" == "README.txt" ]; then
	continue
    fi
    # Get the ASAN report
    if [ "$DATASET" == "google_fuzzer_test_suite" ]; then
        uv run reproduce.py --target "$DIR_PATH" \
            --harness "$ORIGINAL_BUILD_DIRECTORY/out/fuzzer" \
            --input_file "$crash_file" \
            --arvo
    else
        uv run reproduce.py --target "$DIR_PATH" \
            --harness "$ORIGINAL_BUILD_DIRECTORY/out/fuzzer" \
            --input_file "$crash_file" \
            --arvo --no_runner
    fi
    crash_file_basename=$(basename "$crash_file")
    if [ -f "$ORIGINAL_BUILD_DIRECTORY/out/asan.log" ]; then
        cp "$ORIGINAL_BUILD_DIRECTORY/out/asan.log" "$LOCAL_CRASH_ANALYSIS_OUTPUT_DIR/$crash_file_basename"
    fi
done

rsync -raz /aijon/logs/ "$LOCAL_LOG_OUTPUT_DIR/"

chown -R 1000:1000 "$LOCAL_OUTPUT_DIR"
tar -czf "$LOCAL_CRASH_ANALYSIS_OUTPUT_DIR.tar.gz" -C "$LOCAL_CRASH_ANALYSIS_OUTPUT_DIR" .
rsync -raz "$LOCAL_CRASH_ANALYSIS_OUTPUT_DIR.tar.gz" "$CRASH_ANALYSIS_OUTPUT_DIR/"
rsync -raz "$LOCAL_LOG_OUTPUT_DIR/" "$LOG_OUTPUT_DIR/"
