#!/bin/bash

set -e
set -x


analyze_one_harness () {
    HARNESS="$1"
    tar -xf "$LOCAL_FUZZING_OUTPUT_DIR/fuzzing_${HARNESS}.tar.gz" -C "$LOCAL_FUZZING_OUTPUT_DIR"
    chown -R "$USER":"$USER" "$LOCAL_FUZZING_OUTPUT_DIR"

    FUZZER_RESULT_DIRECTORY="$LOCAL_FUZZING_OUTPUT_DIR/out/${HARNESS}_afl_address_out"

    if [ ! -d "$FUZZER_RESULT_DIRECTORY" ]; then
        echo "Fuzzer result directory $FUZZER_RESULT_DIRECTORY does not exist."
        return
    fi

    ORIGINAL_ANALYSIS_DIRECTORY="$ORIGINAL_ANALYSIS_DIRECTORY/${HARNESS}_afl_address_out"
    ANALYSIS_RESULT_DIR="$PATCHED_ANALYSIS_DIRECTORY/${HARNESS}_afl_address_out"
    STDOUT_RESULT_DIR="$PATCHED_STDOUT_DIRECTORY/${HARNESS}_afl_address_out"

    TEMP_BUILD_DIR=$(mktemp -d /tmp/temp_build.XXXXXX)
    rsync -raz "$PATCHED_BUILD_DIRECTORY"/ "$TEMP_BUILD_DIR"/

    TEMP_ORIGINAL_DIR=$(mktemp -d /tmp/temp_original_build.XXXXXX)
    rsync -raz "$ORIGINAL_BUILD_DIRECTORY"/ "$TEMP_ORIGINAL_DIR"/

    mkdir -p "$ORIGINAL_ANALYSIS_DIRECTORY"
    mkdir -p "$ANALYSIS_RESULT_DIR"
    mkdir -p "$STDOUT_RESULT_DIR"

    # Run the queue against the original directory
    for queue_file in "$FUZZER_RESULT_DIRECTORY/default/queue"/*; do
        # Get the actual edge coverage data
        uv run showmap.py --target "$DIR_PATH" \
            --output "$TEMP_ORIGINAL_DIR/out" \
            --input_file "$queue_file" \
            --harness "$HARNESS"
        queue_file_basename=$(basename "$queue_file")
        if [ -f "$TEMP_ORIGINAL_DIR/out/map_output" ]; then
            cp "$TEMP_ORIGINAL_DIR/out/map_output" "$ORIGINAL_ANALYSIS_DIRECTORY/$queue_file_basename"
        fi

        # Get the annotation coverage data
        uv run showmap.py --target "$DIR_PATH" \
            --output "$TEMP_BUILD_DIR/out" \
            --input_file "$queue_file" \
            --harness "$HARNESS"

        queue_file_basename=$(basename "$queue_file")
        if [ -f "$TEMP_BUILD_DIR/out/map_output" ]; then
            cp "$TEMP_BUILD_DIR/out/map_output" "$ANALYSIS_RESULT_DIR/$queue_file_basename"
        fi
        if [ -f "$TEMP_BUILD_DIR/out/showmap.stdout" ]; then
            cp "$TEMP_BUILD_DIR/out/showmap.stdout" "$STDOUT_RESULT_DIR/$queue_file_basename"
        fi
    done
}


if [ "$#" -eq 1 ]; then
    EXP_ID="$1"
elif [ -n "$EXP_ID" ]; then
    EXP_ID="$EXP_ID"
else
    echo "Usage: $0 <experiment_id>"
    echo "Please provide an experiment ID as the first argument or set the EXP_ID environment variable."
    exit 1
fi

OSS_FUZZ_PROJECT_DIR="/oss-fuzz"
if [ ! -d "$OSS_FUZZ_PROJECT_DIR" ]; then
	git clone https://github.com/google/oss-fuzz.git /oss-fuzz
fi

TIMEOUT=${TIMEOUT:-86400}
NO_CACHE=${NO_CACHE:-0}
TRIAL=${TRIAL:-1}

NFS_DIR="/shared//aijon_stuff"
if [ ! -d "$NFS_DIR" ]; then
    echo "NFS mounted directory $NFS_DIR does not exist."
    exit 1
fi
export USE_LLM_API=0

BASE_DIR=$(realpath "$(dirname $(readlink -f $0))/../")
PROJECT_NAME=$(grep "^$EXP_ID," $BASE_DIR/experiments/oss_fuzz_coverage_target_mapping.csv | cut -d',' -f2)

if [ -z "$PROJECT_NAME" ]; then
    echo "No project name found for experiment ID $EXP_ID."
    exit 1
fi

DIR_PATH="$OSS_FUZZ_PROJECT_DIR/projects/$PROJECT_NAME"
if [ ! -d "$DIR_PATH" ]; then
    echo "Experiment directory $DIR_PATH does not exist."
    exit 1
fi

OSS_FUZZ_POI_DIR="$BASE_DIR/experiments/oss_fuzz_coverage_targets/coverage_targets_json_files"
OSS_FUZZ_POI_PATH="$OSS_FUZZ_POI_DIR/$PROJECT_NAME.json"
if [ ! -f "$OSS_FUZZ_POI_PATH" ]; then
    echo "Optimal targets file $OSS_FUZZ_POI_PATH does not exist."
    exit 1
fi

OUTPUT_DIR="$NFS_DIR/oss_fuzz_results/$PROJECT_NAME/trial_${TRIAL}"
LOG_OUTPUT_DIR="$OUTPUT_DIR/logs"
INSTRUMENTATION_OUTPUT_DIR="$OUTPUT_DIR/instrumentation"
FUZZING_OUTPUT_DIR="$OUTPUT_DIR/fuzzing"
ANALYSIS_OUTPUT_DIR="$OUTPUT_DIR/analysis"

mkdir -p "$LOG_OUTPUT_DIR"
mkdir -p "$INSTRUMENTATION_OUTPUT_DIR"
mkdir -p "$FUZZING_OUTPUT_DIR"
mkdir -p "$ANALYSIS_OUTPUT_DIR"

LOCAL_OUTPUT_DIR="/aijon/oss_fuzz_results/$PROJECT_NAME"
LOCAL_LOG_OUTPUT_DIR="$LOCAL_OUTPUT_DIR/logs"
LOCAL_INSTRUMENTATION_OUTPUT_DIR="$LOCAL_OUTPUT_DIR/instrumentation"
LOCAL_FUZZING_OUTPUT_DIR="$LOCAL_OUTPUT_DIR/fuzzing"
LOCAL_ANALYSIS_OUTPUT_DIR="$LOCAL_OUTPUT_DIR/analysis"

mkdir -p "$LOCAL_LOG_OUTPUT_DIR"
mkdir -p "$LOCAL_INSTRUMENTATION_OUTPUT_DIR"
mkdir -p "$LOCAL_FUZZING_OUTPUT_DIR"
mkdir -p "$LOCAL_ANALYSIS_OUTPUT_DIR"

chown -R 1000:1000 "$LOCAL_OUTPUT_DIR"

rsync -raz "$INSTRUMENTATION_OUTPUT_DIR/" "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/"
tar -xf "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/instrumentation.tar.gz" -C "$LOCAL_INSTRUMENTATION_OUTPUT_DIR" || true
chown -R $USER:$USER "$LOCAL_INSTRUMENTATION_OUTPUT_DIR"

docker pull ghcr.io/base-builder:latest
docker pull ghcr.io/base-runner:latest

docker tag ghcr.io/base-builder:latest gcr.io/oss-fuzz-base/base-builder:latest
docker tag ghcr.io/base-runner:latest gcr.io/oss-fuzz-base/base-runner:latest

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

grep "^$EXP_ID," $BASE_DIR/experiments/oss_fuzz_coverage_target_mapping.csv | tr ',' '\n' | tail -n +3 > /tmp/actual_harnesses.txt

rsync -raz /aijon/logs/ "$LOCAL_LOG_OUTPUT_DIR/"

ORIGINAL_BUILD_DIRECTORY=$(mktemp -d /tmp/original_build.XXXXXX)
PATCHED_BUILD_DIRECTORY=$(mktemp -d /tmp/patched_build.XXXXXX)
PATCHED_STDOUT_DIRECTORY="$LOCAL_ANALYSIS_OUTPUT_DIR/patched_stdout"
PATCHED_ANALYSIS_DIRECTORY="$LOCAL_ANALYSIS_OUTPUT_DIR/patched_analysis"
ORIGINAL_ANALYSIS_DIRECTORY="$LOCAL_ANALYSIS_OUTPUT_DIR/original_analysis"

mkdir -p "$PATCHED_ANALYSIS_DIRECTORY"
mkdir -p "$PATCHED_STDOUT_DIRECTORY"

chown -R 1000:1000 "$LOCAL_OUTPUT_DIR"

# Build the original version without patches
uv run builder.py --target "$DIR_PATH" \
    --destination "$ORIGINAL_BUILD_DIRECTORY" \
    --target_source "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/src" \
    --patch_path "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/aijon_instrumentation/aijon_instrumentation.patch" \
    --allow_list "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/aijon_instrumentation/aijon_allowlist.txt" \
     --skip_patch

uv run builder.py --target "$DIR_PATH" \
    --destination "$PATCHED_BUILD_DIRECTORY" \
    --target_source "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/src" \
    --patch_path "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/aijon_instrumentation/aijon_instrumentation.patch" \
    --allow_list "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/aijon_instrumentation/aijon_allowlist.txt" \
    --ijon_log

rsync -raz /aijon/logs/ "$LOCAL_LOG_OUTPUT_DIR/"
rsync -raz "$FUZZING_OUTPUT_DIR/" "$LOCAL_FUZZING_OUTPUT_DIR/"

# Export variables and function so they're available to parallel subprocesses
export LOCAL_FUZZING_OUTPUT_DIR
export ORIGINAL_ANALYSIS_DIRECTORY
export PATCHED_ANALYSIS_DIRECTORY
export PATCHED_STDOUT_DIRECTORY
export PATCHED_BUILD_DIRECTORY
export ORIGINAL_BUILD_DIRECTORY
export DIR_PATH
export USER
export -f analyze_one_harness

set +e
parallel --lb --timeout 86400 analyze_one_harness :::: /tmp/actual_harnesses.txt
set -e

rsync -raz /aijon/logs/ "$LOCAL_LOG_OUTPUT_DIR/"

chown -R 1000:1000 "$LOCAL_OUTPUT_DIR"
tar -czf "$LOCAL_ANALYSIS_OUTPUT_DIR.tar.gz" -C "$LOCAL_ANALYSIS_OUTPUT_DIR" .
rsync -raz "$LOCAL_ANALYSIS_OUTPUT_DIR.tar.gz" "$ANALYSIS_OUTPUT_DIR/"
rsync -raz "$LOCAL_LOG_OUTPUT_DIR/" "$LOG_OUTPUT_DIR/"
