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
export IDA_PATH="/idapro-9.0"
rsync -raz "$NFS_DIR/idapro-9.0/" "$IDA_PATH"

export USE_LLM_API=0

pushd $IDA_PATH
./idapyswitch --auto-apply
mkdir -p ~/.idapro
cp ida.reg ~/.idapro/
popd

BASE_DIR=$(realpath "$(dirname $(readlink -f $0))/../")
PROJECT_NAME=$(grep "^$EXP_ID," $BASE_DIR/experiments/ossfuzz_target_mapping.csv | cut -d',' -f2)

if [ -z "$PROJECT_NAME" ]; then
    echo "No project name found for experiment ID $EXP_ID."
    exit 1
fi

DIR_PATH="$OSS_FUZZ_PROJECT_DIR/projects/$PROJECT_NAME"
if [ ! -d "$DIR_PATH" ]; then
    echo "Experiment directory $DIR_PATH does not exist."
    exit 1
fi

OSS_FUZZ_POI_DIR="$BASE_DIR/experiments/ossfuzz_targets/ossfuzz_targets_files"
OSS_FUZZ_POI_PATH="$OSS_FUZZ_POI_DIR/$PROJECT_NAME.yaml"
if [ ! -f "$OSS_FUZZ_POI_PATH" ]; then
    echo "Optimal targets file $OSS_FUZZ_POI_PATH does not exist."
    exit 1
fi

OUTPUT_DIR="$NFS_DIR/oss_fuzz_results/${PROJECT_NAME}/trial_${TRIAL}"
LOG_OUTPUT_DIR="$OUTPUT_DIR/logs"
INSTRUMENTATION_OUTPUT_DIR="$OUTPUT_DIR/instrumentation"
BUILD_OUTPUT_DIR="$OUTPUT_DIR/build"
FUZZING_OUTPUT_DIR="$OUTPUT_DIR/fuzzing"

if [ "$TRIAL" -gt 1 ]; then
    # Use cached annotation if we're running a subsequent trial
    NO_CACHE=0
    INSTRUMENTATION_OUTPUT_DIR="$NFS_DIR/oss_fuzz_results/${PROJECT_NAME}/trial_1/instrumentation"
    if [ ! -f "$INSTRUMENTATION_OUTPUT_DIR/instrumentation.tar.gz" ]; then
        echo "Cached instrumentation not found for project $PROJECT_NAME from trial 1."
        exit 1
    fi
fi

mkdir -p "$LOG_OUTPUT_DIR"
mkdir -p "$INSTRUMENTATION_OUTPUT_DIR"
mkdir -p "$BUILD_OUTPUT_DIR"
mkdir -p "$FUZZING_OUTPUT_DIR"

LOCAL_OUTPUT_DIR="/aijon/oss_fuzz_results/$PROJECT_NAME"
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
docker pull ghcr.io/base-builder:latest
docker pull ghcr.io/base-runner:latest

docker tag ghcr.io/base-builder:latest gcr.io/oss-fuzz-base/base-builder:latest
docker tag ghcr.io/base-runner:latest gcr.io/oss-fuzz-base/base-runner:latest

mkdir -p /aijon/logs
grep "^$EXP_ID," $BASE_DIR/experiments/ossfuzz_target_mapping.csv | tr ',' '\n' | tail -n +3 > /tmp/actual_harnesses.txt

if [[ ! -f "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/aijon_instrumentation/aijon_instrumentation.patch" ]] || [[ $NO_CACHE -eq 1 ]]; then
    uv run main.py --target "$DIR_PATH" \
        --oss_fuzz_report "$OSS_FUZZ_POI_PATH" \
        --destination "$LOCAL_INSTRUMENTATION_OUTPUT_DIR" \
        --clang_indexer_output_dir "$LOCAL_INSTRUMENTATION_OUTPUT_DIR" \
        --diff_only
fi
rsync -raz /aijon/logs/ "$LOCAL_LOG_OUTPUT_DIR/"

INSTRUMENTATION_OUTPUT_DIR="$NFS_DIR/oss_fuzz_results/${PROJECT_NAME}/trial_${TRIAL}/instrumentation"

chown -R 1000:1000 "$LOCAL_OUTPUT_DIR"
tar -czf "$LOCAL_INSTRUMENTATION_OUTPUT_DIR.tar.gz" -C "$LOCAL_INSTRUMENTATION_OUTPUT_DIR" .
rsync -raz "$LOCAL_INSTRUMENTATION_OUTPUT_DIR.tar.gz" "$INSTRUMENTATION_OUTPUT_DIR/"
rsync -raz "$LOCAL_LOG_OUTPUT_DIR/" "$LOG_OUTPUT_DIR/"

uv run builder.py --target "$DIR_PATH" \
    --destination "$LOCAL_FUZZING_OUTPUT_DIR" \
    --target_source "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/src" \
    --patch_path "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/aijon_instrumentation/aijon_instrumentation.patch" \
    --allow_list "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/aijon_instrumentation/aijon_allowlist.txt"

rsync -raz /aijon/logs/ "$LOCAL_LOG_OUTPUT_DIR/"

chown -R 1000:1000 "$LOCAL_OUTPUT_DIR"
tar -czf "$LOCAL_BUILD_OUTPUT_DIR.tar.gz" -C "$LOCAL_FUZZING_OUTPUT_DIR" .
rsync -raz "$LOCAL_BUILD_OUTPUT_DIR.tar.gz" "$BUILD_OUTPUT_DIR/"
rsync -raz "$LOCAL_LOG_OUTPUT_DIR/" "$LOG_OUTPUT_DIR/"

parallel --lb \
  'uv run fuzz.py --target {1} \
      --output {2}/out \
      --timeout {3} \
      --harness {4} \
      --ignore_errors \
      --hybrid' \
  ::: "$DIR_PATH" \
  ::: "$LOCAL_FUZZING_OUTPUT_DIR" \
  ::: "$TIMEOUT" \
  :::: /tmp/actual_harnesses.txt

rsync -raz /aijon/logs/ "$LOCAL_LOG_OUTPUT_DIR/"

chown -R 1000:1000 "$LOCAL_OUTPUT_DIR"
while read -r HARNESS; do
    tar -czf "$LOCAL_FUZZING_OUTPUT_DIR.tar.gz" -C "$LOCAL_FUZZING_OUTPUT_DIR" .
    mv "$LOCAL_FUZZING_OUTPUT_DIR.tar.gz" "$FUZZING_OUTPUT_DIR/fuzzing_${HARNESS}.tar.gz"
done < /tmp/actual_harnesses.txt
rsync -raz "$LOCAL_LOG_OUTPUT_DIR/" "$LOG_OUTPUT_DIR/"
