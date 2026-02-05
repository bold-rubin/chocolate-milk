#!/bin/bash
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
TRIAL=${TRIAL:-1}
DEFAULT=${DEFAULT:-0}

OSS_FUZZ_PROJECT_DIR="/oss-fuzz"
if [ ! -d "$OSS_FUZZ_PROJECT_DIR" ]; then
	git clone https://github.com/google/oss-fuzz.git /oss-fuzz
fi

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
CRASH_ANALYSIS_OUTPUT_DIR="$OUTPUT_DIR/crash_analysis"

if [ "$DEFAULT" -eq 1 ]; then
    FUZZING_OUTPUT_DIR="$NFS_DIR/aflplusplus_results/$PROJECT_NAME/trial_${TRIAL}/fuzzing"
    CRASH_ANALYSIS_OUTPUT_DIR="$NFS_DIR/aflplusplus_results/$PROJECT_NAME/trial_${TRIAL}/crash_analysis"
fi

mkdir -p "$LOG_OUTPUT_DIR"
mkdir -p "$INSTRUMENTATION_OUTPUT_DIR"
mkdir -p "$FUZZING_OUTPUT_DIR"
mkdir -p "$CRASH_ANALYSIS_OUTPUT_DIR"

LOCAL_OUTPUT_DIR="/aijon/oss_fuzz_results/$PROJECT_NAME"
LOCAL_LOG_OUTPUT_DIR="$LOCAL_OUTPUT_DIR/logs"
LOCAL_INSTRUMENTATION_OUTPUT_DIR="$LOCAL_OUTPUT_DIR/instrumentation"
LOCAL_FUZZING_OUTPUT_DIR="$LOCAL_OUTPUT_DIR/fuzzing"
LOCAL_CRASH_ANALYSIS_OUTPUT_DIR="$LOCAL_OUTPUT_DIR/crash_analysis"

mkdir -p "$LOCAL_LOG_OUTPUT_DIR"
mkdir -p "$LOCAL_INSTRUMENTATION_OUTPUT_DIR"
mkdir -p "$LOCAL_FUZZING_OUTPUT_DIR"
mkdir -p "$LOCAL_CRASH_ANALYSIS_OUTPUT_DIR"

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

ORIGINAL_BUILD_DIRECTORY=$(mktemp -d /tmp/original_build_XXXXXX)
# Build the original version without patches
uv run builder.py --target "$DIR_PATH" \
    --destination "$ORIGINAL_BUILD_DIRECTORY" \
    --target_source "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/src" \
    --patch_path "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/aijon_instrumentation/aijon_instrumentation.patch" \
    --allow_list "$LOCAL_INSTRUMENTATION_OUTPUT_DIR/aijon_instrumentation/aijon_allowlist.txt" \
    --skip_patch

grep "^$EXP_ID," $BASE_DIR/experiments/oss_fuzz_coverage_target_mapping.csv | tr ',' '\n' | tail -n +3 > /tmp/actual_harnesses.txt

rsync -raz "$FUZZING_OUTPUT_DIR/" "$LOCAL_FUZZING_OUTPUT_DIR/"
while read -r HARNESS; do
    if [ -f "$LOCAL_FUZZING_OUTPUT_DIR/fuzzing.tar.gz" ]; then
        mv "$LOCAL_FUZZING_OUTPUT_DIR/fuzzing.tar.gz" "$LOCAL_FUZZING_OUTPUT_DIR/fuzzing_${HARNESS}.tar.gz"
        mv "$FUZZING_OUTPUT_DIR/fuzzing.tar.gz" "$FUZZING_OUTPUT_DIR/fuzzing_${HARNESS}.tar.gz"
    fi
    if [ ! -f "$LOCAL_FUZZING_OUTPUT_DIR/fuzzing_${HARNESS}.tar.gz" ]; then
        echo "Fuzzing output tarball $LOCAL_FUZZING_OUTPUT_DIR/fuzzing_${HARNESS}.tar.gz does not exist."
        continue
    fi
    tar -xf "$LOCAL_FUZZING_OUTPUT_DIR/fuzzing_${HARNESS}.tar.gz" -C "$LOCAL_FUZZING_OUTPUT_DIR"
    chown -R "$USER":"$USER" "$LOCAL_FUZZING_OUTPUT_DIR"

    if [ "$DEFAULT" -eq 1 ]; then
        FUZZER_RESULT_DIRECTORY="$LOCAL_FUZZING_OUTPUT_DIR/${HARNESS}_afl_address_out"
    else
        FUZZER_RESULT_DIRECTORY="$LOCAL_FUZZING_OUTPUT_DIR/out/${HARNESS}_afl_address_out"
    fi


    if [ ! -d "$FUZZER_RESULT_DIRECTORY" ]; then
        echo "Fuzzer result directory $FUZZER_RESULT_DIRECTORY does not exist."
        continue
    fi

    CRASHES_DIR="$FUZZER_RESULT_DIRECTORY/default/crashes"
    if [ ! -d "$CRASHES_DIR" ]; then
        echo "Crashes directory $CRASHES_DIR does not exist. Making it now"
        mkdir -p "$CRASHES_DIR"
        echo "Copying AFLPP crashes to crashes dir"
        AFLPP_CRASHES_DIR="$FUZZER_RESULT_DIRECTORY/aflpp/crashes"
        if [ -d "$AFLPP_CRASHES_DIR" ]; then
            count=$(ls "$AFLPP_CRASHES_DIR" | wc -l)
            if [ "$count" -gt 0 ]; then
                for inp_file in "$AFLPP_CRASHES_DIR"/id*; do
                    fname=$(cat $inp_file | md5sum)
                    cp "$inp_file" "$CRASHES_DIR/$fname"
                done
            fi
        fi
        echo "Copying AIJON crashes to crashes dir"
        AIJON_CRASHES_DIR="$FUZZER_RESULT_DIRECTORY/aijon/crashes"
        if [ -d "$AIJON_CRASHES_DIR" ]; then
            count=$(ls "$AIJON_CRASHES_DIR" | wc -l)
            if [ "$count" -gt 0 ]; then
                for inp_file in "$AIJON_CRASHES_DIR"/id*; do
                    fname=$(cat $inp_file | md5sum)
                    cp "$inp_file" "$CRASHES_DIR/$fname"
                done
            fi
        fi
    fi
    count=$(ls "$FUZZER_RESULT_DIRECTORY/default/crashes" | wc -l)
    if [ "$count" -eq 0 ]; then
        echo "No crashes found in $FUZZER_RESULT_DIRECTORY/default/crashes."
        continue
    fi

    # Run the crashing inputs against the target
    for crash_file in "$FUZZER_RESULT_DIRECTORY/default/crashes"/*; do
        filename=$(basename "$crash_file")
        if [ "$filename" == "README.txt" ]; then
          continue
        fi
        uv run reproduce.py --target "$DIR_PATH" \
            --harness "$ORIGINAL_BUILD_DIRECTORY/out/$HARNESS" \
            --input_file "$crash_file"

        crash_file_basename=$(basename "$crash_file")
        if [ -f "$ORIGINAL_BUILD_DIRECTORY/out/asan.log" ]; then
            cp "$ORIGINAL_BUILD_DIRECTORY/out/asan.log" "$LOCAL_CRASH_ANALYSIS_OUTPUT_DIR/$crash_file_basename"
        fi
    done

    chown -R 1000:1000 "$LOCAL_OUTPUT_DIR"
    tar -czf "$LOCAL_CRASH_ANALYSIS_OUTPUT_DIR.tar.gz" -C "$LOCAL_CRASH_ANALYSIS_OUTPUT_DIR" .
    rsync -raz "$LOCAL_CRASH_ANALYSIS_OUTPUT_DIR.tar.gz" "$CRASH_ANALYSIS_OUTPUT_DIR/crash_analysis_${HARNESS}.tar.gz"

    rsync -raz /aijon/logs/ "$LOCAL_LOG_OUTPUT_DIR/"
    rsync -raz "$LOCAL_LOG_OUTPUT_DIR/" "$LOG_OUTPUT_DIR/"
done < /tmp/actual_harnesses.txt
