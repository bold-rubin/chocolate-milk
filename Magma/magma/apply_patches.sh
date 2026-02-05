#!/bin/bash
set -e
set -x

##
# Pre-requirements:
# - env TARGET: path to target work dir
##


add_ijon_log_to_patchids() {
    local file="$1"

    if [[ ! -f "$file" ]]; then
        echo "Error: File '$file' not found" >&2
        return 1
    fi

    # Use sed to prepend IJON_LOG(<num>); to lines with PATCHID comments
    # Pattern explanation:
    # ^(\+)        - Match and capture the '+' at start of line
    # (.*)         - Capture everything after '+' up to the PATCHID comment
    # \/\* PATCHID:\s*([0-9]+) \*\/ - Match PATCHID comment (with optional space after colon)
    # $            - End of line
    #
    # Replace with: +IJON_LOG(<num>);<original_code> /* PATCHID: <num> */
    sed -i -E 's/^(\+)(.*)\/\* PATCHID:\s*([0-9]+) \*\/$/\1IJON_LOG(\3);\2\/\* PATCHID: \3 *\//' "$file"

    echo "Modified $file - prepended IJON_LOG() to all PATCHID lines"
}

# TODO filter patches by target config.yaml
find "$TARGET/patches/setup" "$TARGET/patches/bugs" -name "*.patch" | \
while read patch; do
    echo "Applying $patch"
    name=${patch##*/}
    name=${name%.patch}
    sed "s/%MAGMA_BUG%/$name/g" "$patch" | patch -p1 -d "$TARGET/repo"
done

MANUAL_PATCHES=${MANUAL_PATCHES:-0}
IJON_LOG=${IJON_LOG:-0}
MODE=""
MAX=0
MIN=0
if [[ "$(basename $FUZZER)" == "aflplusplus_aijon" ]] || [[ "$(basename $FUZZER)" == "shellphish_aijon" ]]; then
    if [ "$MANUAL_PATCHES" -eq 1 ]; then
        if [ -f "$TARGET/patches/manual/aijon_instrumentation.patch" ]; then
            if [ "$IJON_LOG" -eq 1 ]; then
                add_ijon_log_to_patchids "$TARGET/patches/manual/aijon_instrumentation.patch"
            fi
            echo "Applying manual AIJON patch"
            patch -p1 -d "$TARGET/repo" < "$TARGET/patches/manual/aijon_instrumentation.patch" || true
        else
            echo "No manual AIJON patch found, skipping"
        fi
    elif [[ $MAX -eq 1 ]]; then
        if [ -f "$TARGET/patches/max/aijon_instrumentation.patch" ]; then
            echo "Applying Max AIJON patch"
            patch -p1 -d "$TARGET/repo" < "$TARGET/patches/max/aijon_instrumentation.patch" || true
        else
            echo "No Max AIJON patch found, skipping"
        fi
    elif [[ $MIN -eq 1 ]]; then
        if [ -f "$TARGET/patches/min/aijon_instrumentation.patch" ]; then
            echo "Applying Min AIJON patch"
            patch -p1 -d "$TARGET/repo" < "$TARGET/patches/min/aijon_instrumentation.patch" || true
        else
            echo "No Min AIJON patch found, skipping"
        fi
    else
        if [ -f "$TARGET/patches/aijon${MODE}/aijon_instrumentation.patch" ]; then
            if [ "$IJON_LOG" -eq 1 ]; then
                add_ijon_log_to_patchids "$TARGET/patches/aijon${MODE}/aijon_instrumentation.patch"
            fi
            echo "Applying AIJON patch"
            patch -p1 -d "$TARGET/repo" < "$TARGET/patches/aijon${MODE}/aijon_instrumentation.patch" || true
        else
            echo "No AIJON patch found, skipping"
        fi
    fi
fi
