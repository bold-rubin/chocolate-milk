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

VULN_ID=${VULN_ID:-""}
if [[ "$(basename $FUZZER)" == "aflplusplus_aijon" ]] || [[ "$(basename $FUZZER)" == "shellphish_aijon" ]]; then
    # Apply the patch for VULN_ID
    if [ -z "$VULN_ID" ]; then
        echo "Error: VULN_ID is not set for Aijon fuzzer"
        exit 1
    fi
    aijon_patch="$TARGET/patches/ijonsinglebug/${VULN_ID}.patch"
    if [ ! -f "$aijon_patch" ]; then
        echo "Error: Aijon patch file '$aijon_patch' not found"
        exit 1
    fi
    echo "Applying Aijon patch for VULN_ID $VULN_ID"
    patch -p1 -d "$TARGET/repo" < "$aijon_patch"
fi
