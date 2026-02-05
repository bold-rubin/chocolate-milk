#!/bin/bash

set -e
set -x

if [ $# -lt 3 ]; then
    echo "Usage: $0 <ossfuzz_project_dir> <corpus_dir> <harness_name>"
    exit 1
fi

SCRIPT_DIR=$(dirname "$(realpath "$0")")
PARSER_SCRIPT="$SCRIPT_DIR/parse_cov_report.py"

OSSFUZZ_PROJECT_DIR="$1"
CORPUS_DIR="$2"
HARNESS_NAME="$3"

OSS_FUZZ_BASE_DIR=$(realpath $OSSFUZZ_PROJECT_DIR/../../)

PROJECT_NAME=$(basename "$OSSFUZZ_PROJECT_DIR")

if [ ! -d "$OSSFUZZ_PROJECT_DIR" ]; then
    echo "OSS-Fuzz project directory $OSSFUZZ_PROJECT_DIR does not exist."
    exit 1
fi

if [ ! -d "$CORPUS_DIR" ]; then
    echo "Corpus directory $CORPUS_DIR does not exist."
    exit 1
fi

HELPER_SCRIPT="$OSS_FUZZ_BASE_DIR/infra/helper.py"

if [ ! -f "$HELPER_SCRIPT" ]; then
    echo "Helper script $HELPER_SCRIPT does not exist."
    exit 1
fi

python3 "$HELPER_SCRIPT" build_image "$PROJECT_NAME" --pull
python3 "$HELPER_SCRIPT" build_fuzzers --sanitizer coverage "$PROJECT_NAME"
python3 "$HELPER_SCRIPT" coverage --no-serve --fuzz-target "$HARNESS_NAME" --corpus-dir "$CORPUS_DIR" "$PROJECT_NAME"

# Grab the coverage report from OSS Fuzz too
OUTDIR="$OSS_FUZZ_BASE_DIR/build/out/$PROJECT_NAME/textcov_reports"
REPORT_LINK=$(curl "https://introspector.oss-fuzz.com/project-profile?project=$PROJECT_NAME" 2>/dev/null | grep '<td><a href=.*/fuzz_report.html">' | grep -oP '(?<=href=")[^"]*')
COVREPORT_LINK=$(echo "$REPORT_LINK" | sed "s|fuzz_report\.html|${HARNESS_NAME}.covreport|")
wget "$COVREPORT_LINK" -O "$OUTDIR/${HARNESS_NAME}_ossfuzz.covreport"

python3 "$PARSER_SCRIPT" "$OUTDIR/${HARNESS_NAME}_ossfuzz.covreport" "$OUTDIR/${HARNESS_NAME}.covreport" > "$OUTDIR/${HARNESS_NAME}_coverage_summary.txt"