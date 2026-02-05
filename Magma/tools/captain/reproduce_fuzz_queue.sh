#!/usr/bin/env bash
set -euo pipefail

: "${ROOT_DIR:?Set ROOT_DIR to the base folder (e.g. /home/research/aijon_stuff/trial_aijon/default)}"
MANUAL_PATCHES="${MANUAL_PATCHES:-0}"
MODE="${MODE:-single}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -d "$ROOT_DIR" ]]; then
  echo "ROOT_DIR is not a directory: $ROOT_DIR" >&2
  exit 1
fi

if [[ ! -f "$SCRIPT_DIR/process_findings.sh" ]]; then
  echo "Missing process script" >&2
  exit 1
fi


if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required but not found in PATH" >&2
  exit 1
fi

WORKDIR="$ROOT_DIR/workdir"
mkdir -p "$WORKDIR"
export WORKDIR

cp "$SCRIPT_DIR/process_findings.sh" "$WORKDIR"

ERROR_DIR="$WORKDIR/errors"
mkdir -p "$ERROR_DIR"

safe_filename_component() {
  # Keep this conservative to avoid surprising paths.
  # (Do not use for security boundaries; only for nicer filenames.)
  tr -cs 'A-Za-z0-9._-' '_' <<<"${1:-}"
}

write_error_file() {
  local step_name="$1"
  local rc="$2"
  local log_file="$3"
  shift 3

  {
    echo "timestamp=$(date -Is)"
    echo "json_file=$json_file"
    echo "FUZZER=$FUZZER"
    echo "TARGET=$TARGET"
    echo "PROGRAM=$PROGRAM"
    echo "step=$step_name"
    echo "rc=$rc"
    printf 'cmd='
    printf '%q ' "$@"
    echo
    echo "---- output ----"
    cat "$log_file"
  } >"$ERROR_FILE"
}

run_step_or_record_error() {
  local step_name="$1"
  shift

  local tmp_log
  tmp_log="$(mktemp)"

  set +e
  "$@" 2>&1 | tee "$tmp_log"
  local rc="${PIPESTATUS[0]}"
  set -e

  if [[ "$rc" -ne 0 ]]; then
    write_error_file "$step_name" "$rc" "$tmp_log" "$@"
    rm -f "$tmp_log"
    return "$rc"
  fi

  rm -f "$tmp_log"
  return 0
}


find "$ROOT_DIR" -type f -name "*.json" -print0 | while IFS= read -r -d '' json_file; do
  VULN_ID=$(basename "$json_file" .json)
  FUZZER="$(jq -r 'keys_unsorted[0] // empty' "$json_file" 2>/dev/null || true)"
  if [[ -z "$FUZZER" ]]; then
    # If this JSON is malformed, jq will fail and we land here.
    err_file="$ERROR_DIR/$(safe_filename_component "$(basename "$json_file")")_error"
    {
      echo "timestamp=$(date -Is)"
      echo "json_file=$json_file"
      echo "step=parse_fuzzer"
      echo "---- output ----"
      jq -r 'keys_unsorted[0] // empty' "$json_file" 2>&1 || true
    } >"$err_file"
    echo "Skipping $json_file (failed to parse FUZZER); wrote $err_file" >&2
    continue
  fi

  TARGET="$(jq -r --arg f "$FUZZER" '.[$f] | keys_unsorted[-1] // empty' "$json_file" 2>/dev/null || true)"
  if [[ -z "$TARGET" ]]; then
    err_file="$ERROR_DIR/$(safe_filename_component "$FUZZER")_unknown_unknown_error"
    {
      echo "timestamp=$(date -Is)"
      echo "json_file=$json_file"
      echo "FUZZER=$FUZZER"
      echo "step=parse_target"
      echo "---- output ----"
      jq -r --arg f "$FUZZER" '.[$f] | keys_unsorted[-1] // empty' "$json_file" 2>&1 || true
    } >"$err_file"
    echo "Skipping $json_file (failed to parse TARGET); wrote $err_file" >&2
    continue
  fi

  PROGRAM="$(jq -r --arg f "$FUZZER" --arg t "$TARGET" '.[$f][$t] | keys_unsorted[0] // empty' "$json_file" 2>/dev/null || true)"
  if [[ -z "$PROGRAM" ]]; then
    err_file="$ERROR_DIR/$(safe_filename_component "$FUZZER")_unknown_$(safe_filename_component "$TARGET")_error"
    {
      echo "timestamp=$(date -Is)"
      echo "json_file=$json_file"
      echo "FUZZER=$FUZZER"
      echo "TARGET=$TARGET"
      echo "step=parse_program"
      echo "---- output ----"
      jq -r --arg f "$FUZZER" --arg t "$TARGET" '.[$f][$t] | keys_unsorted[0] // empty' "$json_file" 2>&1 || true
    } >"$err_file"
    echo "Skipping $json_file (failed to parse PROGRAM); wrote $err_file" >&2
    continue
  fi

  VULN_IDS="$(jq -r --arg f "$FUZZER" --arg t "$TARGET" --arg p "$PROGRAM" '.[$f][$t][$p].vul_id // [] | join(",")' "$json_file" 2>/dev/null || true)"

<<<<<<< HEAD
  echo "file=$json_file FUZZER=$FUZZER TARGET=$TARGET PROGRAM=$PROGRAM VULN_IDS=$VULN_IDS"
=======
  ERROR_FILE="$ERROR_DIR/$(safe_filename_component "$FUZZER")_$(safe_filename_component "$PROGRAM")_$(safe_filename_component "$TARGET")_error"

  if ! run_step_or_record_error "build" env \
      FUZZER="$FUZZER" \
      IJON_LOG=1 \
      MANUAL_PATCHES=$MANUAL_PATCHES \
      VULN_ID="$VULN_ID" \
      TARGET="$TARGET" \
      "$SCRIPT_DIR/build.sh"; then
    echo "Build failed for FUZZER=$FUZZER TARGET=$TARGET PROGRAM=$PROGRAM; continuing (see $ERROR_FILE)" >&2
    continue
  fi
  
  if [[ ! -d "$WORKDIR/$VULN_ID" ]]; then
    mkdir -p "${WORKDIR}/$VULN_ID"
    rsync -ravz "${ROOT_DIR}/${VULN_ID}/" "${WORKDIR}/${VULN_ID}/"
    # if ! run_step_or_record_error "extract" tar -xf "${ROOT_DIR}/fuzzing_${PROGRAM}.tar.gz" -C "${WORKDIR}/fuzzing_${PROGRAM}"; then
    #   rm -rf "${WORKDIR}/fuzzing_${PROGRAM}" || true
    #   echo "Extract failed for FUZZER=$FUZZER TARGET=$TARGET PROGRAM=$PROGRAM; continuing (see $ERROR_FILE)" >&2
    #   continue
    # fi
  fi
>>>>>>> 1e0a956c (updates to queue analysis)

  # some harness need args to run
  ARGS=""
  if [[ "$PROGRAM" == "tiffcp" ]]; then
    ARGS="-M @@ tmp.out"
  fi

  if [[ "$PROGRAM" == "xmllint" ]]; then
    ARGS="--valid --oldxml10 --push --memory @@"
  fi

  if [[ "$PROGRAM" == "pdfimages" ]]; then
    ARGS="@@ /tmp/out"
  fi

  if [[ "$PROGRAM" == "pdftoppm" ]]; then
    ARGS="-mono -cropbox @@"
  fi

  # Loop over each VUL_ID
  IFS=',' read -ra VUL_ID_ARRAY <<< "$VULN_IDS"
  for VUL_ID in "${VUL_ID_ARRAY[@]}"; do
    [[ -z "$VUL_ID" ]] && continue

    ERROR_FILE="$ERROR_DIR/$(safe_filename_component "$FUZZER")_$(safe_filename_component "$PROGRAM")_$(safe_filename_component "$TARGET")_$(safe_filename_component "$VUL_ID")_error"

    # Build with VULN_ID
    echo "Building for FUZZER=$FUZZER TARGET=$TARGET VULN_ID=$VUL_ID"
    
    if ! run_step_or_record_error "build" env \
        FUZZER="$FUZZER" \
        IJON_LOG=1 \
        MANUAL_PATCHES=$MANUAL_PATCHES \
        TARGET="$TARGET" \
        VULN_ID="$VUL_ID" \
        "$SCRIPT_DIR/build.sh"; then
      echo "Build failed for FUZZER=$FUZZER TARGET=$TARGET PROGRAM=$PROGRAM VULN_ID=$VUL_ID; continuing (see $ERROR_FILE)" >&2
      continue
    fi

    if ! run_step_or_record_error "copy_extract" cp -r "$ROOT_DIR/$VUL_ID" "$WORKDIR/${VUL_ID}"; then
      echo "Copy failed for VUL_ID=$VUL_ID; continuing (see $ERROR_FILE)" >&2
      continue
    fi
    
    pushd "$WORKDIR/${VUL_ID}" || continue
    find . -type f -name 'ball.tar' -print0 | while IFS= read -r -d '' tarpath; do
      dir="$(dirname "$tarpath")"
      out="$dir/ball"
      mkdir -p -- "$out" && tar -xf "$tarpath" -C "$out" || echo "Warning: Failed to extract $tarpath" >&2
    done
    popd

    
    echo "ARGS=$ARGS FUZZER=$FUZZER TARGET=$TARGET PROGRAM=$PROGRAM VULN_ID=$VUL_ID SHARED=$WORKDIR POLL=5 TIMEOUT=24h ENTRYPOINT=/magma_shared/process_findings.sh $SCRIPT_DIR/start.sh"
    if ! run_step_or_record_error "start" env \
      ARGS="$ARGS" \
      FUZZER="$FUZZER" \
      TARGET="$TARGET" \
      PROGRAM="$PROGRAM" \
      VULN_ID="$VUL_ID" \
      SHARED="$WORKDIR" \
      POLL=5 \
      TIMEOUT=24h \
      ENTRYPOINT=/magma_shared/process_findings.sh \
      "$SCRIPT_DIR/start.sh"; then
      echo "Start failed for FUZZER=$FUZZER TARGET=$TARGET PROGRAM=$PROGRAM VUL_ID=$VUL_ID; continuing (see $ERROR_FILE)" >&2
      continue
    fi
  done
done
