#!/usr/bin/env bash
set -euo pipefail

# Traverse trials/fuzzers under bignum findings and run a placeholder action on
# queue files. 

# Environment overrides (CLI options still take precedence):
#   PF_OUTPUT_ROOT - output root (default: results)
#   PF_TRIALS      - comma-separated list of trials (default: 0-10)
#   PF_DRY_RUN     - true/1/yes to enable dry-run by default
#   PF_JOBS        - parallel workers (default: 10)
# - env FUZZER: fuzzer name (from fuzzers/)
# - env TARGET: target name (from targets/)
# - env PROGRAM: program name (name of binary artifact from $TARGET/build.sh)
# - env ARGS: optional

if [[ -z "${FUZZER:-}" || -z "${TARGET:-}" || -z "${PROGRAM:-}" ]]; then
  echo '$FUZZER, $TARGET, and $PROGRAM must be specified as environment variables.'
  exit 1
fi


BASE_DIR="${PF_BASE_DIR:-/magma_shared/fuzzing_${PROGRAM##*/}/ar/${FUZZER##*/}/${TARGET##*/}/${PROGRAM##*/}}"
OUTPUT_ROOT="${PF_OUTPUT_ROOT:-/magma_shared/results/fuzzing_${PROGRAM##*/}}"
DRY_RUN=false

TRIAL_LIST="${PF_TRIALS:-}"

JOBS="${PF_JOBS:-10}"

if [[ ! "$JOBS" =~ ^[0-9]+$ ]] || (( JOBS < 1 )); then
  JOBS=1
fi

usage() {
  cat <<'EOF'
Usage: process_findings.sh [options]

Options:
  --dry-run               Print planned operations without writing output
  --output-root PATH      Where to store results (default: results; env PF_OUTPUT_ROOT)
  --trials "0,1,2"        Comma-separated trial IDs to process (default: 0-10; env PF_TRIALS)
  --jobs N                Number of parallel workers (default: nproc; env PF_JOBS)
  --help                  Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --output-root)
      OUTPUT_ROOT="${2:-}"
      shift 2
      ;;
    --trials)
      TRIAL_LIST="${2:-}"
      shift 2
      ;;
    --jobs)
      JOBS="${2:-}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$TRIAL_LIST" ]]; then
  TRIALS=(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15)
else
  IFS=',' read -r -a TRIALS <<< "$TRIAL_LIST"
fi

ACTION_CMD=(ls -l)

declare -A BUG_FIRST_SEEN=()

load_bug_dict() {
  local path="$1"

  if [[ -f "$path" ]]; then
    while read -r bug_id ts; do
      [[ -z "${bug_id:-}" || -z "${ts:-}" ]] && continue
      BUG_FIRST_SEEN["$bug_id"]="$ts"
    done < "$path"
  fi
}

save_bug_dict() {
  local path="$1"
  local dir

  dir=$(dirname "$path")
  mkdir -p "$dir"

  {
    for bug_id in "${!BUG_FIRST_SEEN[@]}"; do
      printf "%s %s\n" "$bug_id" "${BUG_FIRST_SEEN[$bug_id]}"
    done | sort
  } > "$path"
}

process_file() {
  local file="$1"
  local out_dir="$2"
  local bug_tmp_dir="$3"
  local src_type="$4"  # "queue" or "crashes"
  local base out_file status out code bug_id timestamp seed_id record_file
  local attempt runs
  local -a out_lines

  base=$(basename "$file")
  out_file="${out_dir}/${base}.out"
  

  mkdir -p "$out_dir"

  runs=1
  set +e
  for (( attempt=1; attempt<=runs; attempt++ )); do
    out="$("$MAGMA"/runonce.sh "$file")"
    code=$?
    out_lines+=("$file [code=${code}]: ${out}")
    if [[ -z "${bug_id:-}" && $out =~ bug[[:space:]]+([A-Za-z0-9_-]+) ]]; then
      bug_id="${BASH_REMATCH[1]}"
    fi
  done
  set -e
  printf '%s\n' "${out_lines[@]}" > "$out_file"

  if [[ -n "${bug_id:-}" && "$file" =~ id:([0-9]+) ]]; then
    seed_id="${BASH_REMATCH[1]}"
  fi


  #aflpp fuzzer seed in queue does not have time
  if [[ -n "${bug_id:-}" && -n "${seed_id:-}" ]]; then
    record_file=$(mktemp "${bug_tmp_dir}/bug.XXXXXX")
    printf "%s\t%s\t%s\t%s\n" "$bug_id" "$seed_id" "$src_type" "$file" > "$record_file"
  fi
  

}

update_bug_first_seen_from_tmp() {
  local bug_tmp_dir="$1"
  local bug_id seed_id src_type src_file record_file key
  local num
  num=$(ls -1 -- "$bug_tmp_dir" | wc -l)
  echo "$num bugs triggered in total via $FUZZER"
  shopt -s nullglob
  for record_file in "${bug_tmp_dir}"/bug.*; do
    IFS=$'\t' read -r bug_id seed_id src_type src_file < "$record_file" || continue
    [[ -z "${bug_id:-}" || -z "${seed_id:-}" || -z "${src_type:-}" ]] && continue
    key="${src_type}:${bug_id}"
    if [[ -z "${BUG_FIRST_SEEN[$key]:-}" ]] || (( 10#$seed_id < 10#${BUG_FIRST_SEEN[$key]} )); then
      echo "bug ${bug_id} (${src_type}) triggered by ${src_file}"
      BUG_FIRST_SEEN["$key"]="$seed_id"
    fi
  done
  shopt -u nullglob
}

for trial in "${TRIALS[@]}"; do
  trial_root="${BASE_DIR}/${trial}"


  if [[ ! -d "$trial_root" ]]; then
    echo "Skipping trial ${trial}: missing ${trial_root}"
    continue
  fi

  if [[ ! -d "${trial_root}/ball" ]]; then
    if [[ -f "${trial_root}/ball.tar" ]]; then
      mkdir -p "${trial_root}/ball"
      tar -xf "${trial_root}/ball.tar" -C "${trial_root}/ball"
    else
      echo "Skipping trial ${trial}: missing ${trial_root}/ball and ${trial_root}/ball.tar"
      continue
    fi
  fi
  trial_dir="${trial_root}/ball/findings"
  if [[ ! -d "$trial_dir" ]]; then
    echo "Skipping trial ${trial}: missing ${trial_dir}"
    continue
  fi

  for fuzzer_dir in "$trial_dir"/*; do
    [[ -d "$fuzzer_dir" ]] || continue
    fuzzer_name=$(basename "$fuzzer_dir")
    queue_dir="${fuzzer_dir}/queue"
    crashes_dir="${fuzzer_dir}/crashes"

    if [[ ! -d "$queue_dir" && ! -d "$crashes_dir" ]]; then
      echo "Skipping ${trial}/${fuzzer_name}: no queue or crashes dir"
      continue
    fi

    out_dir="${OUTPUT_ROOT}/trial${trial}/${fuzzer_name}"
    echo "out dir is ${out_dir}"

    BUG_FIRST_SEEN=()
    bug_dict_path="${out_dir}/bug_first_seen.txt"
    load_bug_dict "$bug_dict_path"

    bug_tmp_dir=$(mktemp -d)
    echo "tmp files saved in "$bug_tmp_dir""
    pids=()

    for src_dir in "$queue_dir" "$crashes_dir"; do
      [[ -d "$src_dir" ]] || continue
      src_type=$(basename "$src_dir")  # "queue" or "crashes"
      type_out_dir="${out_dir}/${src_type}"

      queue_files=()
      while IFS= read -r -d '' file; do
        queue_files+=("$file")
      done < <(find "$src_dir" -maxdepth 1 -type f ! -name "README.txt" -print0)

      if (( ${#queue_files[@]} )); then
        for file in "${queue_files[@]}"; do
          process_file "$file" "$type_out_dir" "$bug_tmp_dir" "$src_type" &
          pids+=($!)
          if (( ${#pids[@]} >= JOBS )); then
            wait "${pids[0]}"
            pids=("${pids[@]:1}")
          fi
        done
      fi
    done

    for pid in "${pids[@]}"; do
      wait "$pid"
    done

    update_bug_first_seen_from_tmp "$bug_tmp_dir"
    rm -rf "$bug_tmp_dir"
    save_bug_dict "$bug_dict_path"
  done
done
