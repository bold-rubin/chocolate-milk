#!/bin/bash

# Script to process AFL fuzzing crashes and generate ASAN reports
# Usage: ./process_crashes.sh
# DATASETS=("aflgo_dataset" "selectfuzz_dataset" "google_fuzzer_test_suite")
DATASETS=("google_fuzzer_test_suite")

OUTPUT_DIR="/home/projects/aijon/stuff"
EXPERIMENT_DIR="/home/projects/aijon/experiments"
DATASET_DIR="/home/projects/aijon/results"


# Function to extract command from fuzzer script
extract_target_command() {
    local fuzzer_file="$1"
    if [[ ! -f "$fuzzer_file" ]]; then
        echo "Error: Fuzzer file not found: $fuzzer_file" >&2
        return 1
    fi

    if head -c4 "$fuzzer_file" | grep -q $'\x7fELF'; then
        # Google fuzzer test suite makes ELF
        echo "./fuzzer"
    elif head -n1 "$fuzzer_file" | grep -q '^#!.*bash'; then
        # Other datasets use bash scripts
        # Extract the command after the last -- from the afl-fuzz line
        local cmd=$(grep "afl-fuzz" "$fuzzer_file" | sed 's/.*-- \/out/./')
        echo "$cmd"
    fi
}

# Function to process crashes for a project
process_project_crashes() {
    local project_dir="$1"
    local project_reproducer_dir="$2"
    local project_name=$(basename "$project_dir")

    echo "Processing project: $project_name"

    local fuzzer_file="$project_dir/fuzzing/out/fuzzer"
    local crashes_dir="$project_dir/fuzzing/out/result/default/crashes"
    local out_dir="$project_reproducer_dir/out"

    if [ "$DATASET" == "google_fuzzer_test_suite" ]; then
	crashes_dir="$project_dir/fuzzing/out/fuzzer_afl_address_out/default/crashes"
    fi

    # Check if required files/directories exist
    if [[ ! -f "$fuzzer_file" ]]; then
        echo "  Skipping: No fuzzer file found"
        return 0
    fi

    if [[ ! -d "$crashes_dir" ]]; then
        echo "  Skipping: No crashes directory found: $crashes_dir"
        return 0
    fi

    # Extract target command
    local target_cmd=$(extract_target_command "$fuzzer_file")
    if [[ -z "$target_cmd" ]]; then
        echo "  Error: Could not extract target command"
        return 1
    fi

    echo "  Target command: $target_cmd"

    # Count crash files (excluding README.txt)
    local crash_count=$(ls -1 "$crashes_dir" | grep -v "README.txt" | wc -l)
    echo "  Found $crash_count crash files"

    if [[ $crash_count -eq 0 ]]; then
        echo "  No crash files to process"
        return 0
    fi

    mkdir -p "$OUTPUT_DIR/${project_name}"
    cp $EXPERIMENT_DIR/$DATASET/$project_name/stderr $OUTPUT_DIR/${project_name}/stderr

    # Process each crash file
    local processed=0

    for crash_file in "$crashes_dir"/*; do
        local crash_filename=$(basename "$crash_file")

        # Skip README.txt
        if [[ "$crash_filename" == "README.txt" ]]; then
            continue
        fi

        echo "    Processing: $crash_filename"

        # Replace @@ with the crash file path in the target command
        local run_cmd="${target_cmd/@@/\"$crash_file\"}"

        # If the @@ does not exist in the target_cmd command, cat the crash_file as input
        if [[ "$target_cmd" != *"@@"* ]]; then
            run_cmd="${target_cmd} < \"$crash_file\""
        fi

        # Ensure the command is run in the fuzzing directory
        local full_cmd="cd ${out_dir} && ${run_cmd} && cd -"

        # Create output filename for ASAN report
        local asan_output="$OUTPUT_DIR/${project_name}/${crash_filename}_asan.txt"

        # Run the target with the crash file and capture ASAN output
        echo "Running: $full_cmd" > "$asan_output"
        echo "Crash file: $crash_file" >> "$asan_output"
        echo "Project: $project_name" >> "$asan_output"
        echo "=" >> "$asan_output"
        echo "" >> "$asan_output"

        # Execute the command with timeout and capture stderr (ASAN output)
        timeout 5s bash -c "$full_cmd" 1>/dev/null 2>> "$asan_output" || true

        echo "    Saved ASAN report to: $asan_output"
        processed=$((processed + 1))
    done

    echo "  Processed $processed crash files"
    echo ""
}

for DATASET in "${DATASETS[@]}"; do
    if [[ ! -d "$DATASET_DIR/$DATASET" ]]; then
        echo "Dataset directory $DATASET_DIR/$DATASET does not exist. Skipping $DATASET."
        continue
    fi
    EXP_DATASET_DIR="$DATASET_DIR/$DATASET"

    if [[ ! -d "$EXPERIMENT_DIR/$DATASET" ]]; then
        echo "Experiment directory $EXPERIMENT_DIR/$DATASET does not exist. Skipping $DATASET."
        continue
    fi
    REPRODUCER_DIR="$EXPERIMENT_DIR/$DATASET"

    # Main execution
    echo "Starting crash processing for $DATASET"
    echo "Dataset directory: $EXP_DATASET_DIR"
    echo "Output directory: $OUTPUT_DIR"
    echo ""

    # Find all project directories (containing CVE or issues in name)
    project_count=0
    for project_dir in "$EXP_DATASET_DIR"/*; do
        if [[ -d "$project_dir" ]]; then
            project_reproducer_dir="$REPRODUCER_DIR/$(basename "$project_dir")"
            process_project_crashes "$project_dir" "$project_reproducer_dir"
            project_count=$((project_count + 1))
        fi
    done

    echo "Completed processing $project_count projects"
    echo "ASAN reports saved to $OUTPUT_DIR/"
done
