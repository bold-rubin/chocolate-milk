#!/usr/bin/env python3
import argparse
import csv
import json
import os
from collections import defaultdict
from multiprocessing import Pool, cpu_count

# Default path to binary mapping file
DEFAULT_MAPPING_FILE = os.path.join(os.path.dirname(__file__), "binary_mapping.csv")
failed_ijon_runs = {
}


failed_afl_runs = {

}


VULS = [
    "LUA001",
    "LUA002",
    "LUA003",
    "LUA004",
    "PDF001",
    "PDF003",
    "PDF004",
    "PDF006",
    "PDF007",
    "PDF008",
    "PDF009",
    "PDF010",
    "PDF011",
    "PDF012",
    "PDF014",
    "PDF016",
    "PDF018",
    "PDF019",
    "PDF021",
    "PDF022",
    "PHP002",
    "PHP003",
    "PHP004",
    "PHP009",
    "PHP011",
    "PNG001",
    "PNG003",
    "PNG004",
    "PNG005",
    "PNG006",
    "PNG007",
    "SQL002",
    "SQL003",
    "SQL006",
    "SQL007",
    "SQL009",
    "SQL010",
    "SQL011",
    "SQL012",
    "SQL013",
    "SQL014",
    "SQL015",
    "SQL016",
    "SQL017",
    "SQL018",
    "SQL019",
    "SQL020",
    "SSL001",
    "SSL002",
    "SSL003",
    "SSL005",
    "SSL008",
    "SSL009",
    "SSL010",
    "SSL016",
    "SSL019",
    "SSL020",
    "TIF001",
    "TIF002",
    "TIF003",
    "TIF005",
    "TIF006",
    "TIF007",
    "TIF008",
    "TIF009",
    "TIF010",
    "TIF012",
    "TIF014",
    "XML001",
    "XML002",
    "XML003",
    "XML006",
    "XML008",
    "XML009",
    "XML011",
    "XML012",
    "XML017",
]


def load_binary_mapping(mapping_file):
    """Load binary mapping from CSV file.

    Returns a dict mapping bug prefix (e.g., 'LUA') to list of harness names.
    Also returns a flat list of all harness names.
    """
    prefix_to_harnesses = {}
    all_harnesses = []

    try:
        with open(mapping_file, "r") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row or not row[0].strip():
                    continue
                prefix = row[0].strip()
                harnesses = [h.strip() for h in row[1:] if h.strip()]
                prefix_to_harnesses[prefix] = harnesses
                all_harnesses.extend(harnesses)
    except Exception as e:
        print(f"Error loading mapping file {mapping_file}: {e}")
        return {}, []

    return prefix_to_harnesses, all_harnesses


def find_monitor_dirs(base_dir, harness_list=None):
    """Find all directories matching 'ball/monitor' pattern.

    If harness_list is provided, only search within those harness directories
    under workdir/ to reduce search space.
    """
    monitor_dirs = []

    # If harness_list provided and base_dir ends with 'workdir', search only those harnesses
    if harness_list and os.path.basename(base_dir.rstrip(os.sep)) == "workdir":
        for harness in harness_list:
            harness_dir = os.path.join(base_dir, harness)
            if os.path.isdir(harness_dir):
                print(f"  Searching in harness: {harness}")
                for root, dirs, files in os.walk(harness_dir):
                    if os.path.basename(root) == "ball" and "monitor" in dirs:
                        monitor_dirs.append(os.path.join(root, "monitor"))
            else:
                print(f"  Harness directory not found: {harness}")
    else:
        # Fall back to full recursive search
        for root, dirs, files in os.walk(base_dir):
            # Check if current directory is 'ball' and contains 'monitor'
            if os.path.basename(root) == "ball" and "monitor" in dirs:
                monitor_dirs.append(os.path.join(root, "monitor"))

    return monitor_dirs


def extract_harness_and_trial(monitor_dir):
    """Extract harness name and trial number from monitor directory path.

    Expected path structure:
    .../workdir/fuzzing_lua/ar/shellphish_aijon/lua/lua/0/ball/monitor
                ^harness                              ^trial
    """
    parts = monitor_dir.split(os.sep)

    harness = None
    trial = None

    # Find workdir and get the next part as harness
    for i, part in enumerate(parts):
        if part == "workdir" and i + 1 < len(parts):
            harness = parts[i + 1]
            break

    # Trial number is the part just before 'ball/monitor'
    # Path ends with .../trial_num/ball/monitor
    for i, part in enumerate(parts):
        if part == "ball" and i > 0:
            trial_str = parts[i - 1]
            if trial_str.isdigit():
                trial = int(trial_str)
            break

    return harness, trial


def get_largest_filename(monitor_dir):
    """Find the largest numeric filename in the monitor directory."""
    try:
        files = os.listdir(monitor_dir)
        # Filter only numeric filenames
        numeric_files = [int(f) for f in files if f.isdigit()]
        if not numeric_files:
            return None
        return str(max(numeric_files))
    except Exception as e:
        print(f"Error reading {monitor_dir}: {e}")
        return None


def parse_monitor_file(file_path):
    """Parse the monitor file and extract bug_id_R values."""
    bug_data = {}
    try:
        with open(file_path, "r") as f:
            lines = f.readlines()
            if len(lines) < 2:
                return bug_data

            # Parse header and values
            headers = [h.strip() for h in lines[0].strip().split(",")]
            values = [v.strip() for v in lines[1].strip().split(",")]

            # Extract bug_id_R columns
            for i, header in enumerate(headers):
                if header.endswith("_R") and i < len(values):
                    bug_id = header[:-2]  # Remove '_R' suffix
                    try:
                        bug_data[bug_id] = float(values[i])
                    except ValueError:
                        print(
                            f"Warning: Could not convert value '{values[i]}' for {header}"
                        )
    except Exception as e:
        print(f"Error parsing file {file_path}: {e}")

    return bug_data


def process_monitor_dir(monitor_dir):
    """Process a single monitor directory and return bug data. Worker function for multiprocessing."""
    result = {
        "monitor_dir": monitor_dir,
        "bug_data": {},
        "largest_file": None,
        "harness": None,
        "trial": None,
    }

    # Extract harness and trial from path
    harness, trial = extract_harness_and_trial(monitor_dir)
    result["harness"] = harness
    result["trial"] = trial

    # Get the largest filename
    largest_file = get_largest_filename(monitor_dir)
    if largest_file is None:
        return result

    result["largest_file"] = largest_file
    file_path = os.path.join(monitor_dir, largest_file)

    # Parse the file
    result["bug_data"] = parse_monitor_file(file_path)

    return result


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Parse monitor files and aggregate bug statistics"
    )
    parser.add_argument(
        "base_dir", help="Base directory to search for ball/monitor folders"
    )
    parser.add_argument("output_dir", help="Directory to save the output JSON file")
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=None,
        help="Number of parallel jobs (default: number of CPUs)",
    )
    parser.add_argument(
        "-m",
        "--mapping",
        default=DEFAULT_MAPPING_FILE,
        help=f"Path to binary mapping CSV file (default: {DEFAULT_MAPPING_FILE})",
    )
    parser.add_argument(
        "--no-mapping",
        action="store_true",
        help="Disable mapping-based search optimization (search all directories)",
    )
    parser.add_argument(
        "--fuzzer",
        choices=["ijon", "aflpp"],
        default=None,
        help="Fuzzer type to filter out failed runs (ijon or aflpp)",
    )
    args = parser.parse_args()

    base_dir = args.base_dir
    output_file = os.path.join(args.output_dir, "bug_frequency.json")
    breakdown_file = os.path.join(args.output_dir, "bug_breakdown.json")
    num_workers = args.jobs if args.jobs else cpu_count()

    # Load binary mapping (always load for bug breakdown, but search optimization is optional)
    print(f"Loading binary mapping from: {args.mapping}")
    prefix_to_harnesses, all_harnesses = load_binary_mapping(args.mapping)

    # Use harness list for search optimization unless disabled
    harness_list = None
    if not args.no_mapping:
        if all_harnesses:
            harness_list = all_harnesses
            print(
                f"Found {len(harness_list)} harnesses to search: {', '.join(harness_list)}"
            )
        else:
            print("No harnesses found in mapping, will search all directories")

    # Determine which failed runs to skip based on fuzzer type
    failed_runs = {}
    if args.fuzzer == "ijon":
        failed_runs = failed_ijon_runs
        print("\nFuzzer: ijon - will skip failed ijon runs")
    elif args.fuzzer == "aflpp":
        failed_runs = failed_afl_runs
        print("\nFuzzer: aflpp - will skip failed aflpp runs")

    # Find all monitor directories
    print(f"\nSearching for monitor directories in: {base_dir}")
    monitor_dirs = find_monitor_dirs(base_dir, harness_list)
    print(f"Found {len(monitor_dirs)} monitor directories")
    print(f"Using {num_workers} parallel workers")

    # Aggregate bug data using multiprocessing
    total_bug_data = defaultdict(float)

    with Pool(processes=num_workers) as pool:
        results = pool.map(process_monitor_dir, monitor_dirs)

    # Build detailed breakdown structure:
    # bug_id -> harnesses -> harness_name -> trials dict (trial_num -> value)
    # Similar to bug_first_trigger.json format
    breakdown = defaultdict(lambda: {"harnesses": defaultdict(lambda: {"trials": {}})})

    # Track all trial numbers seen per harness (to fill in missing ones with 0)
    harness_trial_nums = defaultdict(set)

    # First pass: collect all trials per harness per bug
    skipped_count = 0
    for res in results:
        monitor_dir = res["monitor_dir"]
        largest_file = res["largest_file"]
        bug_data = res["bug_data"]
        harness = res["harness"]
        trial = res["trial"]

        print(f"\nProcessed: {monitor_dir}")
        if largest_file is None:
            print("  No numeric files found")
            continue

        # Skip failed trials based on fuzzer type
        if harness in failed_runs and trial in failed_runs[harness]:
            print(
                f"  SKIPPED: Failed {args.fuzzer} run (harness={harness}, trial={trial})"
            )
            skipped_count += 1
            continue

        print(f"  File: {largest_file}, Harness: {harness}, Trial: {trial}")

        # Track this trial number for the harness
        if harness is not None and trial is not None:
            harness_trial_nums[harness].add(trial)

        # Add to totals and breakdown
        for bug_id, value in bug_data.items():
            total_bug_data[bug_id] += value
            print(f"    {bug_id}: {value}")

            # Add to breakdown if harness is known
            if harness is not None and trial is not None:
                breakdown[bug_id]["harnesses"][harness]["trials"][trial] = value

    # Second pass: fill in missing trials with 0 and compute statistics
    # Also include all harnesses from the binary mapping for each bug's prefix
    final_breakdown = {}

    # Get all bug_ids: from breakdown AND from VULS list
    all_bug_ids = set(breakdown.keys()) | set(VULS)

    for bug_id in sorted(all_bug_ids):
        bug_info = breakdown.get(bug_id, {"harnesses": {}})
        harnesses_data = {}
        total_sum = 0.0
        total_count = 0

        # Determine which harnesses should be included for this bug
        # Extract prefix from bug_id (e.g., "LUA" from "LUA003")
        bug_prefix = "".join(c for c in bug_id if c.isalpha())
        expected_harnesses = prefix_to_harnesses.get(bug_prefix, [])

        # Combine harnesses found in data with expected harnesses from mapping
        all_harnesses_for_bug = set(bug_info["harnesses"].keys()) | set(
            expected_harnesses
        )

        for harness_name in sorted(all_harnesses_for_bug):
            harness_data = bug_info["harnesses"].get(harness_name, {"trials": {}})
            trials_dict = harness_data.get("trials", {})

            # Get all trial numbers for this harness (from all bugs, excluding skipped)
            all_trials = harness_trial_nums.get(harness_name, set())
            if all_trials:
                # Only include trials that were not skipped
                trial_values = []
                for t in sorted(all_trials):
                    trial_values.append(trials_dict.get(t, 0.0))
            else:
                # No trials found for this harness at all - use empty list
                trial_values = list(trials_dict.values()) if trials_dict else []

            count = len(trial_values)
            avg = sum(trial_values) / count if count > 0 else 0.0

            harnesses_data[harness_name] = {
                "trials": trial_values,
                "count": count,
                "avg": avg,
            }
            total_sum += sum(trial_values)
            total_count += count

        final_breakdown[bug_id] = {
            "harnesses": harnesses_data,
            "total_harnesses": len(harnesses_data),
            "final_avg": total_sum / total_count if total_count > 0 else 0.0,
        }

    # Convert defaultdict to regular dict and sort by key
    aggregated_result = dict(sorted(total_bug_data.items()))

    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)

    # Save breakdown JSON (before aggregation)
    with open(breakdown_file, "w") as f:
        json.dump(final_breakdown, f, indent=4)

    # Save aggregated JSON
    with open(output_file, "w") as f:
        json.dump(aggregated_result, f, indent=4)

    print(f"\n{'=' * 50}")
    if args.fuzzer:
        print(f"Fuzzer: {args.fuzzer} (skipped {skipped_count} failed runs)")
    print(f"Breakdown saved to: {breakdown_file}")
    print(f"Aggregated results saved to: {output_file}")
    print(f"Total bugs found: {len(aggregated_result)}")
    print("\nSummary:")
    for bug_id, total in aggregated_result.items():
        print(f"  {bug_id}: {total}")


if __name__ == "__main__":
    main()
