import argparse
import json
import os
import re
from collections import defaultdict
from multiprocessing import Pool, cpu_count
from pathlib import Path

failed_ijon_runs = {
}


failed_afl_runs = {
}


def extract_harness_and_trial(filepath, single_mode=False):
    """Extract harness name and trial number from a .out file path.

    Expected path pattern (normal mode):
      /path/to/fuzzing_harness_name/trialN/something.out
      e.g., .../fuzzing_bignum/trial0/...

    Expected path pattern (single mode):
      /path/to/BUG_ID/trialN/fuzzer_type/(crashes|queue)/something.out
      e.g., .../SQL012/trial0/aijon/crashes/...

    Returns: (harness_name, trial_number) or (None, None) if not found.
    In single mode, harness_name is the target bug ID (e.g., SQL012).
    """
    filepath_str = str(filepath)

    # Try to find trial number in the path (e.g., "trial0", "trial1", etc.)
    trial_match = re.search(r"/trial(\d+)/", filepath_str)
    if trial_match:
        trial_num = int(trial_match.group(1))

        if single_mode:
            # Single mode: extract bug ID before trial folder
            # Pattern: /BUG_ID/trialN/ where BUG_ID is like SQL012, PNG007, etc.
            bug_id_match = re.search(r"/([A-Z]{3,4}\d{3})/trial\d+/", filepath_str)
            if bug_id_match:
                return bug_id_match.group(1), trial_num
        else:
            # Normal mode: extract harness name - look for fuzzing_* pattern in path
            harness_match = re.search(r"(fuzzing_[^/]+)", filepath_str)
            if harness_match:
                return harness_match.group(1), trial_num

    return None, None


def should_skip_file(filepath, fuzzer, single_mode=False):
    """Check if a file should be skipped based on fuzzer and failed runs.

    Args:
        filepath: Path to the .out file
        fuzzer: Either 'ijon' or 'aflpp'
        single_mode: Whether using single bug folder structure

    Returns: True if the file should be skipped, False otherwise.
    """
    filepath_str = str(filepath)

    # In single mode, filter by fuzzer folder (aijon or aflpp)
    if single_mode and fuzzer:
        # Map fuzzer arg to folder name
        fuzzer_folder = "aijon" if fuzzer == "ijon" else "aflpp"
        # Check if the file is in the correct fuzzer folder
        if f"/{fuzzer_folder}/" not in filepath_str:
            return True

    if fuzzer is None:
        return False

    harness, trial = extract_harness_and_trial(filepath, single_mode)
    if harness is None or trial is None:
        return False

    if fuzzer == "ijon":
        failed_runs = failed_ijon_runs
    elif fuzzer == "aflpp":
        failed_runs = failed_afl_runs
    else:
        return False

    # Check if this harness/trial combination should be skipped
    if harness in failed_runs and trial in failed_runs[harness]:
        return True

    return False


def check_vuln_in_file(filepath, target_vuln):
    """Check if a file reached the target vulnerability ID (triggered or just reached).
    Returns a dict with status information or None if not found.
    """
    try:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()
            # Look for lines like "exit_code X bug TIF003 TIF001 reached LUA012"
            # Vulnerability IDs between "bug" and "reached" are triggered
            # IDs after "reached" were only reached but not triggered
            for line in content.split("\n"):
                triggered = False
                reached_only = False

                # Check if it was triggered (between "bug" and "reached")
                match = re.search(r"\bbug\s+(.*?)\s+reached\s+", line)
                if match:
                    triggered_section = match.group(1)
                    vulns = re.findall(r"[A-Z]{3,4}\d{3}", triggered_section)
                    if target_vuln in vulns:
                        triggered = True

                # Check if it was reached (after "reached")
                match = re.search(r"\breached\s+(.*?)(?:\s*$)", line)
                if match:
                    reached_section = match.group(1)
                    vulns = re.findall(r"[A-Z]{3,4}\d{3}", reached_section)
                    if target_vuln in vulns:
                        reached_only = True

                if triggered or reached_only:
                    return {
                        "triggered": triggered,
                        "reached_only": reached_only and not triggered,
                    }
        return None
    except Exception:
        # Skip files that can't be read
        return None


def extract_all_bug_ids_from_file(filepath):
    """Extract all bug IDs from a file (both triggered and reached).
    Returns a dict with bug_id as key and count as value.
    """
    bug_counts = defaultdict(int)

    try:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()

            for line in content.split("\n"):
                # Extract triggered bugs (between "bug" and "reached")
                match = re.search(r"\bbug\s+(.*?)\s+reached\s+", line)
                if match:
                    triggered_section = match.group(1)
                    vulns = re.findall(r"[A-Z]{3,4}\d{3}", triggered_section)
                    for vuln in vulns:
                        bug_counts[vuln] += 1

                # Extract reached bugs (after "reached")
                match = re.search(r"\breached\s+(.*?)(?:\s*$)", line)
                if match:
                    reached_section = match.group(1)
                    vulns = re.findall(r"[A-Z]{3,4}\d{3}", reached_section)
                    for vuln in vulns:
                        bug_counts[vuln] += 1

    except Exception:
        pass

    return bug_counts


def process_file_wrapper(filepath):
    """Wrapper function for multiprocessing that extracts bug counts from a file."""
    return extract_all_bug_ids_from_file(filepath)


def process_file_with_metadata(args):
    """Process a file and return bug counts along with harness/trial metadata."""
    filepath, fuzzer, single_mode = args
    if should_skip_file(filepath, fuzzer, single_mode):
        return None
    harness, trial = extract_harness_and_trial(filepath, single_mode)
    bug_counts = extract_all_bug_ids_from_file(filepath)
    return {
        "harness": harness,
        "trial": trial,
        "bug_counts": bug_counts,
    }


def load_binary_mapping(mapping_file):
    """Load bug prefix to harness mapping from a CSV file.

    Expected format: PREFIX,harness1,harness2,...
    e.g.: PDF,fuzzing_pdf_fuzzer,fuzzing_pdfimages,fuzzing_pdftoppm

    Returns:
        Dict mapping bug prefix to list of harnesses
    """
    mapping = {}
    try:
        with open(mapping_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(",")
                if len(parts) >= 2:
                    prefix = parts[0]
                    harnesses = [h.strip() for h in parts[1:] if h.strip()]
                    mapping[prefix] = harnesses
    except Exception as e:
        print(f"Warning: Could not load mapping file {mapping_file}: {e}")
    return mapping


def build_bug_breakdown(file_results, all_harnesses, binary_mapping=None, single_mode=False):
    """Build the bug breakdown structure from file results.

    Args:
        file_results: List of dicts with harness, trial, bug_counts
        all_harnesses: Set of all harness names found
        binary_mapping: Dict mapping bug prefix to list of harnesses (optional, ignored in single mode)
        single_mode: Whether using single bug folder structure (default: False)

    Returns:
        Dict with bug breakdown in the format:
        {
            "BUG001": {
                "harnesses": {
                    "fuzzing_foo": {  # or target bug ID in single mode
                        "trials": [count0, count1, ...],
                        "count": num_trials,
                        "avg": average
                    },
                    ...
                },
                "total_harnesses": N,
                "final_avg": average_across_harnesses
            },
            ...
        }
    """
    # First, collect all bug counts by (bug_id, harness, trial)
    # bug_counts_by_trial[bug_id][harness][trial] = count
    bug_counts_by_trial = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))

    for result in file_results:
        if result is None:
            continue
        harness = result["harness"]
        trial = result["trial"]
        if harness is None or trial is None:
            continue
        for bug_id, count in result["bug_counts"].items():
            bug_counts_by_trial[bug_id][harness][trial] += count

    # Get max trial number per harness (some harnesses may have different trial counts)
    max_trial_per_harness = defaultdict(int)
    for result in file_results:
        if result is None:
            continue
        harness = result["harness"]
        trial = result["trial"]
        if harness and trial is not None:
            max_trial_per_harness[harness] = max(max_trial_per_harness[harness], trial)

    # Build the breakdown structure
    breakdown = {}

    # Get all unique bug IDs
    all_bug_ids = sorted(bug_counts_by_trial.keys())

    for bug_id in all_bug_ids:
        harness_data = {}

        # Get the bug prefix to determine which harnesses to include
        prefix_match = re.match(r"([A-Z]+)", bug_id)
        bug_prefix = prefix_match.group(1) if prefix_match else ""

        # Get harnesses relevant to this bug type from mapping or infer from data
        # In single mode, don't use mapping - harnesses are target bug IDs, not fuzzing_* names
        if not single_mode and binary_mapping and bug_prefix in binary_mapping:
            relevant_harnesses = binary_mapping[bug_prefix]
        else:
            # Use harnesses that have data for this specific bug
            relevant_harnesses = list(bug_counts_by_trial[bug_id].keys())

        for harness in sorted(relevant_harnesses):
            # Get the number of trials for this harness
            num_trials = max_trial_per_harness.get(harness, 0) + 1

            if num_trials > 0:
                # Build trials array for this harness
                trials = []
                for trial_num in range(num_trials):
                    count = bug_counts_by_trial[bug_id][harness].get(trial_num, 0)
                    trials.append(float(count))

                trial_count = len(trials)
                avg = sum(trials) / trial_count if trial_count > 0 else 0.0
                harness_data[harness] = {
                    "trials": trials,
                    "count": trial_count,
                    "avg": round(avg, 1) if avg != int(avg) else avg,
                }
            else:
                # Harness is in mapping but has no trial data at all
                harness_data[harness] = {
                    "trials": [],
                    "count": 0,
                    "avg": 0.0,
                }

        # Calculate final_avg (average of harness averages for harnesses with data)
        harness_avgs = [
            h["avg"] for h in harness_data.values() if h["count"] > 0 and h["avg"] > 0
        ]
        if harness_avgs:
            final_avg = sum(harness_avgs) / len(harness_avgs)
        else:
            # If no harness has non-zero avg, average all harnesses with data
            harness_avgs_all = [h["avg"] for h in harness_data.values() if h["count"] > 0]
            final_avg = sum(harness_avgs_all) / len(harness_avgs_all) if harness_avgs_all else 0.0

        breakdown[bug_id] = {
            "harnesses": harness_data,
            "total_harnesses": len(harness_data),
            "final_avg": final_avg,
        }

    return breakdown


def scan_folder_for_bugs(
    folder_path,
    output_json="bug_frequency.json",
    num_workers=None,
    fuzzer=None,
    breakdown_json=None,
    mapping_file=None,
    single_mode=False,
):
    """Scan all .out files in folder recursively and count bug frequencies using multiprocessing.

    Args:
        folder_path: Path to the folder to scan
        output_json: Output JSON file name (default: bug_frequency.json)
        num_workers: Number of worker processes (default: number of CPU cores)
        fuzzer: Fuzzer type ('ijon' or 'aflpp') to skip failed trials (default: None)
        breakdown_json: Output JSON file for bug breakdown by harness/trial (default: None)
        mapping_file: CSV file mapping bug prefixes to harnesses (default: None)
        single_mode: Use single bug folder structure (BUG_ID/trialN/fuzzer_type/) (default: False)
    """
    total_bug_counts = defaultdict(int)

    # Find all .out files recursively
    folder = Path(folder_path)
    out_files = list(folder.rglob("*.out"))

    print(f"Found {len(out_files)} .out files to process...")

    # Collect all harnesses (or bug IDs in single mode) from the folder structure
    all_harnesses = set()
    for f in out_files:
        harness, _ = extract_harness_and_trial(f, single_mode)
        if harness:
            all_harnesses.add(harness)
    label = "target bugs" if single_mode else "harnesses"
    print(f"Found {len(all_harnesses)} {label}: {sorted(all_harnesses)}")

    # Determine number of workers
    if num_workers is None:
        num_workers = cpu_count()

    print(f"Using {num_workers} worker processes...")

    # Process files in parallel with progress tracking
    files_processed = 0
    chunk_size = max(1, len(out_files) // (num_workers * 10))  # Adaptive chunk size

    # Prepare args for processing with metadata
    file_args = [(f, fuzzer, single_mode) for f in out_files]

    # Store all results for breakdown generation
    all_file_results = []

    with Pool(processes=num_workers) as pool:
        # Use imap_unordered for better performance and progress tracking
        for result in pool.imap_unordered(
            process_file_with_metadata, file_args, chunksize=chunk_size
        ):
            files_processed += 1

            if result is not None:
                all_file_results.append(result)

                # Add to total counts
                for bug_id, count in result["bug_counts"].items():
                    total_bug_counts[bug_id] += count

            # Print progress
            if files_processed % 1000 == 0:
                print(f"Processed {files_processed}/{len(out_files)} files...")

    # Convert to regular dict and sort by bug ID
    result = dict(sorted(total_bug_counts.items()))

    # Save frequency JSON
    with open(output_json, "w") as f:
        json.dump(result, f, indent=4)

    print("\nProcessing complete!")
    print(f"Total files processed: {files_processed}")
    print(f"Files included (after filtering): {len(all_file_results)}")
    print(f"Unique bug IDs found: {len(result)}")
    print(f"Results saved to: {output_json}")

    # Generate and save breakdown JSON if requested
    if breakdown_json:
        print(f"\nGenerating bug breakdown...")
        # Load binary mapping if provided
        binary_mapping = None
        if mapping_file:
            binary_mapping = load_binary_mapping(mapping_file)
            print(f"Loaded mapping for {len(binary_mapping)} bug prefixes from {mapping_file}")
        breakdown = build_bug_breakdown(all_file_results, all_harnesses, binary_mapping, single_mode)
        with open(breakdown_json, "w") as f:
            json.dump(breakdown, f, indent=4)
        print(f"Bug breakdown saved to: {breakdown_json}")

    # Print top 10 most frequent bugs
    if result:
        print("\nTop 10 most frequent bugs:")
        sorted_bugs = sorted(result.items(), key=lambda x: x[1], reverse=True)[:10]
        for bug_id, count in sorted_bugs:
            print(f"  {bug_id}: {count:,}")

    return result


if __name__ == "__main__":
    # Set up command line argument parser
    parser = argparse.ArgumentParser(
        description="Scan .out files recursively and count bug ID frequencies"
    )
    parser.add_argument(
        "folder_path",
        nargs="?",
        default=".",
        help="Path to the folder to scan (default: current directory)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="bug_frequency.json",
        help="Output JSON file path (default: bug_frequency.json)",
    )
    parser.add_argument(
        "-b",
        "--breakdown",
        default=None,
        help="Output JSON file path for bug breakdown by harness/trial (optional)",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=None,
        help=f"Number of worker processes (default: {cpu_count()} - number of CPU cores)",
    )
    parser.add_argument(
        "-f",
        "--fuzzer",
        choices=["ijon", "aflpp"],
        default=None,
        help="Fuzzer type to skip failed trials (ijon or aflpp). In single mode, also filters to only process files from the specified fuzzer folder (aijon or aflpp). If not specified, no filtering is applied.",
    )
    parser.add_argument(
        "-m",
        "--mapping",
        default="binary_mapping.csv",
        help="CSV file mapping bug prefixes to harnesses (e.g., binary_mapping.csv)",
    )
    parser.add_argument(
        "-s",
        "--single",
        action="store_true",
        help="Use single bug folder structure (BUG_ID/trialN/fuzzer_type/) instead of (fuzzing_harness/trialN/)",
    )

    args = parser.parse_args()

    # Validate folder path
    if not os.path.exists(args.folder_path):
        print(f"Error: Folder '{args.folder_path}' does not exist!")
        exit(1)

    if not os.path.isdir(args.folder_path):
        print(f"Error: '{args.folder_path}' is not a directory!")
        exit(1)

    # Run the scanner
    print(f"Scanning folder: {args.folder_path}")
    print(f"Output will be saved to: {args.output}")
    if args.breakdown:
        print(f"Bug breakdown will be saved to: {args.breakdown}")
    if args.mapping:
        print(f"Using bug-harness mapping from: {args.mapping}")
    if args.fuzzer:
        print(f"Fuzzer: {args.fuzzer} (skipping failed trials)")
    if args.single:
        print(f"Mode: single (BUG_ID/trialN/fuzzer_type/ structure)")
    print()
    results = scan_folder_for_bugs(
        args.folder_path,
        args.output,
        args.workers,
        args.fuzzer,
        args.breakdown,
        args.mapping,
        args.single,
    )
