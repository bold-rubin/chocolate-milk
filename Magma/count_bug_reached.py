#!/usr/bin/env python3
"""
Count the number of times each bug was reached by each fuzzer across all trials.

Input format: {fuzzer: {project: {harness: {trial_num: {reached: {VULN_ID: TIME}, triggered: {VULN_ID: TIME}}}}}}
"""

import json
import argparse
from pathlib import Path
from collections import defaultdict


def load_fuzzing_data(filepath):
    """Load and parse a fuzzing results JSON file."""
    with open(filepath, 'r') as f:
        return json.load(f)


def count_bug_reaches(json_files):
    """
    Count how many times each bug was reached and triggered by each fuzzer.

    Returns a dictionary with structure:
    {
        fuzzer_name: {
            VULN_ID: {
                'reach_count': int,     # Total number of times the bug was reached
                'trial_count': int,     # Number of unique trials that reached the bug
                'trigger_count': int,   # Total number of times the bug was triggered
                'triggered': bool       # Whether the bug was ever triggered
            }
        }
    }
    """
    fuzzer_stats = defaultdict(lambda: defaultdict(lambda: {
        'reach_count': 0,
        'trial_count': 0,
        'trials': set(),
        'trigger_count': 0,
        'triggered': False
    }))

    for json_file in json_files:
        data = load_fuzzing_data(json_file)

        for fuzzer, projects in data.items():
            for project, harnesses in projects.items():
                for harness, trials in harnesses.items():
                    for trial_num, results in trials.items():
                        # Create a unique trial identifier
                        trial_id = f"{json_file}:{fuzzer}:{project}:{harness}:{trial_num}"

                        # Count reached vulnerabilities
                        for vuln_id, time in results.get('reached', {}).items():
                            fuzzer_stats[fuzzer][vuln_id]['reach_count'] += 1
                            fuzzer_stats[fuzzer][vuln_id]['trials'].add(trial_id)

                        # Count triggered vulnerabilities
                        for vuln_id, time in results.get('triggered', {}).items():
                            fuzzer_stats[fuzzer][vuln_id]['trigger_count'] += 1
                            fuzzer_stats[fuzzer][vuln_id]['triggered'] = True

    # Convert trial sets to counts and remove the set from output
    result = {}
    for fuzzer, vuln_stats in fuzzer_stats.items():
        result[fuzzer] = {}
        for vuln_id, stats in vuln_stats.items():
            result[fuzzer][vuln_id] = {
                'reach_count': stats['reach_count'],
                'trial_count': len(stats['trials']),
                'trigger_count': stats['trigger_count'],
                'triggered': stats['triggered']
            }

    return result


def print_reach_statistics(fuzzer_stats, base_ids=None):
    """Print reach count statistics in a comparison table for all fuzzers."""
    if not fuzzer_stats:
        print("No vulnerability data found.")
        return

    fuzzer_names = sorted(fuzzer_stats.keys())

    if len(fuzzer_names) == 0:
        print("No fuzzers found in data.")
        return

    # Get all unique vulnerability IDs across all fuzzers
    all_vuln_ids = set()
    for stats in fuzzer_stats.values():
        all_vuln_ids.update(stats.keys())

    # Add base_ids to ensure all are included in output
    if base_ids:
        all_vuln_ids.update(base_ids)

    # ANSI color codes
    GREEN = '\033[92m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

    # Print comparison table
    print("\n" + "="*120)
    print("BUG REACH COUNT - FUZZER COMPARISON TABLE")
    print("="*120)
    print(f"{GREEN}{BOLD}Green highlighting{RESET}: Highest reach count (per row)")
    print("="*120)

    # Build header
    header = f"{'Vulnerability ID':<20} "
    for fuzzer_name in fuzzer_names:
        header += f"| {fuzzer_name:<30} "
    print(header)

    # Build subheader with column names
    subheader = f"{'':<20} "
    for _ in fuzzer_names:
        subheader += f"| {'Reach Count':<13} {'Trials':<8} {'Triggered':<8} "
    print(subheader)
    print("-" * 120)

    # Print each vulnerability
    for vuln_id in sorted(all_vuln_ids):
        # Find the highest reach count for this vulnerability
        max_reach_count = 0
        for fuzzer_name in fuzzer_names:
            if vuln_id in fuzzer_stats[fuzzer_name]:
                reach_count = fuzzer_stats[fuzzer_name][vuln_id]['reach_count']
                if reach_count > max_reach_count:
                    max_reach_count = reach_count

        # Build row with highlighting
        row = f"{vuln_id:<20} "

        for fuzzer_name in fuzzer_names:
            if vuln_id in fuzzer_stats[fuzzer_name]:
                stats = fuzzer_stats[fuzzer_name][vuln_id]
                reach_count = stats['reach_count']
                trial_count = stats['trial_count']
                triggered = 'YES' if stats['triggered'] else 'NO'

                # Highlight if this is the maximum reach count
                if reach_count == max_reach_count and max_reach_count > 0:
                    reach_str = f"{GREEN}{reach_count}{RESET}"
                    # Pad to 13 visible characters (accounting for ANSI codes)
                    reach_str = reach_str + ' ' * (13 - len(str(reach_count)))
                else:
                    reach_str = f"{reach_count:<13}"

                row += f"| {reach_str} {trial_count:<8} {triggered:<8} "
            else:
                row += f"| {'-':<13} {'-':<8} {'-':<8} "

        print(row)

    # Print summary statistics for each fuzzer
    print("\n" + "="*120)
    print("SUMMARY STATISTICS")
    print("="*120)

    summary_rows = []
    for fuzzer_name in fuzzer_names:
        stats = fuzzer_stats[fuzzer_name]

        total_bugs_reached = len(stats)
        total_reach_count = sum(s['reach_count'] for s in stats.values())
        total_bugs_triggered = sum(1 for s in stats.values() if s['triggered'])

        # Calculate average reaches per bug
        avg_reaches = total_reach_count / total_bugs_reached if total_bugs_reached > 0 else 0

        summary_rows.append({
            'fuzzer': fuzzer_name,
            'total_bugs_reached': total_bugs_reached,
            'total_reach_count': total_reach_count,
            'total_bugs_triggered': total_bugs_triggered,
            'avg_reaches': avg_reaches
        })

    # Print summary comparison
    print(f"\n{'Metric':<40} " + " ".join([f"| {fn:<25}" for fn in fuzzer_names]))
    print("-" * 120)

    print(f"{'Total unique bugs reached':<40} " +
          " ".join([f"| {row['total_bugs_reached']:<25}" for row in summary_rows]))
    print(f"{'Total bugs triggered':<40} " +
          " ".join([f"| {row['total_bugs_triggered']:<25}" for row in summary_rows]))
    print(f"{'Total reach count (all bugs)':<40} " +
          " ".join([f"| {row['total_reach_count']:<25}" for row in summary_rows]))
    print(f"{'Average reaches per bug':<40} " +
          " ".join([f"| {row['avg_reaches']:.2f}{'':<19}" for row in summary_rows]))


def export_to_csv(fuzzer_stats, output_file, base_ids=None):
    """Export reach count statistics to a CSV file with fuzzers side by side."""
    import csv

    if not fuzzer_stats:
        print("No data to export.")
        return

    # Get sorted list of fuzzer names and all unique vulnerability IDs
    fuzzer_names = sorted(fuzzer_stats.keys())
    all_vuln_ids = set()
    for stats in fuzzer_stats.values():
        all_vuln_ids.update(stats.keys())

    # Add base_ids to ensure all are included in output
    if base_ids:
        all_vuln_ids.update(base_ids)

    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)

        # Build header row with fuzzer names as column groups
        header = ['Vulnerability ID']
        for fuzzer_name in fuzzer_names:
            header.extend([
                f'{fuzzer_name} - Reach Count',
                f'{fuzzer_name} - Trial Count',
                f'{fuzzer_name} - Triggered'
            ])

        writer.writerow(header)

        # Write data for each vulnerability
        for vuln_id in sorted(all_vuln_ids):
            row = [vuln_id]

            for fuzzer_name in fuzzer_names:
                if vuln_id in fuzzer_stats[fuzzer_name]:
                    stats = fuzzer_stats[fuzzer_name][vuln_id]
                    row.extend([
                        stats['reach_count'],
                        stats['trial_count'],
                        'YES' if stats['triggered'] else 'NO'
                    ])
                else:
                    # No data for this fuzzer-vulnerability combination
                    row.extend(['', '', ''])

            writer.writerow(row)

    print(f"\nExported results to {output_file}")


def load_base_ids(base_ids_arg):
    """
    Load base IDs from a file or parse from comma-separated string.

    Args:
        base_ids_arg: Either a file path or comma-separated string of IDs

    Returns:
        set of vulnerability IDs
    """
    if not base_ids_arg:
        return None

    # Check if it's a file
    if Path(base_ids_arg).exists():
        with open(base_ids_arg, 'r') as f:
            # Read line by line, strip whitespace, skip empty lines
            ids = [line.strip() for line in f if line.strip()]
            return set(ids)
    else:
        # Treat as comma-separated list
        ids = [id.strip() for id in base_ids_arg.split(',') if id.strip()]
        return set(ids)


def main():
    parser = argparse.ArgumentParser(
        description='Count the number of times each bug was reached by each fuzzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s results1.json results2.json results3.json
  %(prog)s results*.json --csv reach_counts.csv
  %(prog)s file1.json file2.json --csv reach_counts.csv
  %(prog)s results*.json --base-ids base_ids.txt
  %(prog)s results*.json --base-ids "AAH001,AAH002,AAH003"
        """
    )
    parser.add_argument('json_files', nargs='+', help='JSON files with fuzzing results')
    parser.add_argument('--csv', '-c', help='Export results to CSV file')
    parser.add_argument('--base-ids', '-b',
                       help='File containing vulnerability IDs (one per line) or comma-separated list of IDs. '
                            'All IDs will be included in output even if not found in results.')

    args = parser.parse_args()

    # Validate that all files exist
    for json_file in args.json_files:
        if not Path(json_file).exists():
            print(f"Error: File not found: {json_file}")
            return 1

    # Load base IDs if provided
    base_ids = load_base_ids(args.base_ids)
    if base_ids:
        print(f"Loaded {len(base_ids)} base vulnerability IDs")

    print(f"Counting bug reaches from {len(args.json_files)} file(s)...")

    # Count bug reaches
    stats = count_bug_reaches(args.json_files)

    # Print results
    print_reach_statistics(stats, base_ids=base_ids)

    # Export to CSV if requested
    if args.csv:
        export_to_csv(stats, args.csv, base_ids=base_ids)

    print("\nDone!")
    return 0


if __name__ == '__main__':
    exit(main())
