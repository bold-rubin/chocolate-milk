#!/usr/bin/env python3
"""
Aggregate fuzzing results from multiple JSON files and display average statistics.

Input format: {fuzzer: {project: {harness: {trial_num: {reached: {VULN_ID: TIME}, triggered: {VULN_ID: TIME}}}}}}
"""

import json
import argparse
import numpy as np
from pathlib import Path
from collections import defaultdict


def load_fuzzing_data(filepath):
    """Load and parse a fuzzing results JSON file."""
    with open(filepath, 'r') as f:
        return json.load(f)


def aggregate_statistics(json_files):
    """
    Aggregate statistics across multiple JSON files for each VULN ID, separated by fuzzer.

    Returns a dictionary with structure:
    {
        fuzzer_name: {
            VULN_ID: {
                'triggered_times': [list of time differences (triggered_time - reached_time)],
                'total_trials': int,
                'trials_triggered': int
            }
        }
    }
    """
    # Outer dict for fuzzers, inner dict for aggregated stats per fuzzer
    fuzzer_stats = defaultdict(lambda: defaultdict(lambda: {
        'triggered_times': [],
        'total_trials': 0,
        'trials_triggered': 0,
        'was_reached': False
    }))

    # Track which trials we've seen for each vuln per fuzzer
    fuzzer_vuln_trial_sets = defaultdict(lambda: defaultdict(set))

    for json_file in json_files:
        # print(f"Processing {json_file}...")
        data = load_fuzzing_data(json_file)

        for fuzzer, projects in data.items():
            for project, harnesses in projects.items():
                for harness, trials in harnesses.items():
                    for trial_num, results in trials.items():
                        # Create a unique trial identifier
                        trial_id = f"{json_file}:{fuzzer}:{project}:{harness}:{trial_num}"

                        # Get reached times for this trial
                        reached_times = results.get('reached', {})

                        # Process triggered vulnerabilities
                        triggered_vulns = set()
                        for vuln_id, triggered_time in results.get('triggered', {}).items():
                            # Calculate time difference between reaching and triggering
                            if vuln_id in reached_times:
                                time_diff = triggered_time - reached_times[vuln_id]
                                fuzzer_stats[fuzzer][vuln_id]['triggered_times'].append(time_diff)
                            else:
                                # If no reached time, use absolute time (fallback)
                                fuzzer_stats[fuzzer][vuln_id]['triggered_times'].append(triggered_time)
                            fuzzer_stats[fuzzer][vuln_id]['trials_triggered'] += 1
                            triggered_vulns.add(vuln_id)

                        # For total trials, count any vuln that was reached (whether triggered or not)
                        for vuln_id in reached_times.keys():
                            fuzzer_vuln_trial_sets[fuzzer][vuln_id].add(trial_id)
                            fuzzer_stats[fuzzer][vuln_id]['was_reached'] = True

                        # Also count trials where vuln was triggered but maybe not in reached
                        for vuln_id in triggered_vulns:
                            fuzzer_vuln_trial_sets[fuzzer][vuln_id].add(trial_id)

    # Set total_trials based on unique trial count for each fuzzer
    for fuzzer, vuln_trial_sets in fuzzer_vuln_trial_sets.items():
        for vuln_id, trial_set in vuln_trial_sets.items():
            fuzzer_stats[fuzzer][vuln_id]['total_trials'] = len(trial_set)

    # Convert to regular dict
    return {fuzzer: dict(stats) for fuzzer, stats in fuzzer_stats.items()}


def print_aggregated_statistics(fuzzer_stats, base_ids=None):
    """Print aggregated statistics in a single comparison table for all fuzzers."""
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
    print("\n" + "="*150)
    print("FUZZER COMPARISON TABLE")
    print("="*150)
    print(f"{GREEN}{BOLD}Green highlighting{RESET}: Highest success rate (per row) | Shortest average time from reach to trigger (per row)")
    print("="*150)

    # Build header
    header = f"{'Vulnerability ID':<20} "
    for fuzzer_name in fuzzer_names:
        header += f"| {fuzzer_name:<61} "
    print(header)

    # Build subheader with column names
    subheader = f"{'':<20} "
    for _ in fuzzer_names:
        subheader += f"| {'Reached':<8} {'Trials':<7} {'Triggered':<9} {'Rate':<8} {'Avg Δt (s)':<25} "
    print(subheader)
    print("-" * 150)

    # Print each vulnerability
    for vuln_id in sorted(all_vuln_ids):
        # Collect stats for all fuzzers for this vulnerability
        vuln_stats = {}
        for fuzzer_name in fuzzer_names:
            if vuln_id in fuzzer_stats[fuzzer_name]:
                vstats = fuzzer_stats[fuzzer_name][vuln_id]
                total = vstats['total_trials']
                triggered = vstats['trials_triggered']
                success_rate = (triggered / total * 100) if total > 0 else 0

                if vstats['triggered_times']:
                    avg_time = np.mean(vstats['triggered_times'])
                else:
                    avg_time = None

                vuln_stats[fuzzer_name] = {
                    'total': total,
                    'triggered': triggered,
                    'rate': success_rate,
                    'avg_time': avg_time,
                    'vstats': vstats
                }

        # Find best rate and fastest time
        best_rate = -1
        best_time = float('inf')

        for fstats in vuln_stats.values():
            if fstats['rate'] > best_rate:
                best_rate = fstats['rate']
            if fstats['avg_time'] is not None and fstats['avg_time'] < best_time:
                best_time = fstats['avg_time']

        # Build row with highlighting
        row = f"{vuln_id:<20} "

        for fuzzer_name in fuzzer_names:
            if fuzzer_name in vuln_stats:
                fstats = vuln_stats[fuzzer_name]
                vstats = fstats['vstats']

                total = fstats['total']
                triggered = fstats['triggered']
                success_rate = fstats['rate']

                # Determine if this cell should be highlighted
                highlight_rate = (success_rate == best_rate and best_rate > 0)
                highlight_time = (fstats['avg_time'] is not None and
                                fstats['avg_time'] == best_time and
                                best_time != float('inf'))

                if vstats['triggered_times']:
                    avg_time = fstats['avg_time']
                    std_time = np.std(vstats['triggered_times'])
                    time_str = f"{avg_time:.1f}±{std_time:.1f}"
                else:
                    time_str = "N/A"

                # Format with selective highlighting
                rate_str = f"{success_rate:>5.1f}%"
                if highlight_rate:
                    rate_str = f"{GREEN}{rate_str}{RESET}"

                # Store original length before adding ANSI codes
                time_str_len = len(time_str)
                if highlight_time:
                    time_str = f"{GREEN}{time_str}{RESET}"
                    # Pad to 25 visible characters (accounting for ANSI codes)
                    time_str = time_str + ' ' * (25 - time_str_len)
                else:
                    time_str = f"{time_str:<25}"

                # Add green checkmark if vulnerability was reached
                if vstats['was_reached']:
                    reached_str = f"{GREEN}✓{RESET}"
                    # Pad to 8 visible characters (accounting for ANSI codes)
                    reached_str = reached_str + ' ' * 7  # checkmark is 1 char, need 7 more
                else:
                    reached_str = ' ' * 8

                row += f"| {reached_str} {total:<7} {triggered:<9} {rate_str}   {time_str} "
            else:
                row += f"| {'-':<8} {'-':<7} {'-':<9} {'-':<8} {'-':<25} "

        print(row)

    # Print summary statistics for each fuzzer
    print("\n" + "="*150)
    print("SUMMARY STATISTICS")
    print("="*150)

    summary_rows = []
    for fuzzer_name in fuzzer_names:
        stats = fuzzer_stats[fuzzer_name]

        total_vulns = len(stats)
        total_trials = sum(s['total_trials'] for s in stats.values())
        total_triggered = sum(s['trials_triggered'] for s in stats.values())
        overall_rate = (total_triggered / total_trials * 100) if total_trials > 0 else 0

        all_times = []
        for vstats in stats.values():
            all_times.extend(vstats['triggered_times'])

        if all_times:
            avg_time = np.mean(all_times)
            median_time = np.median(all_times)
            min_time = min(all_times)
            max_time = max(all_times)
        else:
            avg_time = median_time = min_time = max_time = None

        summary_rows.append({
            'fuzzer': fuzzer_name,
            'total_vulns': total_vulns,
            'total_trials': total_trials,
            'total_triggered': total_triggered,
            'overall_rate': overall_rate,
            'avg_time': avg_time,
            'median_time': median_time,
            'min_time': min_time,
            'max_time': max_time
        })

    # Print summary comparison
    print(f"\n{'Metric':<40} " + " ".join([f"| {fn:<25}" for fn in fuzzer_names]))
    print("-" * 150)

    print(f"{'Total unique vulnerabilities':<40} " +
          " ".join([f"| {row['total_vulns']:<25}" for row in summary_rows]))
    print(f"{'Total trials':<40} " +
          " ".join([f"| {row['total_trials']:<25}" for row in summary_rows]))
    print(f"{'Total successful triggers':<40} " +
          " ".join([f"| {row['total_triggered']:<25}" for row in summary_rows]))
    print(f"{'Overall success rate (%)':<40} " +
          " ".join([f"| {row['overall_rate']:.2f}%{'':<19}" for row in summary_rows]))

    print(f"\n{'Average Δt (reach→trigger) (s)':<40} " +
          " ".join([f"| {row['avg_time']:.2f}{'':<17}" if row['avg_time'] else f"| N/A{'':<17}" for row in summary_rows]))
    print(f"{'Median Δt (reach→trigger) (s)':<40} " +
          " ".join([f"| {row['median_time']:.2f}{'':<18}" if row['median_time'] else f"| N/A{'':<18}" for row in summary_rows]))
    print(f"{'Min Δt (reach→trigger) (s)':<40} " +
          " ".join([f"| {row['min_time']:.2f}{'':<20}" if row['min_time'] else f"| N/A{'':<20}" for row in summary_rows]))
    print(f"{'Max Δt (reach→trigger) (s)':<40} " +
          " ".join([f"| {row['max_time']:.2f}{'':<17}" if row['max_time'] else f"| N/A{'':<17}" for row in summary_rows]))


def export_to_csv(fuzzer_stats, output_file, base_ids=None):
    """Export aggregated statistics to a CSV file with fuzzers side by side."""
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
                f'{fuzzer_name} - Reached',
                f'{fuzzer_name} - Trials',
                f'{fuzzer_name} - Triggered',
                f'{fuzzer_name} - Success Rate (%)',
                f'{fuzzer_name} - Avg Δt (s)',
                f'{fuzzer_name} - Std Dev (s)',
                f'{fuzzer_name} - Min Δt (s)',
                f'{fuzzer_name} - Max Δt (s)'
            ])

        writer.writerow(header)

        # Write data for each vulnerability
        for vuln_id in sorted(all_vuln_ids):
            row = [vuln_id]

            for fuzzer_name in fuzzer_names:
                if vuln_id in fuzzer_stats[fuzzer_name]:
                    vstats = fuzzer_stats[fuzzer_name][vuln_id]
                    total = vstats['total_trials']
                    triggered = vstats['trials_triggered']
                    success_rate = (triggered / total * 100) if total > 0 else 0
                    reached = 'Yes' if vstats['was_reached'] else 'No'

                    if vstats['triggered_times']:
                        avg_time = np.mean(vstats['triggered_times'])
                        std_time = np.std(vstats['triggered_times'])
                        min_time = min(vstats['triggered_times'])
                        max_time = max(vstats['triggered_times'])

                        row.extend([
                            reached,
                            total,
                            triggered,
                            f"{success_rate:.2f}",
                            f"{avg_time:.2f}",
                            f"{std_time:.2f}",
                            f"{min_time:.2f}",
                            f"{max_time:.2f}"
                        ])
                    else:
                        row.extend([
                            reached,
                            total,
                            triggered,
                            f"{success_rate:.2f}",
                            '',
                            '',
                            '',
                            ''
                        ])
                else:
                    # No data for this fuzzer-vulnerability combination
                    row.extend(['', '', '', '', '', '', '', ''])

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
        description='Aggregate fuzzing results from multiple JSON files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s results1.json results2.json results3.json
  %(prog)s results*.json --csv output.csv
  %(prog)s file1.json file2.json --csv aggregated_results.csv
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

    print(f"Aggregating data from {len(args.json_files)} file(s)...")

    # Aggregate statistics
    stats = aggregate_statistics(args.json_files)

    # Print results
    print_aggregated_statistics(stats, base_ids=base_ids)

    # Export to CSV if requested
    if args.csv:
        export_to_csv(stats, args.csv, base_ids=base_ids)

    print("\nDone!")
    return 0


if __name__ == '__main__':
    exit(main())
