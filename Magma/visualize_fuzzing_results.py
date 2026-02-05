#!/usr/bin/env python3
"""
Visualize fuzzing results from JSON files with format:
{fuzzer: {project: {harness: {trial_num: {reached: {VULN_ID: TIME}, triggered: {VULN_ID: TIME}}}}}}
"""

import json
import argparse
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path
from collections import defaultdict


def load_fuzzing_data(filepath):
    """Load and parse the fuzzing results JSON file."""
    with open(filepath, 'r') as f:
        return json.load(f)


def extract_statistics(data):
    """
    Extract statistics from fuzzing data.
    Returns a structured dictionary with fuzzer comparisons.
    Note: triggered_times now contains time differences (trigger_time - reach_time).
    """
    stats = defaultdict(lambda: defaultdict(lambda: {
        'reached_times': [],
        'triggered_times': [],  # Now stores time differences between reach and trigger
        'trials_reached': 0,
        'trials_triggered': 0,
        'total_trials': 0
    }))

    for fuzzer, projects in data.items():
        for project, harnesses in projects.items():
            for harness, trials in harnesses.items():
                for trial_num, results in trials.items():
                    # Process reached vulnerabilities
                    for vuln_id, time in results.get('reached', {}).items():
                        stats[fuzzer][vuln_id]['reached_times'].append(time)
                        stats[fuzzer][vuln_id]['trials_reached'] += 1

                    # Process triggered vulnerabilities
                    # Calculate time difference between reaching and triggering
                    reached = results.get('reached', {})
                    for vuln_id, trigger_time in results.get('triggered', {}).items():
                        if vuln_id in reached:
                            time_diff = trigger_time - reached[vuln_id]
                            stats[fuzzer][vuln_id]['triggered_times'].append(time_diff)
                        else:
                            # If not reached but triggered, use absolute time (shouldn't happen normally)
                            stats[fuzzer][vuln_id]['triggered_times'].append(trigger_time)
                        stats[fuzzer][vuln_id]['trials_triggered'] += 1

                    # Count total trials per fuzzer
                    for vuln_id in results.get('reached', {}).keys():
                        stats[fuzzer][vuln_id]['total_trials'] = len(trials)

    return stats


def plot_trigger_time_comparison(stats, output_path=None):
    """
    Create box plots comparing trigger times across fuzzers for each vulnerability.
    """
    # Collect all vulnerabilities
    all_vulns = set()
    for fuzzer_stats in stats.values():
        all_vulns.update(fuzzer_stats.keys())
    all_vulns = sorted(all_vulns)

    if not all_vulns:
        print("No vulnerability data to plot")
        return

    fig, axes = plt.subplots(len(all_vulns), 1, figsize=(12, 4 * len(all_vulns)))
    if len(all_vulns) == 1:
        axes = [axes]

    for idx, vuln_id in enumerate(all_vulns):
        ax = axes[idx]
        data_to_plot = []
        labels = []

        for fuzzer, fuzzer_stats in sorted(stats.items()):
            if vuln_id in fuzzer_stats and fuzzer_stats[vuln_id]['triggered_times']:
                data_to_plot.append(fuzzer_stats[vuln_id]['triggered_times'])
                labels.append(fuzzer.split('_')[-1])  # Use last part of fuzzer name

        if data_to_plot:
            bp = ax.boxplot(data_to_plot, tick_labels=labels, patch_artist=True)
            for patch in bp['boxes']:
                patch.set_facecolor('lightblue')
            ax.set_ylabel('Time Difference (seconds)')
            ax.set_title(f'{vuln_id} - Time from Reach to Trigger (lower is better)')
            ax.grid(True, alpha=0.3)
        else:
            ax.text(0.5, 0.5, f'{vuln_id}\nNo triggers recorded',
                   ha='center', va='center', transform=ax.transAxes)
            ax.set_xticks([])
            ax.set_yticks([])

    plt.tight_layout()
    if output_path:
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        print(f"Saved trigger time comparison to {output_path}")
    else:
        plt.show()
    plt.close()


def plot_success_rate(stats, output_path=None):
    """
    Create bar chart showing trigger success rate for each vulnerability across fuzzers.
    """
    # Collect all vulnerabilities
    all_vulns = set()
    for fuzzer_stats in stats.values():
        all_vulns.update(fuzzer_stats.keys())
    all_vulns = sorted(all_vulns)

    if not all_vulns:
        print("No vulnerability data to plot")
        return

    fig, ax = plt.subplots(figsize=(12, 6))

    x = np.arange(len(all_vulns))
    width = 0.8 / len(stats)  # Width of bars

    for idx, (fuzzer, fuzzer_stats) in enumerate(sorted(stats.items())):
        success_rates = []
        for vuln_id in all_vulns:
            if vuln_id in fuzzer_stats:
                total = fuzzer_stats[vuln_id]['total_trials']
                triggered = fuzzer_stats[vuln_id]['trials_triggered']
                rate = (triggered / total * 100) if total > 0 else 0
                success_rates.append(rate)
            else:
                success_rates.append(0)

        offset = (idx - len(stats)/2 + 0.5) * width
        ax.bar(x + offset, success_rates, width,
               label=fuzzer.split('_')[-1], alpha=0.8)

    ax.set_xlabel('Vulnerability ID')
    ax.set_ylabel('Trigger Success Rate (%)')
    ax.set_title('Vulnerability Trigger Success Rate by Fuzzer')
    ax.set_xticks(x)
    ax.set_xticklabels(all_vulns)
    ax.legend()
    ax.grid(True, alpha=0.3, axis='y')

    plt.tight_layout()
    if output_path:
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        print(f"Saved success rate plot to {output_path}")
    else:
        plt.show()
    plt.close()


def plot_average_trigger_times(stats, output_path=None):
    """
    Create bar chart comparing average trigger times across fuzzers.
    """
    # Collect all vulnerabilities
    all_vulns = set()
    for fuzzer_stats in stats.values():
        all_vulns.update(fuzzer_stats.keys())
    all_vulns = sorted(all_vulns)

    if not all_vulns:
        print("No vulnerability data to plot")
        return

    fig, ax = plt.subplots(figsize=(12, 6))

    x = np.arange(len(all_vulns))
    width = 0.8 / len(stats)

    for idx, (fuzzer, fuzzer_stats) in enumerate(sorted(stats.items())):
        avg_times = []
        for vuln_id in all_vulns:
            if vuln_id in fuzzer_stats and fuzzer_stats[vuln_id]['triggered_times']:
                avg_time = np.mean(fuzzer_stats[vuln_id]['triggered_times'])
                avg_times.append(avg_time)
            else:
                avg_times.append(0)

        offset = (idx - len(stats)/2 + 0.5) * width
        ax.bar(x + offset, avg_times, width,
               label=fuzzer.split('_')[-1], alpha=0.8)

    ax.set_xlabel('Vulnerability ID')
    ax.set_ylabel('Average Time Difference (seconds)')
    ax.set_title('Average Time from Reach to Trigger (lower is better)')
    ax.set_xticks(x)
    ax.set_xticklabels(all_vulns)
    ax.legend()
    ax.grid(True, alpha=0.3, axis='y')

    plt.tight_layout()
    if output_path:
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        print(f"Saved average trigger times plot to {output_path}")
    else:
        plt.show()
    plt.close()


def print_summary_statistics(stats):
    """Print summary statistics to console."""
    print("\n" + "="*80)
    print("FUZZING RESULTS SUMMARY")
    print("="*80)

    for fuzzer, fuzzer_stats in sorted(stats.items()):
        print(f"\n{fuzzer.upper()}")
        print("-" * 80)
        print(f"{'Vulnerability':<15} {'Reached':<10} {'Triggered':<12} {'Success %':<12} {'Reach→Trigger (s)':<15}")
        print("-" * 80)

        for vuln_id in sorted(fuzzer_stats.keys()):
            vstats = fuzzer_stats[vuln_id]
            reached = vstats['trials_reached']
            triggered = vstats['trials_triggered']
            total = vstats['total_trials']
            success_rate = (triggered / total * 100) if total > 0 else 0

            if vstats['triggered_times']:
                avg_time = np.mean(vstats['triggered_times'])
                min_time = min(vstats['triggered_times'])
                max_time = max(vstats['triggered_times'])
                time_str = f"{avg_time:.1f} ({min_time}-{max_time})"
            else:
                time_str = "N/A"

            print(f"{vuln_id:<15} {reached}/{total:<9} {triggered}/{total:<11} {success_rate:>6.1f}%      {time_str:<15}")


def main():
    parser = argparse.ArgumentParser(
        description='Visualize fuzzing results from JSON file',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s input.json
  %(prog)s input.json --output-dir ./plots
  %(prog)s input.json --plot-type all
  %(prog)s input.json --plot-type boxplot --no-summary
        """
    )
    parser.add_argument('input_file', help='Path to JSON file with fuzzing results')
    parser.add_argument('--output-dir', '-o', help='Directory to save plots (if not specified, plots are displayed)')
    parser.add_argument('--plot-type', '-p',
                       choices=['boxplot', 'success', 'average', 'all'],
                       default='all',
                       help='Type of plot to generate (default: all)')
    parser.add_argument('--no-summary', action='store_true',
                       help='Skip printing summary statistics')

    args = parser.parse_args()

    # Load data
    print(f"Loading data from {args.input_file}...")
    data = load_fuzzing_data(args.input_file)

    # Extract statistics
    stats = extract_statistics(data)

    # Print summary
    if not args.no_summary:
        print_summary_statistics(stats)

    # Prepare output paths
    output_dir = Path(args.output_dir) if args.output_dir else None
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

    # Generate plots
    print("\nGenerating plots...")

    if args.plot_type in ['boxplot', 'all']:
        output_path = output_dir / 'trigger_time_boxplot.png' if output_dir else None
        plot_trigger_time_comparison(stats, output_path)

    if args.plot_type in ['success', 'all']:
        output_path = output_dir / 'success_rate.png' if output_dir else None
        plot_success_rate(stats, output_path)

    if args.plot_type in ['average', 'all']:
        output_path = output_dir / 'average_trigger_times.png' if output_dir else None
        plot_average_trigger_times(stats, output_path)

    print("\nDone!")


if __name__ == '__main__':
    main()
