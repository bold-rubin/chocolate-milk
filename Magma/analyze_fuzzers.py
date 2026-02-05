#!/usr/bin/env python3
"""
Script to compare AFL++ and IJON fuzzing results from a CSV file.
Lists rows where one fuzzer significantly outperforms the other.
"""

import csv
import argparse
import sys


def parse_float(value):
    """Parse a string to float, returning None if empty or invalid."""
    if not value or value.strip() == '':
        return None
    try:
        return float(value)
    except ValueError:
        return None


def analyze_csv(filepath, threshold):
    """
    Analyze CSV file and find rows where fuzzers differ by threshold.

    Args:
        filepath: Path to the CSV file
        threshold: Minimum difference threshold
    """
    afl_better = []
    ijon_better = []

    try:
        with open(filepath, 'r') as f:
            reader = csv.DictReader(f, delimiter='\t')

            for row in reader:
                vuln_id = row.get('Vuln ID', '').strip()
                if not vuln_id:
                    continue

                afl_value = parse_float(row.get('AFL++', ''))
                ijon_value = parse_float(row.get('IJON', ''))

                # Skip rows where either value is missing
                if afl_value is None or ijon_value is None:
                    continue

                difference = afl_value - ijon_value

                if difference >= threshold:
                    afl_better.append({
                        'Vuln ID': vuln_id,
                        'AFL++': afl_value,
                        'IJON': ijon_value,
                        'Difference': difference
                    })
                elif difference <= -threshold:
                    ijon_better.append({
                        'Vuln ID': vuln_id,
                        'AFL++': afl_value,
                        'IJON': ijon_value,
                        'Difference': abs(difference)
                    })

    except FileNotFoundError:
        print(f"Error: File '{filepath}' not found.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)

    return afl_better, ijon_better


def print_results(title, results):
    """Print results in a formatted table."""
    if not results:
        print(f"\n{title}: None")
        return

    print(f"\n{title}:")
    print("-" * 70)
    print(f"{'Vuln ID':<12} {'AFL++':<12} {'IJON':<12} {'Difference':<12}")
    print("-" * 70)

    for row in results:
        print(f"{row['Vuln ID']:<12} {row['AFL++']:<12.2f} {row['IJON']:<12.2f} {row['Difference']:<12.2f}")

    print(f"\nTotal: {len(results)} rows")


def main():
    parser = argparse.ArgumentParser(
        description='Compare AFL++ and IJON fuzzing results from CSV file.'
    )
    parser.add_argument(
        'filepath',
        nargs='?',
        default='/tmp/blah.csv',
        help='Path to the CSV file (default: /tmp/blah.csv)'
    )
    parser.add_argument(
        '-t', '--threshold',
        type=float,
        default=600,
        help='Minimum difference threshold (default: 600)'
    )

    args = parser.parse_args()

    print(f"Analyzing: {args.filepath}")
    print(f"Threshold: {args.threshold}")

    afl_better, ijon_better = analyze_csv(args.filepath, args.threshold)

    print_results(
        f"Rows where AFL++ is better than IJON by at least {args.threshold}",
        afl_better
    )

    print_results(
        f"Rows where IJON is better than AFL++ by at least {args.threshold}",
        ijon_better
    )


if __name__ == '__main__':
    main()
