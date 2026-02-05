#!/usr/bin/env python3
import argparse
import csv
import json
import sys
from pathlib import Path


def iter_reached_triggered_pairs(node):
    if isinstance(node, dict):
        reached = node.get("reached")
        triggered = node.get("triggered")
        if isinstance(reached, dict) and isinstance(triggered, dict):
            yield reached, triggered
        for value in node.values():
            yield from iter_reached_triggered_pairs(value)
    elif isinstance(node, list):
        for value in node:
            yield from iter_reached_triggered_pairs(value)


def count_trials(node):
    count = 0
    if isinstance(node, dict):
        reached = node.get("reached")
        triggered = node.get("triggered")
        if isinstance(reached, dict) or isinstance(triggered, dict):
            count += 1
        for value in node.values():
            count += count_trials(value)
    elif isinstance(node, list):
        for value in node:
            count += count_trials(value)
    return count


def process_config_dir(config_dir):
    stats = {}
    for json_file in sorted(config_dir.glob("*.json")):
        if json_file.stat().st_size == 0:
            print(f"warning: skipping empty file {json_file}", file=sys.stderr)
            continue
        try:
            data = json.loads(json_file.read_text())
        except json.JSONDecodeError as exc:
            print(f"warning: skipping invalid json {json_file}: {exc}", file=sys.stderr)
            continue
        trial_count = count_trials(data)
        if trial_count != 10:
            print(
                f"warning: {json_file} has {trial_count} trials (expected 10)",
                file=sys.stderr,
            )
        for reached, triggered in iter_reached_triggered_pairs(data):
            for vuln in reached:
                stats.setdefault(vuln, {"diffs": [], "reached": 0, "triggered": 0})
                stats[vuln]["reached"] += 1
            for vuln, triggered_time in triggered.items():
                stats.setdefault(vuln, {"diffs": [], "reached": 0, "triggered": 0})
                stats[vuln]["triggered"] += 1
                if vuln not in reached:
                    continue
                diff = triggered_time - reached[vuln]
                stats[vuln]["diffs"].append(diff)
    return stats


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Compute average (triggered - reached) times per vulnerability for configs."
        )
    )
    parser.add_argument(
        "configs",
        nargs="*",
        help="config directories (default: *_final dirs in cwd)",
    )
    parser.add_argument(
        "--show-counts",
        action="store_true",
        help="include sample counts per vulnerability",
    )
    parser.add_argument(
        "--csv",
        metavar="PATH",
        help="write table to a CSV file (includes avg and detection rate per config)",
    )
    parser.add_argument(
        "--min-reach",
        type=int,
        default=0,
        help="minimum reached count to keep a vulnerability in output",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    cwd = Path.cwd()
    if args.configs:
        config_dirs = [Path(p) for p in args.configs]
    else:
        config_dirs = sorted(p for p in cwd.iterdir() if p.is_dir() and p.name.endswith("_final"))

    if not config_dirs:
        print("no config directories found", file=sys.stderr)
        return 1

    config_diffs = {}
    for config_dir in config_dirs:
        stats = process_config_dir(config_dir)
        config_diffs[config_dir.name] = stats

    all_vulns = sorted({v for stats in config_diffs.values() for v in stats})
    if args.min_reach > 0:
        filtered = []
        for vuln in all_vulns:
            max_reach = 0
            for stats in config_diffs.values():
                if vuln in stats:
                    max_reach = max(max_reach, stats[vuln]["reached"])
            if max_reach >= args.min_reach:
                filtered.append(vuln)
        all_vulns = filtered
    if not all_vulns:
        print("no vulnerability data found", file=sys.stderr)
        return 1

    headers = ["vuln"] + [d.name for d in config_dirs]
    rows = []
    for vuln in all_vulns:
        row = [vuln]
        for config_dir in config_dirs:
            stats = config_diffs[config_dir.name]
            if vuln not in stats:
                row.append("-")
                continue
            values = stats[vuln]["diffs"]
            if not values:
                if args.show_counts:
                    reached_count = stats[vuln]["reached"]
                    triggered_count = stats[vuln]["triggered"]
                    row.append(f"- (r={reached_count}, t={triggered_count})")
                else:
                    row.append("-")
                continue
            avg = sum(values) / len(values)
            if args.show_counts:
                reached_count = stats[vuln]["reached"]
                triggered_count = stats[vuln]["triggered"]
                row.append(f"{avg:.2f} (r={reached_count}, t={triggered_count})")
            else:
                row.append(f"{avg:.2f}")
        rows.append(row)

    if args.csv:
        csv_headers = ["vuln"]
        for config_dir in config_dirs:
            name = config_dir.name
            csv_headers.extend([f"{name}_avg", f"{name}_detection_rate"])
        with open(args.csv, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(csv_headers)
            for vuln in all_vulns:
                row = [vuln]
                for config_dir in config_dirs:
                    stats = config_diffs[config_dir.name]
                    if vuln not in stats:
                        row.extend(["", ""])
                        continue
                    diffs = stats[vuln]["diffs"]
                    if diffs:
                        avg = sum(diffs) / len(diffs)
                        avg_value = f"{avg:.2f}"
                    else:
                        avg_value = ""
                    reached_count = stats[vuln]["reached"]
                    triggered_count = stats[vuln]["triggered"]
                    if reached_count:
                        detection_rate = (triggered_count / reached_count) * 100
                        detection_value = f"{detection_rate:.2f}"
                    else:
                        detection_value = ""
                    row.extend([avg_value, detection_value])
                writer.writerow(row)

    col_widths = [len(h) for h in headers]
    for row in rows:
        for idx, value in enumerate(row):
            col_widths[idx] = max(col_widths[idx], len(value))

    header_line = "  ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    print(header_line)
    print("  ".join("-" * col_widths[i] for i in range(len(headers))))
    for row in rows:
        print("  ".join(row[i].ljust(col_widths[i]) for i in range(len(headers))))

    detected_counts = {d.name: 0 for d in config_dirs}
    unique_detected = {d.name: [] for d in config_dirs}
    for vuln in all_vulns:
        detected_by = []
        for config_dir in config_dirs:
            stats = config_diffs[config_dir.name]
            if vuln in stats and stats[vuln]["triggered"] > 0:
                detected_by.append(config_dir.name)
        for name in detected_by:
            detected_counts[name] += 1
        if len(detected_by) == 1:
            unique_detected[detected_by[0]].append(vuln)

    print("\nSummary")
    for config_dir in config_dirs:
        name = config_dir.name
        print(f"{name}: detected {detected_counts[name]} vulnerabilities")
    print("\nUnique detections")
    for config_dir in config_dirs:
        name = config_dir.name
        uniques = unique_detected[name]
        if uniques:
            print(f"{name}: {', '.join(sorted(uniques))}")
        else:
            print(f"{name}: (none)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
