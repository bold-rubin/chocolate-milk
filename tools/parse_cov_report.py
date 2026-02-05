#!/usr/bin/env python3
import re
import sys
import json
import collections
from pathlib import Path


def parse_covreport(path: Path):
    file: str | None = None
    hits: dict[tuple[str, int], int] = {}
    hdr = re.compile(r"^(?!.*\|)\s*\S.*:\s*$")
    row = re.compile(r"^\s*([0-9]+)\|\s*([0-9.\-kMG]*)\|")
    branch = "|  Branch ("
    delimiter = "------------------"
    for thing in path.read_bytes().splitlines():
        try:
            line = thing.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if delimiter in line:
            continue
        elif branch in line:
            continue
        if hdr.match(line):
            file = line.rstrip()[:-1]
            continue
        m = row.match(line)
        if m and file:
            ln = int(m.group(1))
            cnt = m.group(2)
            if cnt and cnt != "-":
                multiplier = 1
                if cnt.endswith("k"):
                    multiplier = 1_000
                    cnt = cnt[:-1]
                elif cnt.endswith("M"):
                    multiplier = 1_000_000
                    cnt = cnt[:-1]
                elif cnt.endswith("G"):
                    multiplier = 1_000_000_000
                    cnt = cnt[:-1]
                hits[(file, ln)] = int(float(cnt) * multiplier)
    return hits


def get_function_ranges(poi_report: Path) -> dict[str, tuple[int, int]]:
    content = json.loads(poi_report.read_text())
    ranges: dict[str, tuple[int, int]] = {}
    for func_obj in content["functions"]:
        filename = Path(func_obj["function_filename"])
        start_line = func_obj["source_line_begin"]
        end_line = func_obj["source_line_end"]
        ranges[filename.name] = (start_line, end_line)

    return ranges


def compare_function_coverage(old_file: Path, new_file: Path, poi_report: Path):
    """
    Compare coverage for a specific function between two covreport files.
    Args:
        old_file (Path): Path to the old coverage report.
        new_file (Path): Path to the new coverage report.
        function_name (str): Name of the function to compare.
    """
    function_ranges = get_function_ranges(poi_report)
    old_coverage = parse_covreport(old_file)
    new_coverage = parse_covreport(new_file)

    def filter_by_func(
        coverage: dict[tuple[str, int], int],
    ) -> dict[tuple[str, int], int]:
        filtered_coverage: dict[tuple[str, int], int] = {}
        for file, ln in coverage:
            if file not in function_ranges:
                continue
            if not (function_ranges[file][0] <= ln <= function_ranges[file][1]):
                continue
            filtered_coverage[(file, ln)] = coverage[(file, ln)]
        return filtered_coverage

    old_func_cov = filter_by_func(old_coverage)
    new_func_cov = filter_by_func(new_coverage)

    keys = set(old_func_cov) | set(new_func_cov)
    new_lines = []
    lost_lines = []
    changed_lines = []
    for k in sorted(keys):
        a = old_func_cov.get(k, 0)
        b = new_func_cov.get(k, 0)
        if a == 0 and b > 0:
            new_lines.append(k)
        elif a > 0 and b == 0:
            lost_lines.append(k)
        elif a != b:
            changed_lines.append((k, a, b))

    print(f"Coverage comparison for poi file '{poi_report}':")
    if new_lines:
        print("  Newly covered lines:")
        for f, ln in new_lines:
            print(f"    {f}:{ln}")
    if lost_lines:
        print("  Lost coverage lines:")
        for f, ln in lost_lines:
            print(f"    {f}:{ln}")
    if changed_lines:
        print("  Lines with changed hit count:")
        for (f, ln), a, b in changed_lines:
            print(f"    {f}:{ln}  {a} -> {b}")
    if not (new_lines or lost_lines or changed_lines):
        print("  No differences found for this function.")


def main(old_file: Path, new_file: Path):
    old_coverage_data, new_coverage_data = (
        parse_covreport(old_file),
        parse_covreport(new_file),
    )

    keys = set(old_coverage_data) | set(new_coverage_data)
    perfile: dict[str, dict[str, int]] = collections.defaultdict(
        lambda: {"new": 0, "lost": 0, "chg": 0}
    )
    new_examples: list[tuple[str, int]] = []
    lost_examples: list[tuple[str, int]] = []

    for k in sorted(keys):
        a = old_coverage_data.get(k, 0)
        b = new_coverage_data.get(k, 0)
        f, ln = k
        if a == 0 and b > 0:
            perfile[f]["new"] += 1
            new_examples.append((f, ln))
        elif a > 0 and b == 0:
            perfile[f]["lost"] += 1
            lost_examples.append((f, ln))
        elif a < b:
            perfile[f]["chg"] += 1

    # print("FILE, newly_covered, lost_coverage, count_cold_coverage_datanged")
    # for f, v in sorted(perfile.items()):
    #     if any(v.values()):
    #         print(f"{f=}, {v['new']}, {v['lost']}, {v['chg']}")

    print(f"Newly discovered lines in {new_file} compared to {old_file}")
    for f, ln in new_examples:
        print(f"{f}:{ln}")
    # print("\nExamples (lost coverage):")
    # for f, ln in lost_examples: print(f"{f}:{ln}")
    # print("Lines with more hit count:")
    # for f, v in sorted(perfile.items()):
    #     if v["chg"]:
    #         print(f"{f}: {v['chg']} lines changed coverage")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: parse_cov_report.py <old_cov_report> <new_cov_report> [<poi_report>]")
        sys.exit(1)
    old_file, new_file = Path(sys.argv[1]), Path(sys.argv[2])
    if len(sys.argv) == 4:
        poi_report = Path(sys.argv[3])
        compare_function_coverage(old_file, new_file, poi_report)
    else:
        main(old_file, new_file)
