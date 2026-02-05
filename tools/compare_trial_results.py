#! /usr/bin/env python3
import re
import sys
import csv
import json
import tarfile
from pathlib import Path
from collections import defaultdict
from tempfile import TemporaryDirectory
from argparse import ArgumentParser, Namespace
from scipy.stats import mannwhitneyu, wilcoxon


AIJON_DIR = Path(__file__).resolve().parent.parent
POI_DIR = (
    AIJON_DIR / "experiments/oss_fuzz_coverage_targets/coverage_targets_json_files"
)

FILTER_ENABLED: bool = False


def parse_args() -> Namespace:
    parser = ArgumentParser(
        description="Compare trial results from two different directories."
    )
    parser.add_argument(
        "ossfuzz",
        type=Path,
        help="Path to the directory containing OSS-Fuzz results.",
    )
    parser.add_argument(
        "aflplusplus",
        type=Path,
        help="Path to the directory containing AFL++ results.",
    )
    # Trial can be one integer or multiple integers separated by spaces
    parser.add_argument("--trial", type=int, help="Trial number to compare.", nargs="+")
    parser.add_argument(
        "--project",
        type=str,
        help="Project name to compare.",
        nargs="+",
        required=False,
    )
    parser.add_argument(
        "--all", action="store_true", help="Compare all trials from 1 to 10."
    )
    parser.add_argument(
        "--csv", action="store_true", help="Output results in CSV format."
    )
    parser.add_argument(
        "--summarize", action="store_true", help="Summarize results across trials."
    )
    parser.add_argument(
        "--poi", action="store_true", help="Use POI coverage in the results."
    )
    parser.add_argument(
        "--absolute",
        action="store_true",
        help="Calculate absolute coverage (wrt the POI) instead of differential (vs AFL++).",
    )
    parser.add_argument(
        "--annotation-filter",
        action="store_true",
        help="Only include results from fuzzers that hit annotations.",
    )
    return parser.parse_args()


def parse_covreport(path: Path) -> dict[str, dict[int, int]]:
    """Parse a covreport file and return coverage hits per file and line.

    Input format examples per file section:
      <filename>:
         line_num|    hit_count|
         line_num|    |

    Notes:
      - hit_count may have multipliers: k, M, G.
      - Lines with missing or '-' hit_count are ignored.

    Returns:
      dict mapping filepath -> { line_num: hit_count } for hit_count > 0
    """
    prev_file: str | None = None
    cur_file: str | None = None
    hits: dict[str, dict[int, int]] = {}
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
            if ":" in file:
                file = file.split(":", 1)[0]
            try:
                assert (
                    file.endswith(".c")
                    or file.endswith(".cpp")
                    or file.endswith(".cc")
                    or file.endswith(".h")
                ), f"Unexpected file extension in {file}"
                if prev_file is None or prev_file != file:
                    prev_file = file
            except AssertionError:
                # Fallback to previous file header if the parser stutters
                if prev_file is not None:
                    file = prev_file
            cur_file = file
            if cur_file not in hits:
                hits[cur_file] = {}
            continue
        m = row.match(line)
        if m and cur_file:
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
                value = int(float(cnt) * multiplier)
                if value > 0:
                    hits[cur_file][ln] = value
    return hits


def get_function_ranges(poi_report: Path) -> dict[str, list[tuple[int, int]]]:
    content = json.loads(poi_report.read_text())
    ranges: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for func_obj in content["functions"]:
        filename = Path(func_obj["function_filename"])
        start_line = func_obj["source_line_begin"]
        end_line = func_obj["source_line_end"]
        if True:
            # if func_obj.get("runtime_coverage_percent", 0.0) == 0.0:
            # print(f"POI function {func_obj['function_name']} has runtime coverage.")
            ranges[filename.name].append((start_line, end_line))

    return ranges


def filter_by_func(
    coverage: dict[str, dict[int, int]],
    function_ranges: dict[str, list[tuple[int, int]]],
) -> dict[str, dict[int, int]]:
    filtered_coverage: dict[str, dict[int, int]] = defaultdict(dict)
    for filepath, line_hits in coverage.items():
        # Match by exact filepath or basename present in POI ranges
        basename = Path(filepath).name
        ranges = function_ranges.get(filepath) or function_ranges.get(basename)
        if not ranges:
            continue
        for ln, count in line_hits.items():
            for start, end in ranges:
                if start <= ln <= end:
                    filtered_coverage[filepath][ln] = count
                    break
    return filtered_coverage


def has_annotations(analysis_dir: Path, harness_name: str | None = None) -> bool:
    if not FILTER_ENABLED:
        return True
    if not analysis_dir.is_dir():
        return False
    stdout_dir = analysis_dir / "patched_stdout"
    if not stdout_dir.is_dir():
        return False
    if harness_name is not None:
        harness_stdout_dir = stdout_dir / f"{harness_name}_afl_address_out"
        if not harness_stdout_dir.is_dir():
            return False
        for output_file in harness_stdout_dir.iterdir():
            if b"PATCHID" in output_file.read_bytes():
                return True
    else:
        for harness_stdout_dir in stdout_dir.iterdir():
            if not harness_stdout_dir.is_dir():
                continue
            for output_file in harness_stdout_dir.iterdir():
                if b"PATCHID" in output_file.read_bytes():
                    return True
    return False


def calculate_crashes(crash_analysis_dir: Path) -> int:
    if not crash_analysis_dir.is_dir():
        return 0
    num_crashes: int = 0
    for harness_output_file in crash_analysis_dir.glob("crash_analysis_*.tar.gz"):
        with TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            with tarfile.open(harness_output_file, "r:gz") as tar:
                tar.extractall(path=tmpdir_path)
            num_crashes += len(list(tmpdir_path.glob("id:*")))
    return num_crashes


def calculate_coverage(
    coverage_analysis_dir: Path, annotation_analysis_dir: Path
) -> int:
    """Calculate the coverage differences between AIJON and AFLplusplus

    Args:
        coverage_analysis_dir (Path): Path to the coverage analysis directory.

    Returns:
        int : The coverage difference in number of lines if AIJON has higher coverage, 0 otherwise.
    """
    if not coverage_analysis_dir.is_dir():
        return 0

    coverage_analysis_file = coverage_analysis_dir / "coverage_analysis.tar.gz"
    if not coverage_analysis_file.is_file():
        return 0

    total_new_lines: int = 0

    with TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        with tarfile.open(coverage_analysis_file, "r:gz") as tar:
            tar.extractall(path=tmpdir_path)
        for comparative_coverage_file in tmpdir_path.glob("*.comparative_coverage"):
            harness_name = comparative_coverage_file.name.replace(
                ".comparative_coverage", ""
            )
            if not has_annotations(annotation_analysis_dir, harness_name):
                continue
            num_lines = len(comparative_coverage_file.read_text().splitlines()) - 1

            if num_lines > 10:
                total_new_lines += num_lines

    return total_new_lines


def calculate_poi_coverage(
    coverage_analysis_dir: Path,
    annotation_analysis_dir: Path,
    poi_file: Path,
    absolute: bool = False,
) -> int:
    """Calculate the POI coverage differences between AIJON and AFLplusplus

    Args:
        coverage_analysis_dir (Path): Path to the coverage analysis directory.
        poi_file (Path): Path to the POI report file.

    Returns:
        int : The POI coverage difference in number of lines if AIJON has higher coverage, 0 otherwise.
    """
    if not coverage_analysis_dir.is_dir():
        return 0

    coverage_analysis_file = coverage_analysis_dir / "coverage_analysis.tar.gz"
    if not coverage_analysis_file.is_file():
        return 0

    if poi_file.is_file() is False:
        print(f"POI file {poi_file} does not exist.")
        return 0

    poi_ranges = get_function_ranges(poi_file)

    aijon_new_lines: int = 0
    aflplusplus_new_lines: int = 0

    with TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        with tarfile.open(coverage_analysis_file, "r:gz") as tar:
            tar.extractall(path=tmpdir_path)
        for aijon_coverage_file in tmpdir_path.glob("*.aijon_coverage_txt"):
            harness_name = aijon_coverage_file.name.replace(".aijon_coverage_txt", "")
            if not has_annotations(annotation_analysis_dir, harness_name):
                continue
            aijon_coverage = filter_by_func(
                parse_covreport(aijon_coverage_file), poi_ranges
            )
            aijon_new_lines += sum(len(lines) for lines in aijon_coverage.values())
        for aflplusplus_coverage_file in tmpdir_path.glob("*.afl_coverage_txt"):
            harness_name = aflplusplus_coverage_file.name.replace(
                ".afl_coverage_txt", ""
            )
            if not has_annotations(annotation_analysis_dir, harness_name):
                continue
            aflplusplus_coverage = filter_by_func(
                parse_covreport(aflplusplus_coverage_file), poi_ranges
            )
            aflplusplus_new_lines += sum(
                len(lines) for lines in aflplusplus_coverage.values()
            )

    if absolute:
        return aijon_new_lines

    if aijon_new_lines <= aflplusplus_new_lines:
        return 0
    else:
        return aijon_new_lines - aflplusplus_new_lines


def compare_one_trial(
    ossfuzz_path: Path, aflplusplus_path: Path, trial: int, absolute: bool = False
) -> dict[str, int]:
    ossfuzz_trial_path = ossfuzz_path / f"trial_{trial}"
    aflplusplus_trial_path = aflplusplus_path / f"trial_{trial}"

    ossfuzz_crash_analysis_dir = ossfuzz_trial_path / "crash_analysis"
    aflplusplus_crash_analysis_dir = aflplusplus_trial_path / "crash_analysis"

    ossfuzz_num_crashes = calculate_crashes(ossfuzz_crash_analysis_dir)
    aflplusplus_num_crashes = calculate_crashes(aflplusplus_crash_analysis_dir)

    ossfuzz_coverage_analysis_dir = ossfuzz_trial_path / "coverage_analysis"
    annotation_analysis_dir = ossfuzz_trial_path / "analysis"
    # aflplusplus_coverage_analysis_dir = aflplusplus_trial_path / "coverage_analysis"

    # Coverage results are derived from AIJON's (ossfuzz) comparative coverage artifacts
    coverage_results = calculate_coverage(
        ossfuzz_coverage_analysis_dir, annotation_analysis_dir
    )

    poi_file = POI_DIR / f"{ossfuzz_path.name}.json"
    poi_coverage = calculate_poi_coverage(
        ossfuzz_coverage_analysis_dir, annotation_analysis_dir, poi_file, absolute
    )

    if not has_annotations(annotation_analysis_dir):
        print(
            f"Skipping trial {trial} for project {ossfuzz_path.name} due to missing annotations."
        )
        coverage_results = -1
        poi_coverage = -1

    return {
        "aijon_crashes": ossfuzz_num_crashes,
        "aflpp_crashes": aflplusplus_num_crashes,
        "#new_lines": coverage_results,
        "poi_coverage": poi_coverage,
    }


def do_compare(
    ossfuzz_path: Path,
    aflplusplus_path: Path,
    trials: list[int],
    absolute: bool = False,
) -> dict[str, dict[int, dict[str, int]]]:
    results: dict[str, dict[int, dict[str, int]]] = defaultdict(dict)
    for trial in trials:
        for project in ossfuzz_path.iterdir():
            if not project.is_dir():
                continue
            project_ossfuzz_path = ossfuzz_path / project.name
            project_aflplusplus_path = aflplusplus_path / project.name
            if not project_aflplusplus_path.is_dir():
                continue
            trial_result = compare_one_trial(
                project_ossfuzz_path, project_aflplusplus_path, trial, absolute
            )
            results[project.name][trial] = trial_result
    return results


def pp_table_results(
    results: dict[str, dict[int, dict[str, int]]], use_poi: bool
) -> None:
    """Pretty-print results in a table.

    Shape of results:
      {
        "project_name": {
            trial_number: {
                "aflpp_crashes": int,
                "aijon_crashes": int,
                "#new_lines": int,
                "poi_coverage": int,
            },
            ...
        },
        ...
      }

    Output:
      Project | Trial 1 (aflpp_crashes, aijon_crashes, #new_lines) | Trial 2 ...
    """
    if not results:
        print("No results to display.")
        return

    # Determine set of trials across all projects and sort them
    trial_set: set[int] = set()
    for proj_map in results.values():
        trial_set.update(k for k in proj_map.keys())
    trials = sorted(trial_set)
    if not trials:
        print("No trials found in results.")
        return

    # Column configuration
    project_col_w = 17
    metric_names = [
        "aflpp_crashes",
        "aijon_crashes",
        "#new_lines" if not use_poi else "poi_coverage",
    ]
    metric_col_w = max(10, max(len(n) for n in metric_names)) + 2  # padding
    # Visible width of one trial block when metrics are joined with ' | '
    trial_block_w = len(" | ".join(["".ljust(metric_col_w)] * len(metric_names)))

    # Header row 1: Project + grouped Trial N blocks
    header_top = f"{'Project':<{project_col_w}} | "
    trial_labels = [f"Trial {t}".center(trial_block_w) for t in trials]
    header_top += " | ".join(trial_labels) + " |"

    # Header row 2: metric names repeated per trial with aligned separators
    header_sub = " " * project_col_w + " | "
    metric_headers: list[str] = []
    for _ in trials:
        metric_headers.extend([f"{name:>{metric_col_w}}" for name in metric_names])
    header_sub += " | ".join(metric_headers) + " |"

    # Separator line spans the exact printed width
    sep = "-" * len(header_sub)

    print(header_top)
    print(header_sub)
    print(sep)

    # Rows: one per project
    for project in sorted(results.keys()):
        row = f"{project:<{project_col_w}} | "
        proj_map = results.get(project, {})
        cells: list[str] = []
        for t in trials:
            r = proj_map.get(t, {})
            afl = r.get("aflpp_crashes", 0)
            aij = r.get("aijon_crashes", 0)
            if use_poi:
                new = r.get("poi_coverage", 0)
            else:
                new = r.get("#new_lines", 0)
            cells.extend(
                [
                    f"{afl:>{metric_col_w}}",
                    f"{aij:>{metric_col_w}}",
                    f"{new:>{metric_col_w}}",
                ]
            )
        row += " | ".join(cells) + " |"
        print(row)

    print(sep)


def pp_csv_table_results(
    results: dict[str, dict[int, dict[str, int]]], use_poi: bool
) -> None:
    """Pretty-print results in CSV format.

    CSV layout:
      project, trial_1_aflpp_crashes, trial_1_aijon_crashes, trial_1_#new_lines, ..., trial_N_...
    """
    if not results:
        # No data; still emit a minimal header to be explicit
        print("project")
        return

    # Determine trials present across all projects
    trial_set: set[int] = set()
    for proj_map in results.values():
        trial_set.update(proj_map.keys())
    trials = sorted(trial_set)
    if not trials:
        print("project")
        return

    # Build header
    header: list[str] = ["project"]
    for t in trials:
        header.extend(
            [
                f"trial_{t}_aflpp_crashes",
                f"trial_{t}_aijon_crashes",
                f"trial_{t}_#new_lines" if not use_poi else f"trial_{t}_poi_coverage",
            ]
        )

    writer = csv.writer(sys.stdout)
    writer.writerow(header)

    # Rows
    for project in sorted(results.keys()):
        proj_map: dict[int, dict[str, int]] = results[project]
        row: list[int | str] = [project]
        for t in trials:
            trial_data: dict[str, int] | None = proj_map.get(t)
            if trial_data is None:
                row.extend([0, 0, 0])
            else:
                row.extend(
                    [
                        int(trial_data.get("aflpp_crashes", 0)),
                        int(trial_data.get("aijon_crashes", 0)),
                        int(trial_data.get("#new_lines", 0))
                        if not use_poi
                        else int(trial_data.get("poi_coverage", 0)),
                    ]
                )
        writer.writerow(row)


def summarize_results(
    results: dict[str, dict[int, dict[str, int]]], use_poi: bool = False
) -> None:
    """Summarize results across all projects and trials.

    For crashes and new lines, report total counts and perform Mann-Whitney U test.
    """
    for project in results:
        total_aijon_crashes = 0
        total_aflpp_crashes = 0
        trials = results[project]
        for trial in trials:
            total_aijon_crashes += trials[trial].get("aijon_crashes", 0)
            total_aflpp_crashes += trials[trial].get("aflpp_crashes", 0)
        if total_aijon_crashes + total_aflpp_crashes == 0:
            continue
        print(f"Project: {project}")
        print(f"  Total AIJON Crashes: {total_aijon_crashes}")
        print(f"  Total AFL++ Crashes: {total_aflpp_crashes}")

    mann_whitney_p_values: dict[str, float | None] = {}
    wilcoxon_p_values: dict[str, float | None] = {}
    skipped = 0

    for proj, proj_map in results.items():
        new_lines_list: list[int] = []

        for trial_data in proj_map.values():
            new_lines = (
                trial_data.get("#new_lines", 0)
                if not use_poi
                else trial_data.get("poi_coverage", 0)
            )

            new_lines_list.append(new_lines)

        if sum(new_lines_list) == 0:
            mann_whitney_p_values[proj] = None
            wilcoxon_p_values[proj] = None
            skipped += 1
            continue

        _, p = mannwhitneyu(
            new_lines_list, [0] * len(new_lines_list), alternative="greater"
        )
        mann_whitney_p_values[proj] = p

        _, p = wilcoxon(new_lines_list, alternative="greater", zero_method="pratt")
        wilcoxon_p_values[proj] = p

    print("Summary of Results:")
    print(f"Number of projects analyzed: {len(results)}")
    print(f"NUmber of projects skipped (due to zero new lines): {skipped}")
    significant_projects = 0
    not_significant_projects = 0
    if mann_whitney_p_values:
        for name, p in mann_whitney_p_values.items():
            if p is None:
                print(f"Project {name}: Mann-Whitney U test p-value for new lines: N/A")
                continue
            print(f"Project {name}: Mann-Whitney U test p-value for new lines: {p:.6f}")
            if p < 0.05:
                significant_projects += 1
            else:
                not_significant_projects += 1
    else:
        print("No p-values computed.")

    print(f"Number of significant projects (Mann-Whitney): {significant_projects}")
    print(
        f"Number of not significant projects (Mann-Whitney): {not_significant_projects}"
    )

    significant_projects = 0
    not_significant_projects = 0
    if wilcoxon_p_values:
        for name, p in wilcoxon_p_values.items():
            if p is None:
                print(f"Project {name}: Wilcoxon test p-value for new lines: N/A")
                continue
                continue
            print(f"Project {name}: Wilcoxon test p-value for new lines: {p:.6f}")
            if p < 0.05:
                significant_projects += 1
            else:
                not_significant_projects += 1
    else:
        print("No p-values computed.")

    print(f"Number of significant projects (Wilcoxon): {significant_projects}")
    print(f"Number of not significant projects (Wilcoxon): {not_significant_projects}")


if __name__ == "__main__":
    args = parse_args()

    assert args.ossfuzz.is_dir(), f"OSS-Fuzz path {args.ossfuzz} is not a directory."
    assert args.aflplusplus.is_dir(), (
        f"AFL++ path {args.aflplusplus} is not a directory."
    )

    if not args.all:
        assert args.trial, "Provide --trial <N ...> or use --all."
        # assert max(args.trial) <= 10, (
        #     "Largest trial number must be less than or equal to 10."
        # )

    trials = args.trial if not args.all else list(range(1, 11))

    FILTER_ENABLED = args.annotation_filter

    if args.project:
        results: dict[str, dict[int, dict[str, int]]] = defaultdict(dict)
        for trial in trials:
            for project in args.project:
                ossfuzz_project_path = args.ossfuzz / project
                aflplusplus_project_path = args.aflplusplus / project
                if not ossfuzz_project_path.is_dir():
                    print(
                        f"OSS-Fuzz project path {ossfuzz_project_path} is not a directory. Skipping."
                    )
                    continue
                if not aflplusplus_project_path.is_dir():
                    print(
                        f"AFL++ project path {aflplusplus_project_path} is not a directory. Skipping."
                    )
                    continue
                trial_result = compare_one_trial(
                    ossfuzz_project_path, aflplusplus_project_path, trial, args.absolute
                )
                results[project][trial] = trial_result
    else:
        results = do_compare(args.ossfuzz, args.aflplusplus, trials, args.absolute)

    if args.summarize:
        summarize_results(results, args.poi)
    else:
        if args.csv:
            pp_csv_table_results(results, args.poi)
        else:
            pp_table_results(results, args.poi)
