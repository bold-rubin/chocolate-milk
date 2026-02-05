import re
import sys
from pathlib import Path
from tqdm.rich import tqdm
from collections import defaultdict


def extract_part_with_prefix(filename: str, prefix: str) -> str:
    for part in filename.split(","):
        if part.startswith(prefix):
            return part.split(":")[1]
    return ""


def extract_source_from_filename(filename: str) -> list[str]:
    source = extract_part_with_prefix(filename, "src")
    return source.split("+")


def extract_id_from_filename(filename: str) -> str:
    return extract_part_with_prefix(filename, "id")


def extract_sig_from_filename(filename: str) -> str:
    return extract_part_with_prefix(filename, "sig")


def extract_op_from_filename(filename: str) -> str:
    return extract_part_with_prefix(filename, "op")


def extract_rep_from_filename(filename: str) -> str:
    return extract_part_with_prefix(filename, "rep")


def extract_val_from_filename(filename: str) -> str:
    return extract_part_with_prefix(filename, "val")


def extract_pos_from_filename(filename: str) -> str:
    return extract_part_with_prefix(filename, "pos")


def extract_orig_from_filename(filename: str) -> str:
    return extract_part_with_prefix(filename, "orig")


def get_edge_coverage_for_input(input_filename: str, analysis_result_dir: Path) -> str:
    assert analysis_result_dir.is_dir(), (
        f"Expected {analysis_result_dir} to be a directory."
    )

    edge_coverage_file = analysis_result_dir / "original_analysis" / f"{input_filename}"
    assert edge_coverage_file.is_file(), f"Expected {edge_coverage_file} to be a file."

    return edge_coverage_file.read_text().strip()


def get_annotation_coverage_for_input(
    input_filename: str, edge_coverage: str, analysis_result_dir: Path
) -> str:
    assert analysis_result_dir.is_dir(), (
        f"Expected {analysis_result_dir} to be a directory."
    )

    annotation_coverage_file = (
        analysis_result_dir / "patched_analysis" / f"{input_filename}"
    )
    assert annotation_coverage_file.is_file(), (
        f"Expected {annotation_coverage_file} to be a file."
    )

    contents = annotation_coverage_file.read_text().strip().splitlines()
    for line in edge_coverage.splitlines():
        try:
            contents.remove(line.strip())
        except ValueError:
            pass

    return "\n".join(contents)


def get_annotations_for_input(input_filename: str, stdout_dir: Path) -> list[str]:
    assert stdout_dir.is_dir(), f"Expected {stdout_dir} to be a directory."

    annotation_file = stdout_dir / f"{input_filename}"
    assert annotation_file.is_file(), f"Expected {annotation_file} to be a file."

    pattern = re.compile(rb"PATCHID: ([0-9]+)", re.MULTILINE)

    return [m.decode() for m in re.findall(pattern, annotation_file.read_bytes())]


def get_new_edge_bits(edge_coverage: str, seen_edge_bits: set[str]) -> set[str]:
    cur_edge_bits: set[str] = set()
    for line in edge_coverage.splitlines():
        cur_edge_bits.add(line.strip())
    return cur_edge_bits - seen_edge_bits


def get_new_annotations(annotations: list[str], seen_annotations: set[str]) -> set[str]:
    return set(annotations) - seen_annotations


def print_tree(node: dict, prefix: str = ""):
    print(prefix + node["name"])
    child_count = len(node["children"])
    for i, child in enumerate(node["children"]):
        connector = "├── " if i < child_count - 1 else "└── "
        child_prefix = prefix + ("│   " if i < child_count - 1 else "    ")
        print(prefix + connector, end="")
        print_tree(child, child_prefix)


def flatten_history(node: dict) -> list[str]:
    if extract_sig_from_filename(node["name"]) != "":
        history = []
    else:
        history = [node["name"]]
    for child in node["children"]:
        history.extend(flatten_history(child))
    return history


def get_mutation_sequence(crashing_input_file: Path, queue_dir: Path) -> list[str]:
    tree = build_history_tree(crashing_input_file.name, queue_dir)
    print_tree(tree)
    return list(
        sorted(
            set(flatten_history(tree)),
            key=lambda x: int(extract_id_from_filename(x)),
            reverse=True,
        )
    )


def build_history_tree(current_name: str, queue_dir: Path) -> dict:
    node = {"name": current_name, "children": []}

    while extract_orig_from_filename(current_name) == "":
        source_ids = extract_source_from_filename(current_name)
        assert len(source_ids) in (1, 2)

        if len(source_ids) == 1:
            source_files = list(queue_dir.glob(f"id:{source_ids[0]},*"))
            assert len(source_files) == 1
            current_name = source_files[0].name
            node["children"].append(build_history_tree(current_name, queue_dir))
            return node

        else:  # two parents
            for sid in source_ids:
                source_files = list(queue_dir.glob(f"id:{sid},*"))
                assert len(source_files) == 1
                node["children"].append(
                    build_history_tree(source_files[0].name, queue_dir)
                )
            return node

    # reached an original seed
    return node


def calc_annotation_score(
    history: dict, stdout_dir: Path, edge_coverages: dict[str, bool]
) -> dict[int, int]:
    score: dict[int, int] = defaultdict(int)

    def helper(node: dict, edge_coverages: dict, skip: bool = False):
        anns = get_annotations_for_input(node["name"], stdout_dir)
        if skip is False:
            if edge_coverages.get(node["name"], False) is False:
                # This input did not discover any new actual edges, so we
                # penalize the annotations it hits
                for ann in anns:
                    score[int(ann)] -= 1
            else:
                # This input discovered new edges, so we reward the annotations it hits
                for ann in anns:
                    score[int(ann)] += 1
        for child in node["children"]:
            helper(child, edge_coverages, skip=False)

    helper(history, edge_coverages, skip=True)
    return score


def calc_edge_coverages(original_queue_dir: Path) -> dict[str, bool]:
    edge_coverages: dict[str, bool] = dict()
    total_edges_discovered: set[str] = set()
    for input_file in tqdm(
        sorted(
            original_queue_dir.iterdir(),
            key=lambda x: int(extract_id_from_filename(x.name)),
        )
    ):
        if not input_file.is_file():
            continue

        edge_coverage = get_edge_coverage_for_input(
            input_file.name, original_queue_dir.parent
        )
        new_edges = get_new_edge_bits(edge_coverage, total_edges_discovered)
        total_edges_discovered.update(new_edges)
        edge_coverages[input_file.name] = len(new_edges) > 0

    return edge_coverages


def analyze_queue(analysis_result_dir: Path) -> dict[int, int]:
    annotation_score: dict[int, int] = defaultdict(int)
    original_queue_dir = analysis_result_dir / "original_analysis"
    queue_dir = analysis_result_dir / "patched_analysis"
    stdout_dir = analysis_result_dir / "patched_stdout"
    edge_coverages = calc_edge_coverages(original_queue_dir)
    for harness_out_dir in queue_dir.iterdir():
        for input_file in tqdm(
            sorted(
                harness_out_dir.iterdir(),
                key=lambda x: int(extract_id_from_filename(x.name)),
            )
        ):
            if not input_file.is_file():
                continue

            anns = get_annotations_for_input(
                input_file.name, stdout_dir / harness_out_dir.name
            )
            if len(anns) == 0:
                # This input did not hit any annotations, ie is not interesting
                # SKIP
                continue

            if extract_orig_from_filename(input_file.name) != "":
                # This is an original seed, skip
                continue

            try:
                history: dict = build_history_tree(input_file.name, harness_out_dir)
            except AssertionError:
                # print(f"Failed to build history tree for {input_file.name}")
                continue
            except Exception as e:
                print(f"Error building history tree for {input_file.name}: {e}")
                continue

            score = calc_annotation_score(
                history, stdout_dir / harness_out_dir.name, edge_coverages
            )

            for annotation in score:
                annotation_score[annotation] += score[annotation]

    return annotation_score


def main(analysis_result_dir: Path):
    annotation_score: dict[int, int] = analyze_queue(analysis_result_dir)
    for annotation in sorted(annotation_score.keys()):
        print(f"Annotation {annotation} score: {annotation_score[annotation]}")


if __name__ == "__main__":
    assert len(sys.argv) == 2, (
        "Usage: python calculate_annotation_score.py <analysis_result_dir>"
    )
    analysis_result_dir = Path(sys.argv[1])
    assert analysis_result_dir.is_dir(), (
        f"Directory {analysis_result_dir} does not exist."
    )

    main(analysis_result_dir)
