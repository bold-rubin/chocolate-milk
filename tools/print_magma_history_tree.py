import re
import sys
from pathlib import Path


def extract_part_with_prefix(filename: str, prefix: str) -> str:
    for part in filename.split(","):
        if part.startswith(prefix):
            return part.split(":")[1]
    return ""


def extract_source_from_filename(filename: str) -> list[str]:
    source = extract_part_with_prefix(filename, "src")
    return source.replace(".out", "").split("+")


def extract_sync_from_filename(filename: str) -> str:
    return extract_part_with_prefix(filename, "sync")


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
    print(prefix + node["cur_dir"] + " : " + node["name"])
    child_count = len(node["children"])
    for i, child in enumerate(node["children"]):
        connector = "├── " if i < child_count - 1 else "└── "
        child_prefix = prefix + ("│ " if i < child_count - 1 else " ")
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


def build_history_tree(current_name: str, main_dir: Path, worker_dir: Path, is_crash: bool = False) -> dict:
    # __import__('ipdb').set_trace()

    if is_crash:
        main_crashes_dir = main_dir.parent / "crashes"
        worker_crashes_dir = worker_dir.parent / "crashes"
        if (main_crashes_dir / current_name).is_file():
            current_dir = main_dir
        elif (worker_crashes_dir / current_name).is_file():
            current_dir = worker_dir
        else:
            raise FileNotFoundError(f"Crash file {current_name} not found in either crashes directory.")
    else:
        if (main_dir / current_name).is_file():
            current_dir = main_dir
        elif (worker_dir / current_name).is_file():
            current_dir = worker_dir
        else:
            raise FileNotFoundError(f"File {current_name} not found in either directory.")

    node = {"name": current_name, "cur_dir": current_dir.parent.name, "children": []}
    # if current_name == "id:001465,sync:aijon,src:001437,+cov.out":
    #     import ipdb; ipdb.set_trace()

    while extract_orig_from_filename(current_name) == "":
        sync = extract_sync_from_filename(current_name)
        source_ids = extract_source_from_filename(current_name)
        assert len(source_ids) in (1, 2)

        if len(source_ids) == 1:
            if sync == "aflpp":
                current_dir = worker_dir
            elif sync:
                current_dir = main_dir
            source_files = list(current_dir.glob(f"id:{source_ids[0]},*"))
            assert len(source_files) == 1
            current_name = source_files[0].name
            node["children"].append(build_history_tree(current_name, main_dir, worker_dir))
            return node

        else:  # two parents
            for sid in source_ids:
                source_files = list(current_dir.glob(f"id:{sid},*"))
                assert len(source_files) == 1
                node["children"].append(
                    build_history_tree(source_files[0].name, main_dir, worker_dir)
                )
            return node

    # reached an original seed
    return node


def get_mutation_sequence(input_file: Path, aijon_dir: Path, aflpp_dir: Path) -> list[str]:
    tree = build_history_tree(input_file.name, aijon_dir / "queue", aflpp_dir / "queue", is_crash=input_file.parent.name == 'crashes')
    print_tree(tree)
    return list(
        sorted(
            set(flatten_history(tree)),
            key=lambda x: int(extract_id_from_filename(x)),
            reverse=True,
        )
    )



if __name__ == "__main__":
    assert len(sys.argv) == 2, (
        "Usage: python calculate_annotation_score.py <path/to/input_file>"
    )
    input_file = Path(sys.argv[1])
    analysis_result_dir = input_file.parent.parent.parent
    assert analysis_result_dir.is_dir(), (
        f"Directory {analysis_result_dir} does not exist."
    )

    aijon_result_dir = analysis_result_dir / "aijon"
    aflpp_result_dir = analysis_result_dir / "aflpp"

    get_mutation_sequence(input_file, aijon_result_dir, aflpp_result_dir)
