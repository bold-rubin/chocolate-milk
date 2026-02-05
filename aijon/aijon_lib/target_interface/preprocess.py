from pathlib import Path

import clang_indexer


def preprocess_target(
    oss_fuzz_project_path: Path, destination: Path, is_arvo_target: bool = False
) -> tuple[Path, Path, Path]:
    """Run clang indexer and function index generator on the target project.

    Args:
        oss_fuzz_project_path (Path): Path to the OSS-Fuzz project directory.
        destination (Path): Path to the destination directory for the processed files.
        is_arvo_target (bool): If True, the target is an Arvo project, which requires special handling.

    Returns:
        tuple[Path, Path, Path]: Paths to the source code directory, the function index file and the indexer JSON directory.
    """
    clang_indexer.run_clang_indexer(oss_fuzz_project_path, destination, is_arvo_target=is_arvo_target)
    output_dir = destination / "out/full"
    function_indices_json_file = destination / "function_indices.json"
    functions_by_file_json_path = destination / "functions_by_file.json"
    clang_indexer.full_index_json(
        output_dir, function_indices_json_file, functions_by_file_json_path
    )

    source_code_dir = destination / "src"
    return source_code_dir, function_indices_json_file, output_dir
