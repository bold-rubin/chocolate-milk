import functools
import json
import logging
from collections import defaultdict
from multiprocessing import Pool, cpu_count
from pathlib import Path
from typing import Dict, List, Optional

from project_utils.models import FunctionIndex, FunctionsByFile, ReducedFunctionIndex, SignatureToFile
from tqdm import tqdm  # Import tqdm for progress bar

# Set up logging
logging.basicConfig(
    level="INFO",  # Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    format="%(message)s",
    datefmt="[%X]",
)

log = logging.getLogger("FIG")


def process_file_for_meta_index(
    input_dir: Path, functions_by_file_json_path: Path, file_path: Path
) -> Optional[ReducedFunctionIndex]:
    if file_path.parent.name == "STRUCT":
        log.debug("Skipping STRUCT file: %s", file_path)
        return None
    try:
        f_index = FunctionIndex.model_validate_json(file_path.read_text())
    except Exception as e:
        log.critical("Error processing file: %s", file_path)
        log.critical("Error: %s", e)
        log.critical("File content: %s", file_path.read_text())
        return None

    function_signature = (
        f"{f_index.target_container_path}:{f_index.start_line}:{f_index.start_column}::{f_index.signature}"
    )
    line_map = (
        {f_index.start_line + i: line for i, line in enumerate(f_index.code.split("\n"))}
        if functions_by_file_json_path
        else None
    )

    reduced_index = ReducedFunctionIndex(
        func_name=f_index.funcname,
        function_signature=function_signature,
        filename=f_index.filename,
        start_line=f_index.start_line,
        end_line=f_index.end_line,
        start_column=f_index.start_column,
        end_column=f_index.end_column,
        start_offset=f_index.start_offset,
        end_offset=f_index.end_offset,
        line_map=line_map,
        indexed_jsons_relative_filepath=file_path.relative_to(input_dir),
        target_container_path=f_index.target_container_path,
        focus_repo_relative_path=f_index.focus_repo_relative_path,
    )
    return reduced_index


def parallel_merge_dicts(all_indicies: List[ReducedFunctionIndex], chunk_size) -> Dict[str, Path]:
    chunks = [all_indicies[i : i + chunk_size] for i in range(0, len(all_indicies), chunk_size)]

    final_dict = {}
    for chunk in tqdm(chunks, desc="Merging function indicies", total=len(chunks)):
        final_dict |= {index.function_signature: index.indexed_jsons_relative_filepath for index in chunk}

    return final_dict


def full_index_json(input_dir: Path, target_function_index: Path, functions_by_file_json_path: Path):
    num_cpus = cpu_count()

    log.info("Compiling code database for directory: %s", input_dir)
    files = list(input_dir.rglob("**/*.json"))
    chunk_size = min(512, (len(files) // num_cpus) + 1)
    log.info("Number of CPUs used: %s, Chunk size: %s", num_cpus, chunk_size)

    with Pool(processes=num_cpus) as pool:
        partial_func = functools.partial(process_file_for_meta_index, input_dir, functions_by_file_json_path)
        function_indicies = []
        for func_index in tqdm(
            pool.imap_unordered(partial_func, files, chunksize=chunk_size),
            desc="Processing File Indicies",
            total=len(files),
        ):
            if not func_index:
                continue
            function_indicies.append(func_index)

    source_index = defaultdict(list)
    for func_index in tqdm(function_indicies, desc="Building index file"):
        source_index[str(func_index.target_container_path.resolve())].append(func_index)

    validated_data = json.loads(FunctionsByFile(func_by_file=source_index).model_dump_json())["func_by_file"]
    functions_by_file_json_path.write_text(json.dumps(validated_data, indent=4))

    log.info("Writing index JSON to %s", target_function_index)
    combined_dict = parallel_merge_dicts(function_indicies, chunk_size)
    with target_function_index.open("w") as f:
        validated_data = json.loads(SignatureToFile(sig_to_file=combined_dict).model_dump_json())["sig_to_file"]
        json.dump(validated_data, f, indent=4)
        log.info("Index written to JSON successfully")
