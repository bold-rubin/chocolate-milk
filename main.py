import argparse
import os
import shutil
import sys
import time
import zipfile
from multiprocessing import Pool
from pathlib import Path
from tempfile import NamedTemporaryFile, mkdtemp

from loguru import logger

from aijon.aijon_lib import (
    CodeSwipePOI,
    CrashPOI,
    PatchPOI,
    MagmaPOI,
    SarifPOI,
    OSSFuzzPOI,
    ag_utils,
    apply_llm_response,
    instrument_code_with_ijon,
    preprocess_target,
    sanity_check_project,
    postprocess_artifacts,
)

logger.remove()
logger.add(sys.stderr, level="DEBUG")

CUR_DIR = Path(__file__).parent.absolute()
LOG_DIR = CUR_DIR / "logs"
POI_OBJ: (
    CodeSwipePOI | SarifPOI | PatchPOI | MagmaPOI | CrashPOI | OSSFuzzPOI | None
) = None


def parse_args():
    parser = argparse.ArgumentParser(description="Instrument code with IJON.")
    parser.add_argument(
        "--target",
        "-t",
        type=Path,
        required=True,
        help="Path to the target OSS Fuzz project directory.",
    )
    parser.add_argument(
        "--destination",
        "-d",
        type=Path,
        required=False,
        help="The path to store the output.",
    )
    parser.add_argument(
        "--clang_indexer_output_dir",
        type=Path,
        required=False,
        help="Path to the clang indexer output directory. If not provided, it will be created using clang indexer.",
    )
    parser.add_argument(
        "--callgraphs",
        type=Path,
        required=False,
        help="Path to the call graph JSON file.",
    )
    parser.add_argument(
        "--harness",
        type=str,
        required=False,
        help="Name of the harness for the crash report.",
    )
    parser.add_argument(
        "--diff_only",
        action="store_true",
        required=False,
        help="Only store the diff of the annotated code. This will not store the full code.",
    )
    parser.add_argument(
        "--arvo",
        action="store_true",
        required=False,
        help="If True, the target is an Arvo project, which requires special handling.",
    )
    parser.add_argument(
        "--mode",
        type=str,
        required=False,
        help="Set to 'crazy' for crazy mode for CrashPOI, stupid/intelligent for stupid/intelligent mode for MagmaPOI. Defaults to normal mode.",
    )
    poi = parser.add_mutually_exclusive_group(required=True)
    poi.add_argument(
        "--codeswipe_report",
        type=Path,
        help="Path to the CodeSwip report.",
    )
    poi.add_argument(
        "--sarif_report",
        type=Path,
        help="Path to the SARIF report.",
    )
    poi.add_argument(
        "--patch_report",
        type=Path,
        help="Path to the patch report.",
    )
    poi.add_argument(
        "--magma_report",
        type=Path,
        help="Path to the Magma patch report.",
    )
    poi.add_argument(
        "--crash_report",
        type=Path,
        help="Path to the crash report.",
    )
    poi.add_argument(
        "--oss_fuzz_report",
        type=Path,
        help="Path to the OSS-Fuzz optimal targets report.",
    )
    arguments = parser.parse_args()
    assert any(
        [
            arguments.codeswipe_report,
            arguments.sarif_report,
            arguments.patch_report,
            arguments.magma_report,
            arguments.crash_report,
            arguments.oss_fuzz_report,
        ]
    ), "At least one report must be provided."
    if os.environ.get("IDA_PATH", None) is None:
        logger.warning(
            "🤡 IDA_PATH environment variable is not set. Defaulting to angr"
        )
    return arguments


def worker_function(
    poi: dict,
    modified_source_dir: Path,
):
    """
    Worker function to process a single Point of Interest (POI).
    """
    global POI_OBJ
    poi_obj: (
        CodeSwipePOI | SarifPOI | PatchPOI | MagmaPOI | CrashPOI | OSSFuzzPOI | None
    ) = POI_OBJ
    assert poi_obj is not None, "POI object is not initialized."

    # harness_input_dict = defaultdict(list)
    allow_list_funcs = list()
    total_cost = 0.0
    logger.info(f"Processing POI for function {poi['function_index_key']}")
    sink_funcindex = poi["function_index_key"]

    logger.debug(f"Finding closest covered caller for sink function {sink_funcindex}")

    try:
        resolved_sinkfunc_index = poi_obj.get_function_index_from_poi(
            poi["function_index_key"]
        )
    except ValueError:
        logger.warning(
            f"🤡 Warning: Could not resolve function index for {poi['function_index_key']}. Skipping POI"
        )
        return

    call_path = poi_obj.get_call_path_to(resolved_sinkfunc_index.funcname)
    logger.info(
        f"Found call path to {resolved_sinkfunc_index.funcname} with {len(call_path)} functions."
    )

    allow_list_funcs.extend(call_path)

    # Step 3 is to instrument the code with IJON
    try:
        logger.info(f"Instrumenting code @ {modified_source_dir} with POI {poi}")
        cost, llm_response, file_path = instrument_code_with_ijon(
            poi,
            resolved_sinkfunc_index,
            modified_source_dir,
            poi_class_name=poi_obj.__class__.__name__,
            mode=poi_obj.mode,
        )
        total_cost += cost
        logger.debug(f"Cost of instrumenting code with IJON: {total_cost}")
    except ValueError:
        logger.warning(
            f"🤡 Warning: Could not instrument code with IJON for POI {poi}. Skipping."
        )
        return
    except Exception as e:
        logger.exception(f"🤡 UNEXPECTED EXCEPTION {e}")
        return

    return {
        "total_cost": cost,
        "filename": file_path,
        "function_line_number": resolved_sinkfunc_index.start_line,
        "llm_response": llm_response,
        "allow_list_funcs": allow_list_funcs,
        # "harness_input_dict": harness_input_dict,
    }


def main(
    target_source: Path,
    report_path: Path,
    poi_obj: CodeSwipePOI | SarifPOI | PatchPOI | MagmaPOI | CrashPOI,
) -> tuple[Path, list[str], dict[str, list[str]]]:
    """Main function to instrument code with IJON.

    Args:
        target_source (Path): Path to the target source directory.
        report_path (Path): Path to the report file.
        poi_obj: CodeSwipePOI | SarifPOI | PatchPOI | MagmaPOI | CrashPOI): POI object to handle different report formats.

    Returns
        Path: Path to the instrumented code directory.
    """
    global POI_OBJ
    POI_OBJ = poi_obj

    temp_dir = mkdtemp()
    modified_source_dir = Path(temp_dir)
    shutil.copytree(
        target_source,
        modified_source_dir,
        dirs_exist_ok=True,
        symlinks=True,
        ignore_dangling_symlinks=True,
    )

    # Step 1 is to parse the report and add POIs to the POI object
    poi_obj.add_poi(report_path)
    if poi_obj.empty:
        shutil.rmtree(modified_source_dir)
        raise ValueError("☣️ AIJON instrumentation failed since no POIs were found.")

    global_cost = 0.0
    global_allow_list_funcs: set[str] = set()
    # global_harness_input_dict = defaultdict(list)

    with Pool(processes=20) as pool:
        logger.info(
            f"Starting parallel processing of {len(poi_obj.get_all_pois())} POIs."
        )
        results = pool.starmap(
            worker_function,
            [(poi, modified_source_dir) for poi in poi_obj.get_all_pois()],
        )

        logger.info("Aggregating results from workers.")

        global_cost = sum(x.get("total_cost", 0.0) for x in results if x is not None)
        logger.info(f"Total cost of instrumentation: {global_cost}")

        for worker_data in sorted(
            (r for r in results if r), key=lambda x: -x["function_line_number"]
        ):
            logger.trace(f"Processing results from worker {worker_data}")
            if worker_data is None:
                logger.warning("🤡 Warning: Worker data is None. Skipping.")
                continue
            filename = worker_data["filename"]
            function_line_number = worker_data["function_line_number"]
            llm_response = worker_data["llm_response"]
            allow_list_funcs = worker_data["allow_list_funcs"]
            # harness_input_dict = worker_data["harness_input_dict"]

            logger.debug(
                f"Applying patch:\n{filename=}\n{function_line_number=}\n{llm_response=}"
            )

            try:
                target_file_path = modified_source_dir / filename
                original_code = target_file_path.read_text()
                modified_code, bad_blocks, num_success = apply_llm_response(
                    original_code=original_code,
                    llm_response=llm_response,
                    line_offset=function_line_number
                    - 1,  # stupid clang-indexer 1-indexing
                    language=os.environ.get("LANGUAGE", "c"),
                )
                target_file_path.write_text(modified_code)
            except Exception as e:
                # This can happen if we modify the same file multiple times
                logger.warning(
                    f"🤡 Search and replace failed for {filename}. {e} - Skipping."
                )
                continue

            global_allow_list_funcs.update(allow_list_funcs)
            # global_harness_input_dict.update(harness_input_dict)

    return (
        modified_source_dir,
        list(global_allow_list_funcs),
        {},
    )  # global_harness_input_dict


if __name__ == "__main__":
    args = parse_args()

    if args.destination:
        destination = args.destination
        if not destination.is_dir():
            logger.info(f"🔮 Creating directory {destination}.")
            destination.mkdir(parents=True, exist_ok=True)
    else:
        tempdir = mkdtemp()
        destination = Path(tempdir)

    target_oss_fuzz_project_dir = args.target
    assert target_oss_fuzz_project_dir.is_dir(), (
        f"Target OSS Fuzz project directory {target_oss_fuzz_project_dir} is not a directory."
    )
    log_file = LOG_DIR / f"aijon_instrument_{target_oss_fuzz_project_dir.name}.log"
    logger.add(log_file, rotation="10 MB", level="TRACE")
    try:
        sanity_check_project(target_oss_fuzz_project_dir)
    except Exception as e:
        logger.error(f"Error occurred: {e}")
        sys.exit(1)

    if not args.clang_indexer_output_dir or not args.clang_indexer_output_dir.is_dir():
        flag = False
    else:
        target_source = args.clang_indexer_output_dir / "src"
        full_function_indices = args.clang_indexer_output_dir / "function_indices.json"
        target_functions_json_dir = args.clang_indexer_output_dir / "out/full"
        if not all(
            [
                target_source.is_dir(),
                full_function_indices.is_file(),
                target_functions_json_dir.is_dir(),
            ]
        ):
            flag = False
        else:
            flag = True
    if not flag:
        logger.info(
            "🔮 Running clang indexer to create full_function_indices and target_functions_json_dir."
        )
        target_source, full_function_indices, target_functions_json_dir = (
            preprocess_target(target_oss_fuzz_project_dir, destination, args.arvo)
        )
        outdir = destination / "out"
    else:
        logger.info(f"🔮 Reusing clang indexer output {args.clang_indexer_output_dir}")
        outdir = args.clang_indexer_output_dir / "out"

    assert target_source.is_dir(), f"Target source {target_source} is not a directory."

    assert full_function_indices.is_file(), "Need full_function_indices."
    assert target_functions_json_dir.is_dir(), "Need target_functions_json_dir."

    POI_obj: (
        CodeSwipePOI | SarifPOI | MagmaPOI | PatchPOI | CrashPOI | OSSFuzzPOI | None
    ) = None

    if args.codeswipe_report:
        report_path = args.codeswipe_report
        POI_obj = CodeSwipePOI(
            full_function_indices_path=full_function_indices,
            target_functions_json_dir=target_functions_json_dir,
            function_resolver=None,
            callgraph_json=args.callgraphs,
        )
    elif args.sarif_report:
        report_path = args.sarif_report
        POI_obj = SarifPOI(
            full_function_indices_path=full_function_indices,
            target_functions_json_dir=target_functions_json_dir,
            function_resolver=None,
            callgraph_json=args.callgraphs,
        )
    elif args.patch_report:
        report_path = args.patch_report
        POI_obj = PatchPOI(
            full_function_indices_path=full_function_indices,
            target_functions_json_dir=target_functions_json_dir,
            function_resolver=None,
            callgraph_json=args.callgraphs,
        )
    elif args.magma_report:
        report_path = args.magma_report
        POI_obj = MagmaPOI(
            full_function_indices_path=full_function_indices,
            target_functions_json_dir=target_functions_json_dir,
            function_resolver=None,
            callgraph_json=args.callgraphs,
        )
    elif args.crash_report:
        report_path = args.crash_report
        POI_obj = CrashPOI(
            full_function_indices_path=full_function_indices,
            target_functions_json_dir=target_functions_json_dir,
            function_resolver=None,
            callgraph_json=args.callgraphs,
        )
    elif args.oss_fuzz_report:
        report_path = args.oss_fuzz_report
        POI_obj = OSSFuzzPOI(
            full_function_indices_path=full_function_indices,
            target_functions_json_dir=target_functions_json_dir,
            function_resolver=None,
            callgraph_json=args.callgraphs,
        )
    else:
        raise ValueError("No report provided. Please provide a report file.")

    logger.info(f"🔮 Analyzing harness binaries in {outdir}.")
    POI_obj.analyze_harness_binaries(
        outdir, target_oss_fuzz_project_dir / "project.yaml", args.harness
    )
    logger.info(f"Instrumentation Artifacts will be saved to {destination}")

    POI_obj.set_mode(args.mode)

    assert report_path.is_file(), f"Report {report_path} does not exist."

    logger.info(
        f"🎠 Instrumenting source @ {target_source} with report @ {report_path}."
    )
    ctr = 0
    while True:
        if ctr == 10:
            raise RuntimeError("☣️ AIJON instrumentation failed 10 times.")

        try:
            modified_source, allow_list_funcs, harness_input_dict = main(
                target_source, report_path, POI_obj
            )
        except ValueError as exc:
            logger.error("🤡 No POI's found. Exiting")
            raise RuntimeError(
                "☣️ AIJON instrumentation failed since no POIs were found."
            ) from exc

        if len(allow_list_funcs) > 0:
            break
        else:
            logger.warning("🤡 AIJON failed to find any allowlist functions.")

        logger.warning("🫂 AIJON instrumentation failed. Retrying in 10 minutes.")
        POI_obj.remove_all_pois()
        time.sleep(600)
        ctr += 1

    logger.success("🎊 AIJON instrumentation succeeded.")
    aijon_dir = destination / "aijon_instrumentation"
    aijon_dir.mkdir(parents=True, exist_ok=True)

    if args.diff_only:
        diff_contents = ag_utils.get_diff_contents(modified_source)
        diff_file = aijon_dir / "aijon_instrumentation.patch"
        if len(diff_contents) == 0:
            raise ValueError("☣️ Nothing to diff.️")
        else:
            with NamedTemporaryFile(mode="w+", delete=True) as temp_file:
                temporary_diff_file = Path(temp_file.name)
                temporary_diff_file.write_text(diff_contents, encoding="utf-8")
                logger.info("Verifying diff contents")
                verified_diff = ag_utils.verify_diff_contents(
                    temporary_diff_file, target_source
                )
            diff_file.write_text(verified_diff, encoding="utf-8")
            logger.success(f"🎀 Diff file is saved to {diff_file}")
    else:
        shutil.copytree(modified_source, destination, dirs_exist_ok=True)
        logger.success(f"🎁 Instrumented code is saved to {destination}")

    allowlist_file = aijon_dir / "aijon_allowlist.txt"
    if len(allow_list_funcs) > 0:
        allowlist_file.write_text("\n".join(allow_list_funcs) + "\n")
        logger.success(
            f"📝 Allowlist file is saved to {allowlist_file} with {len(allow_list_funcs)} functions."
        )

    postprocess_artifacts(aijon_dir, diff_mode=args.diff_only)

    if len(harness_input_dict) == 0:
        logger.warning("🤡 No harness inputs found. Skipping harness input generation.")
    for harness_name in harness_input_dict:
        logger.info(
            f"Found {len(harness_input_dict[harness_name])} inputs for harness: {harness_name}"
        )
        input_file_dir = destination / harness_name
        input_file_dir.mkdir(parents=True, exist_ok=True)
        seed_corpus_file = destination / f"{harness_name}_seed_corpus.zip"
        with zipfile.ZipFile(seed_corpus_file, "w") as zipf:
            for idx, input_bytes in enumerate(harness_input_dict[harness_name]):
                input_file = input_file_dir / f"{idx}"
                input_file.write_bytes(input_bytes)
                zipf.write(input_file, arcname=input_file.name)

        shutil.rmtree(input_file_dir)
        logger.success(
            f"🎁 Seed corpus for harness {harness_name} is saved to {seed_corpus_file}"
        )

    shutil.rmtree(modified_source)
