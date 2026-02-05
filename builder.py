import argparse
import shutil
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile, mkdtemp

from loguru import logger

from aijon.aijon_lib import (
    ag_utils,
    build_project,
    find_error_locations,
    sanity_check_project,
    add_ijon_log,
)

logger.remove()
logger.add(sys.stderr, level="DEBUG")

CUR_DIR = Path(__file__).parent.absolute()
LOG_DIR = CUR_DIR / "logs"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Try and fix compiler errors with LLM."
    )
    parser.add_argument(
        "--target",
        type=Path,
        required=True,
        help="Path to the target project directory (e.g., /path/to/oss-fuzz/projects/<project_name>)",
    )
    parser.add_argument(
        "--target_source",
        type=Path,
        required=True,
        help="Path to the target source directory.",
    )
    parser.add_argument(
        "--patch_path",
        type=Path,
        required=True,
        help="Path to the file containing the diff.",
    )
    parser.add_argument(
        "--allow_list",
        type=Path,
        required=False,
        help="Path to the allow list file containing function names to be allowed.",
    )
    parser.add_argument(
        "--destination",
        "-d",
        type=Path,
        required=False,
        help="The path to store the output.",
    )
    parser.add_argument(
        "--arvo",
        action="store_true",
        required=False,
        help="If True, the target is an Arvo project, which requires special handling.",
    )
    parser.add_argument(
        "--skip_patch",
        action="store_true",
        required=False,
        help="If True, skip applying the patch.",
    )
    parser.add_argument(
        "--ijon_log",
        action="store_true",
        required=False,
        help="If True, modify the patch file to log the annotations",
    )
    return parser.parse_args()


def log_patch_ids(target_source: Path, patch_path: Path, destination: Path) -> Path:
    logger.info(f"Modifying patch {patch_path} to log PATCHIDs")
    temp_dir = mkdtemp()
    modified_source_dir = Path(temp_dir)
    shutil.copytree(target_source, modified_source_dir, dirs_exist_ok=True)

    with NamedTemporaryFile(mode="w+", delete=True) as temp_patch_file:
        temp_patch_path = Path(temp_patch_file.name)
        temp_patch_path.write_text(patch_path.read_text())
        add_ijon_log(temp_patch_path)
        logger.info(f"Added IJON_LOG to patch file {temp_patch_path}")
        diff_contents = temp_patch_path.read_text()

    diff_file = destination / "aijon_instrumentation_logging.patch"
    if len(diff_contents) == 0:
        raise ValueError("☣️ Nothing to diff.️")
    else:
        logger.trace(f"Diff contents: \n{diff_contents}")
        diff_file.write_text(diff_contents)
        logger.success(f"🎀 Diff file is saved to {diff_file}.")

    shutil.rmtree(modified_source_dir)
    return diff_file


def fix_compiler_errors(
    target_source: Path, patch_path: Path, compiler_error_str: str, destination: Path
) -> Path:
    """Fix compiler errors by applying a patch and removing hunks that cause errors.

    Args:
        target_source (Path): Path to the target source directory.
        patch_path (Path): Path to the file containing the diff.
        compiler_error_str (str): The compiler error output.
        destination (Path): The path to store the output.

    Raises:
        ValueError: If no valid hunks are found to fix.

    Returns:
        Path: The path to the generated patch file.
    """
    temp_dir = mkdtemp()
    modified_source_dir = Path(temp_dir)
    shutil.copytree(target_source, modified_source_dir, dirs_exist_ok=True)

    logger.info(f"🪛 Applying patch {patch_path} to source @ {modified_source_dir}")
    ag_utils.apply_diff(modified_source=modified_source_dir, patch_path=patch_path)

    logger.info("🗑️ Yeeting hunks that cause errors.")
    location_infos: list[int] = find_error_locations(
        compiler_error_str=compiler_error_str,
        applied_diff=patch_path.read_text(),
    )
    diff_lines = patch_path.read_text().splitlines()
    for patch_id in location_infos:
        for idx, line in enumerate(diff_lines):
            if f"/* PATCHID:{patch_id} */" in line:
                logger.debug(f"Yeeting line {idx}: {line} for patch ID {patch_id}")
                diff_lines[idx] = "+"

    new_diff_contents = "\n".join(diff_lines)
    with NamedTemporaryFile(mode="w+", delete=True) as temp_patch_file:
        temp_patch_path = Path(temp_patch_file.name)
        temp_patch_path.write_text(new_diff_contents + "\n")
        logger.info("Reversing the old patch")
        _ = ag_utils.get_diff_contents(
            modified_source=modified_source_dir,
            reset=True,
        )
        logger.info("Applying the new patch")
        ag_utils.apply_diff(
            modified_source=modified_source_dir,
            patch_path=temp_patch_path,
            allow_rejections=False,
        )
    logger.success("🎉 Successfully yeeted PATCHID that cause errors.")

    logger.info(f"🔎 Getting diff contents from source @ {modified_source_dir}.")
    diff_contents = ag_utils.get_diff_contents(modified_source_dir)
    diff_file = destination / "aijon" / "aijon_instrumentation.patch"
    diff_file.parent.mkdir(exist_ok=True)
    if len(diff_contents) == 0:
        raise ValueError("☣️ Nothing to diff.️")
    else:
        logger.trace(f"Diff contents: \n{diff_contents}")
        diff_file.write_text(diff_contents)
        logger.success(f"🎀 Diff file is saved to {diff_file}.")

    shutil.rmtree(modified_source_dir)
    return diff_file


if __name__ == "__main__":
    args = parse_args()
    target = args.target
    target_source = args.target_source
    patch_path = args.patch_path
    allow_list_path = (
        args.allow_list if args.allow_list and args.allow_list.is_file() else None
    )

    if not target.is_dir():
        logger.error(f"Target project directory {target} does not exist.")
        sys.exit(1)
    if not target_source.is_dir():
        logger.error(f"Target source directory {target_source} does not exist.")
        sys.exit(1)
    if not patch_path.is_file():
        logger.error(f"Applied diff file {patch_path} does not exist.")
        sys.exit(1)

    log_file = LOG_DIR / f"aijon_builder_{target.name}.log"
    logger.add(log_file, rotation="10 MB", level="TRACE")
    try:
        sanity_check_project(target)
    except Exception as e:
        logger.error(f"Error occurred: {e}")
        sys.exit(1)

    if args.destination:
        destination = args.destination
        if not destination.is_dir():
            logger.info(f"🔮 Creating directory {destination}.")
            destination.mkdir(parents=True, exist_ok=True)
    else:
        tempdir = mkdtemp()
        destination = Path(tempdir)

    if args.ijon_log:
        new_patch_path = log_patch_ids(
            target_source=target_source, patch_path=patch_path, destination=destination
        )
        patch_path = new_patch_path

    ctr: int = 0
    modified_source: Path | None = None
    while ctr < 10:
        temp_dir = mkdtemp()
        modified_source = Path(temp_dir)
        shutil.copytree(target_source, modified_source, dirs_exist_ok=True)

        if not args.skip_patch:
            ag_utils.apply_diff(
                modified_source=modified_source,
                patch_path=patch_path,
            )
        else:
            logger.info("Skipping applying the patch as per --skip_patch flag.")

        compiler_error_str: str | None = build_project(
            target_project=target,
            target_source=modified_source,
            allow_list_path=allow_list_path,
            is_arvo_target=args.arvo,
        )

        if compiler_error_str is None:
            logger.success("Built successfully without errors.")
            shutil.copytree(target / "out", destination / "out", dirs_exist_ok=True)
            aijon_dir = destination / "aijon"
            aijon_dir.mkdir(exist_ok=True)
            if patch_path != aijon_dir / "aijon_instrumentation.patch":
                shutil.copy(patch_path, aijon_dir / "aijon_instrumentation.patch")
            if allow_list_path:
                shutil.copy(allow_list_path, aijon_dir / "aijon_allowlist.txt")
            break

        ctr += 1
        logger.info(f"🔄 Retrying build... Attempt {ctr}")
        patch_path = fix_compiler_errors(
            target_source=target_source,
            patch_path=patch_path,
            compiler_error_str=compiler_error_str,
            destination=destination,
        )

    if modified_source:
        try:
            shutil.rmtree(modified_source)
        except PermissionError as e:
            logger.warning(
                f"Could not remove modified source directory: {e}. Retry with sudo."
            )

    if ctr == 10:
        logger.error("Failed to fix compiler errors after 10 attempts.")
        sys.exit(1)

    logger.success("All compiler errors fixed successfully.")
