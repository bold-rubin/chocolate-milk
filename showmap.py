import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path

from loguru import logger

from aijon.aijon_lib import run_showmap, sanity_check_project

logger.remove()
logger.add(sys.stderr, level="DEBUG")

CUR_DIR = Path(__file__).parent.absolute()
LOG_DIR = CUR_DIR / "logs"


def parse_args() -> Namespace:
    parser = ArgumentParser(
        description="Run the fuzzer for a target OSS-Fuzz/Arvo project."
    )
    parser.add_argument(
        "--target", type=Path, required=True, help="Path to the target directory."
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Path to the directory containing the built artifacts.",
    )
    parser.add_argument(
        "--input_file",
        type=Path,
        required=True,
        help="Path to the input file.",
    )
    parser.add_argument(
        "--harness",
        type=str,
        required=True,
        help="Name of the harness to use for fuzzing.",
    )
    parser.add_argument(
        "--arvo",
        action="store_true",
        required=False,
        help="If True, the target is an Arvo project, which requires special handling.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    target = args.target
    output = args.output
    input_file = args.input_file
    harness = args.harness
    is_arvo = args.arvo

    if not target.is_dir():
        logger.error(f"Target project directory {target} does not exist.")
        sys.exit(1)
    if not output.is_dir():
        logger.error(f"Output directory {output} does not exist.")
        sys.exit(1)
    if not (output / harness).is_file():
        logger.error(f"Harness {harness} does not exist in output directory {output}.")
        sys.exit(1)
    if not input_file.is_file():
        logger.error(f"Input file {input_file} does not exist.")
        sys.exit(1)

    log_file = LOG_DIR / f"aijon_showmap_{target.name}.log"
    logger.add(log_file, rotation="10 MB", level="TRACE")
    try:
        sanity_check_project(target)
    except Exception as e:
        logger.error(f"Error occurred: {e}")
        sys.exit(1)

    try:
        run_showmap(
            target_project=target,
            outdir=output,
            input_file=input_file,
            harness_path=output / harness,
            is_arvo_target=is_arvo,
        )
    except RuntimeError as e:
        logger.warning(f"Could not run showmap for {input_file}: {e}")
    else:
        logger.success(
            f"Showmap completed for {target.name}. Logs are saved to {log_file}"
        )
