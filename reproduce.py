import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path

from loguru import logger

from aijon.aijon_lib import run_reproducer, sanity_check_project

logger.remove()
logger.add(sys.stderr, level="DEBUG")

CUR_DIR = Path(__file__).parent.absolute()
LOG_DIR = CUR_DIR / "logs"


def parse_args() -> Namespace:
    parser = ArgumentParser(
        description="Run the reproducer for a target OSS-Fuzz/Arvo project with a given input."
    )
    parser.add_argument(
        "--target", type=Path, required=True, help="Path to the target directory."
    )
    parser.add_argument(
        "--harness",
        type=Path,
        required=True,
        help="Path to the harness file in the output directory.",
    )
    parser.add_argument(
        "--input_file",
        type=Path,
        required=True,
        help="Path to the input file.",
    )
    parser.add_argument(
        "--arvo",
        action="store_true",
        required=False,
        help="If True, the target is an Arvo project, which requires special handling.",
    )
    parser.add_argument(
        "--no_runner",
        action="store_true",
        required=False,
        help="If True, the run_fuzzer command will not be used to start the fuzzer.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    target = args.target
    harness = args.harness
    input_file = args.input_file
    is_arvo = args.arvo

    if not target.is_dir():
        logger.error(f"Target project directory {target} does not exist.")
        sys.exit(1)
    if not harness.is_file():
        logger.error(f"Harness file {harness} does not exist.")
        sys.exit(1)
    if not input_file.is_file():
        logger.error(f"Input file {input_file} does not exist.")
        sys.exit(1)

    log_file = LOG_DIR / f"aijon_reproducer_{target.name}.log"
    logger.add(log_file, rotation="10 MB", level="TRACE")
    try:
        sanity_check_project(target)
    except Exception as e:
        logger.error(f"Error occurred: {e}")
        sys.exit(1)

    try:
        run_reproducer(
            target_project=target,
            harness_path=harness,
            input_file=input_file,
            is_arvo_target=is_arvo,
            no_runner=args.no_runner,
        )
    except RuntimeError as e:
        logger.warning(f"Could not run reproducer for {input_file}: {e}")
    else:
        logger.success(
            f"Reproducer completed for {target.name}. Logs are saved to {log_file}"
        )
