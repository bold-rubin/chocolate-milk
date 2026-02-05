import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path

from loguru import logger

from aijon.aijon_lib import run_fuzzer, sanity_check_project

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
    parser.add_argument(
        "--no_runner",
        action="store_true",
        required=False,
        help="If True, the run_fuzzer command will not be used to start the fuzzing.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        required=False,
        default=86400,
        help="How long to run the fuzzer",
    )
    parser.add_argument(
        "--hybrid",
        action="store_true",
        required=False,
        help="If True, enables seed sharing between AFL++ and AIJON (not compatible with --no_runner).",
    )
    parser.add_argument(
        "--ignore_errors",
        action="store_true",
        required=False,
        help="If True, ignore errors during fuzzing (for debugging purposes).",
    )
    parser.add_argument(
        "--wait_on_err",
        action="store_true",
        required=False,
        help="If True, wait indefinitely on error (for debugging purposes).",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    target = args.target
    output = args.output
    harness = args.harness
    is_arvo = args.arvo
    no_runner = args.no_runner
    timeout = args.timeout
    hybrid = args.hybrid

    if not target.is_dir():
        logger.error(f"Target project directory {target} does not exist.")
        sys.exit(1)
    if not output.is_dir():
        logger.error(f"Output directory {output} does not exist.")
        sys.exit(1)
    if not (output / harness).is_file():
        logger.error(f"Harness {harness} does not exist in output directory {output}.")
        sys.exit(1)

    if hybrid and no_runner:
        logger.error("--hybrid and --no_runner cannot be used together.")
        sys.exit(1)

    log_file = LOG_DIR / f"aijon_fuzzer_{target.name}.log"
    logger.add(log_file, rotation="10 MB", level="TRACE")
    try:
        sanity_check_project(target)
    except Exception as e:
        logger.error(f"Error occurred: {e}")
        sys.exit(1)

    try:
        run_fuzzer(
            target_project=target,
            harness_path=output / harness,
            is_arvo_target=is_arvo,
            no_runner=no_runner,
            timeout=timeout,
            hybrid=hybrid,
        )
    except RuntimeError as e:
        if args.ignore_errors:
            logger.warning(f"Encountered an error but ignoring it: {e}")
            sys.exit(0)
        elif args.wait_on_err:
            logger.error("Fuzzing encountered a runtime error, waiting indefinitely")
            import time

            while True:
                time.sleep(86400)
        else:
            logger.error("Fuzzing encountered a runtime error")
            sys.exit(1)

    logger.success(f"Fuzzing completed for {target.name}. Logs are saved to {log_file}")
