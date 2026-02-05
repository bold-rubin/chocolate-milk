from pathlib import Path

import clang_indexer


def sanity_check_project(target_path: Path) -> None:
    """
    Perform sanity checks on the project directory.

    Args:
        target_path (Path): Path to the OSSFuzz project directory.
    """
    if not target_path.exists() or not target_path.is_dir():
        raise FileNotFoundError(f"Project path {target_path} does not exist.")
    if not (target_path / "Dockerfile").exists():
        raise FileNotFoundError("Dockerfile not found in the project directory.")
    if not (target_path / "build.sh").exists():
        raise FileNotFoundError("build.sh not found in the project directory.")


def build_project(
    target_project: Path,
    target_source: Path,
    allow_list_path: Path | None = None,
    is_arvo_target: bool = False,
) -> str | None:
    if is_arvo_target:
        return clang_indexer.run_arvo_build_fuzzer_command(
            target_path=target_project,
            source_dir=target_source,
            allow_list_path=allow_list_path,
        )
    else:
        return clang_indexer.run_build_fuzzer_command(
            target_path=target_project,
            source_dir=target_source,
            allow_list_path=allow_list_path,
        )


def run_fuzzer(
    target_project: Path,
    harness_path: Path,
    is_arvo_target: bool = False,
    no_runner: bool = False,
    timeout: int = 86400,
    hybrid: bool = False,
) -> None:
    """
    Run the fuzzer for the target project.

    Args:
        target_project (Path): Path to the OSSFuzz project directory.
        harness_path (Path): Path to the harness file.
        is_arvo_target (bool): If True, the target is an Arvo project.
        no_runner (bool): If True, the run_fuzzer command will not be used to start the fuzzing.
        timeout (int): Timeout for the fuzzer execution in seconds.
        hybrid (bool): If True, enables seed sharing between AFL++ and AIJON.
    """
    if hybrid:
        clang_indexer.run_fuzzer_command(
            target_path=target_project,
            harness_path=harness_path,
            is_arvo_target=is_arvo_target,
            no_runner=no_runner,
            timeout=timeout,
            manager=True,
            return_early=True,
        )
        clang_indexer.run_fuzzer_command(
            target_path=target_project,
            harness_path=harness_path,
            is_arvo_target=is_arvo_target,
            no_runner=no_runner,
            timeout=timeout,
            manager=False,
            return_early=False,
        )
    else:
        clang_indexer.run_fuzzer_command(
            target_path=target_project,
            harness_path=harness_path,
            is_arvo_target=is_arvo_target,
            no_runner=no_runner,
            timeout=timeout,
        )


def run_showmap(
    target_project: Path,
    outdir: Path,
    input_file: Path,
    harness_path: Path,
    is_arvo_target: bool = False,
) -> None:
    """Run showmap for the target project.

    Args:
        target_project (Path): Path to the OSSFuzz project directory.
        outdir (Path): Path to the output directory.
        input_file (Path): Path to the input file.
        harness_path (Path): Path to the harness file.
        is_arvo_target (bool, optional): If True, the target is an Arvo project. Defaults to False.
    """
    clang_indexer.run_showmap_command(
        target_path=target_project,
        outdir=outdir,
        input_file=input_file,
        harness_path=harness_path,
        is_arvo_target=is_arvo_target,
    )


def run_reproducer(
    target_project: Path,
    harness_path: Path,
    input_file: Path,
    is_arvo_target: bool = False,
    no_runner: bool = False,
) -> None:
    """
    Run the reproducer for the target project.

    Args:
         target_project (Path): Path to the OSSFuzz project directory.
         harness_path (Path): Path to the harness file.
         input_file (Path): Path to the input file.
         is_arvo_target (bool): If True, the target is an Arvo project.
         no_runner (bool): If True, the run_fuzzer command will not be used to start the fuzzer.
    """
    clang_indexer.run_reproducer_command(
        target_path=target_project,
        harness_path=harness_path,
        input_file=input_file,
        is_arvo_target=is_arvo_target,
        no_runner=no_runner,
    )
