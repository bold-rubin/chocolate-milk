import os
import shutil
from pathlib import Path
from subprocess import CalledProcessError, run, PIPE, TimeoutExpired
from tempfile import TemporaryDirectory, NamedTemporaryFile

from loguru import logger
from yaml import safe_load

CUR_DIR = Path(__file__).parent.parent.resolve()
CLANG_INDEXER_DOCKERFILE = CUR_DIR / "Dockerfile.builder"
AIJON_RUNNER_DOCKERFILE = CUR_DIR / "Dockerfile.runner"
INVSCOV_DOCKERFILE = CUR_DIR / "Dockerfile.invscov"


def make_docker_env_file(
    yaml_file: Path, env_file_path: Path, aijon_runner: bool = False, allow_list_path: Path | None = None
):
    """Creates a Docker environment file with necessary variables.

    Args:
        env_file_path (Path): The path where the environment file will be created.
    """

    project_config = safe_load(yaml_file.read_text(encoding="utf-8"))
    env_vars: dict[str, str] = {
        "AFL_PATH": "/src/aflplusplus",
        "FUZZING_ENGINE": "afl",
        "CC": "afl-clang-fast",
        "CXX": "afl-clang-fast++",
        "SANITIZER": "address",
        # "AFL_LLVM_IJON": "1",
        "FUZZING_LANGUAGE": str(project_config.get("language", "c")),
    }
    if aijon_runner:
        env_vars["CC"] = "/src/shellphish/afl-clang-fast"
        env_vars["CXX"] = "/src/shellphish/afl-clang-fast++"

    # if allow_list_path:
    #     env_vars["AFL_LLVM_ALLOWLIST"] = "/afl_allow_list.txt"

    with open(env_file_path, "w", encoding="utf-8") as env_file:
        for key, value in env_vars.items():
            env_file.write(f"{key}={value}\n")
    logger.debug(f"Created Docker environment file at {env_file_path}")


def make_fuzzer_env_file(
    yaml_file: Path, env_file_path: Path, timeout: int = 86400, symbolize: bool = False, manager: bool = True
):
    """Creates a fuzzer environment file with necessary variables.

    Args:
        yaml_file (Path): The path to the project YAML file.
        env_file_path (Path): The path where the environment file will be created.
    """
    env_vars: dict[str, str] = {
        "FUZZING_ENGINE": "afl",
        "SANITIZER": "address",
        "RUN_FUZZER_MODE": "interactive",
        "ASAN_OPTIONS": f"abort_on_error=1:detect_leaks=0:symbolize={'1' if symbolize else '0'}:allocator_may_return_null=1:alloc_dealloc_mismatch=0",
        "MSAN_OPTIONS": "exit_code=86:symbolize=0",
        "AFL_IGNORE_PROBLEMS": "1",
        # "AFL_ENABLE_IJON": "1",
        # "AFL_FUZZER_ARGS": f"-V {timeout} -m none",
    }
    if manager:
        env_vars["AFL_FUZZER_ARGS"] = "-M aijon"
        env_vars["__AFL_IJON_ENABLED"] = "1"
    else:
        env_vars["AFL_FUZZER_ARGS"] = "-S aflpp"
        env_vars["__AFL_IJON_ENABLED"] = "0"

    with open(env_file_path, "w", encoding="utf-8") as env_file:
        for key, value in env_vars.items():
            env_file.write(f"{key}={value}\n")
    logger.debug(f"Created fuzzer environment file at {env_file_path}")


def build_oss_fuzz_project_image(target_path: Path):
    """Builds the Docker image for the specified OSS-Fuzz project.

    Args:
        target_path (Path): The path to the OSS-Fuzz project directory (eg: /path/to/oss-fuzz/projects/<project_name>).
    """
    project_name: str = target_path.name
    helper_script: Path = (target_path.parent.parent / "infra" / "helper.py").resolve()

    command = [
        "python",
        str(helper_script),
        "build_image",
        "--cache",
        "--no-pull",
        str(project_name),
    ]
    logger.debug(f"Running command: {' '.join(command)}")
    try:
        retcode = run(command, check=True, stdout=None, stderr=PIPE)
    except CalledProcessError as e:
        logger.error(f"Failed to build image for {target_path}. Error: {e}: {e.stderr.decode()}")
        raise RuntimeError(f"Failed to build image for {target_path}. Error: {e}")

    assert retcode.returncode == 0, f"Failed to build image for {target_path}. Error: {retcode.returncode=}"
    logger.success(f"✅✅ Docker image built for {project_name}")


def build_arvo_project_image(target_path: Path) -> None:
    cur_dir = os.getcwd()
    os.chdir(target_path)
    cmd = ["docker", "build", "-t", f"arvo:{target_path.name}-vul", "."]
    logger.debug(f"Running command: {' '.join(cmd)}")
    try:
        retcode = run(cmd, check=True, stdout=None, stderr=PIPE)
    except CalledProcessError as e:
        logger.error(f"Failed to build Arvo project image for {target_path}. Error: {e}: {e.stderr.decode()}")
        raise RuntimeError(f"Failed to build Arvo project image for {target_path}. Error: {e}")

    assert retcode.returncode == 0, (
        f"Failed to build Arvo project image for {target_path}. Error: {retcode.returncode=}"
    )
    logger.success(f"✅✅ Arvo project Docker image built for {target_path.name}")
    os.chdir(cur_dir)


def copy_source_code_dir(
    project_path: Path, destination: Path, source_dir_path: str, is_arvo_target: bool = False
) -> None:
    """Copies the source code directory from a Docker container to a local destination.

    Args:
        project_path (Path): Path to the OSS-Fuzz project directory (eg: /path/to/oss-fuzz/projects/<project_name>).
        destination (Path): Path to the destination directory where the source code will be copied.
        source_dir_path (str): The working directory inside the Docker container where the source code is located.
        is_arvo_target (bool): If True, the target is an Arvo project,

    Raises:
        RuntimeError: If the Docker commands fail to create, copy, or remove the temporary container.
    """
    project_name = project_path.name
    container_name = f"{project_name}-temp-container"

    logger.debug(f"Removing any existing container with name {container_name}")
    run(
        ["docker", "rm", "-f", container_name],
        check=False,
        stdout=None,
        stderr=None,
    )

    # Start a temporary container
    docker_image_name = f"gcr.io/oss-fuzz/{project_name}" if not is_arvo_target else f"arvo:{project_name}-vul"
    command = [
        "docker",
        "create",
        "--name",
        container_name,
        docker_image_name,
    ]
    logger.debug(f"Running command: {' '.join(command)}")
    try:
        run(command, check=True, stdout=None, stderr=PIPE)
    except CalledProcessError as e:
        logger.error(f"Failed to create temporary container for {project_name}. Error: {e}: {e.stderr.decode()}")
        raise RuntimeError(f"Failed to create temporary container for {project_name}. Error: {e}")

    command = [
        "docker",
        "cp",
        f"{project_name}-temp-container:{source_dir_path}",
        str(destination),
    ]
    logger.debug(f"Running command: {' '.join(command)}")
    try:
        run(command, check=True, stdout=None, stderr=PIPE)
    except CalledProcessError as e:
        logger.error(f"Failed to copy source code for {project_name}. Error: {e}: {e.stderr.decode()}")
        raise RuntimeError(f"Failed to copy source code for {project_name}. Error: {e}")

    # Remove the temporary container
    command = [
        "docker",
        "rm",
        "-f",
        container_name,
    ]
    logger.debug(f"Running command: {' '.join(command)}")
    try:
        run(command, check=True, stdout=None, stderr=None)
    except CalledProcessError as e:
        logger.error(f"Failed to remove temporary container for {project_name}. Error: {e}: {e.stderr.decode()}")
        raise RuntimeError(f"Failed to remove temporary container for {project_name}. Error: {e}")

    logger.success(f"✅ Source code for {project_name} copied to {destination}")


def build_clang_indexer_image(project_name: str, is_arvo_target: bool = False) -> str:
    """Builds the Clang Indexer Docker image for the specified OSS-Fuzz project.

    Args:
        project_name (str): The name of the OSS-Fuzz project (eg: "libpng", "zlib", etc.).

    Returns:
        str: The name of the built Docker image for the Clang Indexer.
    """
    docker_image_name = f"{project_name}-clang-indexer" if not is_arvo_target else f"arvo:{project_name}-clang-indexer"
    base_image_name = f"gcr.io/oss-fuzz/{project_name}" if not is_arvo_target else f"arvo:{project_name}-vul"
    command = [
        "docker",
        "build",
        "--build-arg",
        f"BASE_IMAGE={base_image_name}",
        "-t",
        docker_image_name,
        "-f",
        str(CLANG_INDEXER_DOCKERFILE),
        str(CUR_DIR),
    ]

    logger.debug(f"Running command: {' '.join(command)}")
    try:
        retcode = run(command, check=True, stdout=None, stderr=PIPE)
    except CalledProcessError as e:
        logger.error(f"Failed to build Clang Indexer image for {project_name}. Error: {e}: {e.stderr.decode()}")
        raise RuntimeError(f"Failed to build Clang Indexer image for {project_name}. Error: {e}")

    assert retcode.returncode == 0, (
        f"Failed to build Clang Indexer image for {project_name}. Error: {retcode.returncode=}"
    )
    logger.success(f"✅✅ Clang Indexer Docker image {docker_image_name} built for {project_name}")
    return docker_image_name


def run_clang_indexer(oss_fuzz_project_path: Path, destination: Path, is_arvo_target: bool = False) -> None:
    """Runs the Clang Indexer on the specified OSS-Fuzz project.

    Args:
        oss_fuzz_project_path (Path): Path to the OSS-Fuzz project directory (/path/to/oss-fuzz/projects/<project_name>)
        destination (Path): Path to the directory where the output will be saved.
        is_arvo_target (bool): If True, the target is an Arvo project, which requires special handling.
    """
    logger.info(f"Running Clang Indexer for OSS-Fuzz project: {oss_fuzz_project_path.name}")

    if is_arvo_target:
        logger.info(f"Building Arvo target: {oss_fuzz_project_path.name}")
        build_arvo_project_image(oss_fuzz_project_path)
        project_name = safe_load((oss_fuzz_project_path / "project.yaml").read_text(encoding="utf-8")).get(
            "shellphish_project_name", ""
        )
    else:
        logger.debug(f"Building Docker image for OSS-Fuzz project: {oss_fuzz_project_path.name}")
        build_oss_fuzz_project_image(oss_fuzz_project_path)
        project_name = oss_fuzz_project_path.name

    logger.debug(f"Building Clang Indexer Docker image for project: {oss_fuzz_project_path.name}")
    docker_image_name = build_clang_indexer_image(oss_fuzz_project_path.name, is_arvo_target=is_arvo_target)

    logger.debug("Building the project with Clang Indexer")
    with TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        make_docker_env_file(oss_fuzz_project_path / "project.yaml", temp_path / ".docker.env")
        (temp_path / "work").mkdir(parents=True, exist_ok=True)
        (temp_path / "out").mkdir(parents=True, exist_ok=True)
        command: list[str] = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{temp_path}/work:/work",
            "-v",
            f"{temp_path}/out:/out",
            "--env-file",
            str(temp_path / ".docker.env"),
            docker_image_name,
            "bash",
            "-c",
            "'compile'",
        ]

        logger.debug(f"Running command: {' '.join(command)}")
        try:
            retcode = run(command, check=True, stdout=None, stderr=PIPE)
        except CalledProcessError as e:
            logger.error(
                f"Failed to run Clang Indexer for {oss_fuzz_project_path.name}. Error: {e} {e.stderr.decode()}"
            )
            raise RuntimeError(f"Failed to run Clang Indexer for {oss_fuzz_project_path.name}. Error: {e}")

        assert retcode.returncode == 0, (
            f"Failed to run Clang Indexer for {oss_fuzz_project_path.name}. Error: {retcode.returncode=}"
        )

        logger.success("✅ Clang Indexer completed successfully")

        # Move the output to the specified destination
        logger.info(f"Moving output from {temp_path / 'out'} to {destination / 'out'}")
        shutil.move(temp_path / "out", destination / "out")

    workdir: str = (destination / "out" / "workdir.txt").read_text(encoding="utf-8").strip()
    if workdir == "/src":
        workdir = f"/src/{project_name}"
    # Copy the source directory to the destination
    copy_source_code_dir(oss_fuzz_project_path, destination / "src", workdir, is_arvo_target=is_arvo_target)


def build_aijon_runner_image(project_name: str, is_arvo_target: bool = False) -> str:
    """Builds the Aijon Runner Docker image for the specified OSS-Fuzz project.

    Args:
        project_name (str): The name of the OSS-Fuzz project (eg: "libpng", "zlib", etc.).

    Returns:
        str: The name of the built Docker image for the Clang Indexer.
    """
    docker_image_name = f"{project_name}-aijon-runner" if not is_arvo_target else f"arvo:{project_name}-aijon-runner"
    base_image_name = f"gcr.io/oss-fuzz/{project_name}" if not is_arvo_target else f"arvo:{project_name}-vul"
    command = [
        "docker",
        "build",
        "--build-arg",
        f"BASE_IMAGE={base_image_name}",
        "-t",
        docker_image_name,
        "-f",
        str(AIJON_RUNNER_DOCKERFILE),
        str(CUR_DIR),
    ]

    logger.debug(f"Running command: {' '.join(command)}")
    try:
        retcode = run(command, check=True, stdout=None, stderr=PIPE)
    except CalledProcessError as e:
        logger.error(f"Failed to build AIJON runner image for {project_name}. Error: {e}: {e.stderr.decode()}")
        raise RuntimeError(f"Failed to build AIJON runner image for {project_name}. Error: {e}")

    assert retcode.returncode == 0, (
        f"Failed to build AIJON runner image for {project_name}. Error: {retcode.returncode=}"
    )
    logger.success(f"✅✅ AIJON runner docker image {docker_image_name} built for {project_name}")
    return docker_image_name


def build_aijon_invscov_runner_image(project_name: str, is_arvo_target: bool = False) -> str:
    """Builds the Aijon Runner Docker image for the specified OSS-Fuzz project.

    Args:
        project_name (str): The name of the OSS-Fuzz project (eg: "libpng", "zlib", etc.).

    Returns:
        str: The name of the built Docker image for the Clang Indexer.
    """
    docker_image_name = (
        f"{project_name}-aijon-invscov-runner" if not is_arvo_target else f"arvo:{project_name}-aijon-invscov-runner"
    )
    base_image_name = f"gcr.io/oss-fuzz/{project_name}" if not is_arvo_target else f"arvo:{project_name}-vul"
    command = [
        "docker",
        "build",
        "--build-arg",
        f"BASE_IMAGE={base_image_name}",
        "-t",
        docker_image_name,
        "-f",
        str(INVSCOV_DOCKERFILE),
        str(CUR_DIR),
    ]

    logger.debug(f"Running command: {' '.join(command)}")
    try:
        retcode = run(command, check=True, stdout=None, stderr=None)
    except CalledProcessError as e:
        logger.error(f"Failed to build AIJON Invscov runner image for {project_name}. Error: {e}: {e.stderr.decode()}")
        raise RuntimeError(f"Failed to build AIJON Invscov runner image for {project_name}. Error: {e}")

    assert retcode.returncode == 0, (
        f"Failed to build AIJON Invscov runner image for {project_name}. Error: {retcode.returncode=}"
    )
    logger.success(f"✅✅ AIJON Invscov runner docker image {docker_image_name} built for {project_name}")
    return docker_image_name


def run_build_fuzzer_command(
    target_path: Path, source_dir: Path | None = None, allow_list_path: Path | None = None
) -> str | None:
    """
    Run the build_fuzzer command to build the fuzzer for the target.

    Args:
        target_path (Path): The path to the OSSFuzz project directory.
    Returns:
        str: The name of the container created for the fuzzer.
    """
    logger.debug(f"Building Docker image for OSS-Fuzz project: {target_path.name}")
    build_oss_fuzz_project_image(target_path)

    docker_image_name = f"gcr.io/oss-fuzz/{target_path.name}"

    logger.info(f"📦📦 Building fuzzer for {target_path.name}...")
    make_docker_env_file(
        target_path / "project.yaml", target_path / ".docker.env", aijon_runner=False, allow_list_path=allow_list_path
    )
    command: list[str] = [
        "docker",
        "run",
        "--rm",
    ]

    if allow_list_path:
        command.extend(["-v", f"{allow_list_path}:/afl_allow_list.txt"])

    remote_source_path = f"/src/{target_path.name}"
    command.extend(
        [
            "-v",
            "/src/shellphish/aflplusplus:/src/aflplusplus",
            "-v",
            f"{source_dir}:{remote_source_path}",
            "-v",
            f"{target_path}/work:/work",
            "-v",
            f"{target_path}/out:/out",
            "--env-file",
            str(target_path / ".docker.env"),
            docker_image_name,
            "bash",
            "-c",
            "'compile'",
        ]
    )

    logger.debug(f"Running command: {' '.join(command)}")
    try:
        retcode = run(command, check=True, stdout=None, stderr=PIPE)
    except CalledProcessError as e:
        logger.warning(f"Failed to run AIJON runner for {target_path.name}. Error: {e}: {e.stderr.decode()}")
        return e.stderr.decode()

    if retcode.returncode != 0:
        logger.warning(
            f"Failed to run AIJON runner for {target_path.name}. Error: {retcode.returncode=} {retcode.stderr.decode()}"
        )
        return retcode.stderr.decode()

    logger.success(f"✅ AIJON runner completed successfully for {target_path.name}")
    return None


def run_arvo_build_fuzzer_command(
    target_path: Path, source_dir: Path | None = None, allow_list_path: Path | None = None
) -> str | None:
    """
    Build the fuzzer for an Arvo target.

    Args:
        target_path (Path): The path to the Arvo project directory.
        source_dir (Path | None): Optional path to the source directory.

    Returns:
        str: The name of the container created for the fuzzer.
    """
    logger.debug(f"Building Docker image for Arvo target: {target_path.name}")
    build_arvo_project_image(target_path)

    docker_image_name = f"arvo:{target_path.name}-vul"

    logger.info(f"📦📦 Building fuzzer for Arvo target {target_path.name}...")
    shellphish_project_name = safe_load((target_path / "project.yaml").read_text(encoding="utf-8")).get(
        "shellphish_project_name", ""
    )
    if not shellphish_project_name:
        raise ValueError(f"shellphish_project_name not found in project.yaml for {target_path}")
    project_name = target_path.name
    make_docker_env_file(
        target_path / "project.yaml", target_path / ".docker.env", aijon_runner=True, allow_list_path=allow_list_path
    )
    command: list[str] = [
        "docker",
        "run",
        "--rm",
        "--env-file",
        str(target_path / ".docker.env"),
    ]
    if source_dir:
        command.extend(["-v", f"{source_dir}:/src/{shellphish_project_name}"])
    if allow_list_path:
        command.extend(["-v", f"{allow_list_path}:/afl_allow_list.txt"])
    command.extend(
        [
            "-v",
            "/src/shellphish/aflplusplus:/src/aflplusplus",
            "-v",
            f"{target_path}/work:/work",
            "-v",
            f"{target_path}/out:/out",
            docker_image_name,
            "bash",
            "-c",
            "'compile'",
        ]
    )
    logger.debug(f"Running command: {' '.join(command)}")
    try:
        retcode = run(command, check=True, stdout=None, stderr=PIPE)
    except CalledProcessError as e:
        logger.warning(f"Failed to build fuzzer for Arvo target {project_name}. Error: {e}: {e.stderr.decode()}")
        return e.stderr.decode()

    if retcode.returncode != 0:
        logger.warning(
            f"Failed to build fuzzer for Arvo target {project_name}. Error: {retcode.returncode=}: {retcode.stderr.decode()}"
        )
        return retcode.stderr.decode()

    logger.success(f"✅✅ Fuzzer built for Arvo target {project_name}")
    return None


def run_fuzzer_command(
    target_path: Path,
    harness_path: Path,
    is_arvo_target: bool = False,
    no_runner: bool = False,
    timeout: int = 86400,
    manager: bool = True,
    return_early: bool = False,
) -> None:
    """
    Run the fuzzer command for the target project.

    Args:
        target_path (Path): The path to the OSSFuzz project directory.
        harness_path (Path): The path to the harness file.
        is_arvo_target (bool): If True, the target is an Arvo project.
        no_runner (bool): If True, the run_fuzzer command will not be used to start the fuzzing.
        timeout (int): The timeout for the fuzzer run in seconds. Default is 86400 seconds (24 hours).
    """
    make_fuzzer_env_file(target_path / "project.yaml", target_path / ".fuzzer.env", timeout=timeout, manager=manager)
    logger.info(f"Running fuzzer for target project: {target_path.name}")
    project_name = target_path.name
    docker_image_name = "gcr.io/oss-fuzz-base/base-runner"
    docker_container_name = f"{project_name}-{harness_path.name}-fuzzer-runner"
    manager_container_name = docker_container_name
    if manager is False:
        docker_container_name = f"{project_name}-{harness_path.name}-fuzzer-runner-worker"
    command = [
        "docker",
        "run",
        "--workdir",
        "/out",
        "--env-file",
        str(target_path / ".fuzzer.env"),
        "-v",
        f"{harness_path.parent}:/out",
        "--name",
        docker_container_name,
        "-t",
        docker_image_name,
    ]

    # If return_early is True, run in detached mode; otherwise use --rm
    if return_early:
        command.insert(2, "-d")  # Insert detached mode flag
    else:
        command.insert(2, "--rm")  # Insert auto-remove flag

    if not no_runner:
        command.append("run_fuzzer")
        command.append(harness_path.name)
    else:
        command.append(f"/out/{harness_path.name}")
    logger.debug(f"Running command: {' '.join(command)}")

    if return_early:
        # Start container in detached mode and return immediately
        try:
            retcode = run(command, check=True, stdout=None, stderr=PIPE)
            logger.success(
                f"✅ Fuzzer container {docker_container_name} started in background for {project_name} {manager=}"
            )
            return
        except CalledProcessError as e:
            logger.error(f"Failed to start fuzzer container for {project_name}. Error: {e}: {e.stderr.decode()}")
            raise RuntimeError(f"Failed to start fuzzer container for {project_name}. Error: {e}")

    # Original blocking behavior when return_early is False
    try:
        retcode = run(command, check=True, stdout=None, stderr=PIPE, timeout=timeout)
    except CalledProcessError as e:
        logger.error(f"Failed to run fuzzer for {project_name}. Error: {e}: {e.stderr.decode()}")
        raise RuntimeError(f"Failed to run fuzzer for {project_name}. Error: {e}")
    except TimeoutExpired as e:
        logger.info(f"Fuzzer run timed out for {project_name} after {timeout} seconds")
        run(["docker", "rm", "-f", docker_container_name], check=False, stdout=None, stderr=None)
    # assert retcode.returncode == 0, (
    #     f"Failed to run fuzzer for {project_name}. Error: {retcode.returncode=}:{retcode.stderr.decode()}"
    # )
    if manager is False:
        # Remove the manager container if it exists
        run(["docker", "rm", "-f", manager_container_name], check=False, stdout=None, stderr=None)
    logger.success(f"✅ Fuzzer run completed successfully for {project_name}")


def run_showmap_command(
    target_path: Path,
    outdir: Path,
    input_file: Path,
    harness_path: Path,
    is_arvo_target: bool = False,
) -> None:
    """
    Run the showmap command for the target project.

    Args:
        target_path (Path): The path to the OSSFuzz project directory.
        outdir (Path): The path to the output directory.
        input_file (Path): The path to the input file.
        is_arvo_target (bool): If True, the target is an Arvo project.
    """
    make_fuzzer_env_file(target_path / "project.yaml", target_path / ".fuzzer.env")
    logger.info(f"Running showmap for target project: {target_path.name}")
    project_name = target_path.name
    docker_image_name = "gcr.io/oss-fuzz-base/base-runner"

    stdout_file = outdir / "showmap.stdout"

    with NamedTemporaryFile(mode="wb+", delete=True) as temp_input_file:
        temp_input_path = Path(temp_input_file.name)
        temp_input_path.write_bytes(input_file.read_bytes())

        command = [
            "docker",
            "run",
            "--rm",
            "--workdir",
            "/out",
            "--env-file",
            str(target_path / ".fuzzer.env"),
            "-v",
            f"{str(outdir)}:/out",
            "-v",
            f"{str(temp_input_path)}:/queue_inp",
            "-t",
            docker_image_name,
        ]

        if is_arvo_target:
            command.extend(
                [
                    "/out/showmap.sh",
                ]
            )
        else:
            command.extend(
                [
                    "afl-showmap",
                    "-r",
                    "-o",
                    "/out/map_output",
                    "--",
                    f"/out/{harness_path.name}",
                    "/queue_inp",
                ]
            )
        logger.debug(f"Running command: {' '.join(command)}")
        try:
            retcode = run(command, check=True, stdout=PIPE, stderr=PIPE)
        except CalledProcessError as e:
            logger.error(f"Failed to run showmap for {project_name}. Error: {e}: {e.stderr.decode()}")
            raise RuntimeError(f"Failed to run showmap for {project_name}. Error: {e}")
        assert retcode.returncode == 0, (
            f"Failed to run showmap for {project_name}. Error: {retcode.returncode=}:{retcode.stderr.decode()}"
        )
        stdout_file.write_bytes(retcode.stdout)
        logger.success(f"✅ Showmap run completed successfully for {project_name}")


def run_reproducer_command(
    target_path: Path,
    harness_path: Path,
    input_file: Path,
    is_arvo_target: bool = False,
    no_runner: bool = False,
) -> None:
    """
    Run the reproducer command for the target project.

    Args:
        target_path (Path): The path to the OSSFuzz project directory.
        harness_path (Path): The path to the harness file.
        input_file (Path): The path to the input file.
        is_arvo_target (bool): If True, the target is an Arvo project.
        no_runner (bool): If True, the run_fuzzer command will not be used to start the fuzzer.
    """
    make_fuzzer_env_file(target_path / "project.yaml", target_path / ".fuzzer.env", symbolize=True)
    logger.info(f"Running reproducer for target project: {target_path.name}")
    project_name = target_path.name
    docker_image_name = "gcr.io/oss-fuzz-base/base-runner"

    with NamedTemporaryFile(mode="wb+", delete=True) as temp_input_file:
        temp_input_path = Path(temp_input_file.name)
        temp_input_path.write_bytes(input_file.read_bytes())

        command = [
            "docker",
            "run",
            "--rm",
            "--workdir",
            "/out",
            "--env-file",
            str(target_path / ".fuzzer.env"),
            "-v",
            f"{str(harness_path.parent)}:/out",
            "-v",
            f"{str(temp_input_path)}:/crashing_inp",
            "-t",
            docker_image_name,
            "bash",
            "-lc",
        ]
        if not no_runner:
            if is_arvo_target:
                command.append("/out/fuzzer /crashing_inp 2>/out/asan.log")
            else:
                command.append(f"/out/{harness_path.name} /crashing_inp 2>/out/asan.log")
        else:
            command.append("/out/reproducer.sh 2>/out/asan.log")
        logger.debug(f"Running command: {' '.join(command)}")
        try:
            _ = run(command, check=False, stdout=PIPE, stderr=PIPE, timeout=300)
        except CalledProcessError as e:
            logger.error(f"Failed to run reproducer for {project_name}. Error: {e}: {e.returncode}:{e.stderr.decode()}")
            raise RuntimeError(f"Failed to run reproducer for {project_name}. Error: {e}")
        except TimeoutExpired as e:
            logger.warning(f"Reproducer run timed out for {project_name}. Error: {e}")
            return
        logger.debug(f"Reproducer stdout written to {harness_path.parent / 'asan.log'}")
        logger.success(f"✅ Reproducer run completed successfully for {project_name}")
