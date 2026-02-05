import os
import sys
import json
import shutil
import threading
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from subprocess import run, CalledProcessError, TimeoutExpired, PIPE
from typing import Any, Callable, Generator

import networkx as nx
import yaml
from loguru import logger
from project_utils.function_resolver import (
    FunctionResolver,
    LocalFunctionResolver,
    function_index_to_source_location,
)
from project_utils.models.indexer import FunctionIndex

BASE_DIR = Path(__file__).parent.parent.parent.parent
IDA_SCRIPT = BASE_DIR / "tools" / "gen_callgraph.py"


class TimeoutError(Exception):
    """Custom exception for function timeout."""

    pass


def with_timeout(seconds: int) -> Callable:
    """Thread-safe decorator to add timeout to a function.

    This implementation uses threading.Timer, making it safe for multi-threaded
    environments and cross-platform compatible (works on Unix, Linux, macOS, and Windows).

    Args:
        seconds (int): Timeout duration in seconds.

    Returns:
        Callable: The decorated function with timeout capability.

    Raises:
        TimeoutError: If the function execution exceeds the timeout duration.
    """

    def decorator(func: Callable) -> Callable:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            result_container: list[Any] = []
            exception_container: list[Exception] = []

            def target():
                try:
                    result_container.append(func(*args, **kwargs))
                except Exception as e:
                    exception_container.append(e)

            thread = threading.Thread(target=target, daemon=True)
            thread.start()
            thread.join(timeout=seconds)

            if thread.is_alive():
                # Thread is still running after timeout
                # Note: We can't forcefully kill the thread, but we can return early
                raise TimeoutError(f"Function call timed out after {seconds} seconds")

            if exception_container:
                raise exception_container[0]

            if result_container:
                return result_container[0]

            return None

        return wrapper

    return decorator


class POI(object):
    def __init__(
        self,
        full_function_indices_path: Path,
        target_functions_json_dir: Path,
        function_resolver: FunctionResolver | None = None,
        callgraph_json: Path | None = None,
    ):
        """Initialize the POI object with the function indices and target functions info.

        Args:
            full_function_indices_path (Path): The path to the full function indices JSON file.
            target_functions_json_dir (Path): The directory containing target functions JSON files.
            function_resolver (FunctionResolver, optional): An instance of FunctionResolver. Defaults to None.
            callgraph_json (Path, optional): The path to the call graph JSON file. Defaults to None.
        """
        self._pois: list[dict[str, str]] = []
        self._mode: str = "normal"
        self.full_function_indices: Path = full_function_indices_path
        self.target_functions_json_dir: Path = target_functions_json_dir

        self._function_resolver: FunctionResolver | None = None

        if function_resolver is not None:
            self._function_resolver = function_resolver
        else:
            self._setup_local_function_resolver()

        self.harness_cfg: defaultdict[str, nx.DiGraph] = defaultdict(nx.DiGraph)
        if callgraph_json is not None:
            data = json.loads(callgraph_json.read_text())
            for harness_name in data:
                self.harness_cfg[harness_name] = POI.gen_callgraph_from_file(
                    yaml_file=Path(data[harness_name])
                )

    def _setup_local_function_resolver(self):
        if self._function_resolver is not None:
            logger.debug("Using existing LocalFunctionResolver")
            return
        assert self.full_function_indices.is_file(), (
            f"File {self.full_function_indices} does not exist."
        )
        assert self.target_functions_json_dir.is_dir(), (
            f"Directory {self.target_functions_json_dir} does not exist."
        )
        logger.debug(
            f"Using LocalFunctionResolver with indices at {self.full_function_indices} and functions at {self.target_functions_json_dir}"
        )
        self._function_resolver = LocalFunctionResolver(
            functions_index_path=str(self.full_function_indices),
            functions_jsons_path=str(self.target_functions_json_dir),
        )
        assert self._function_resolver is not None, (
            "Function resolver could not be initialized."
        )

    @property
    def function_resolver(self) -> FunctionResolver:
        """Get the function resolver instance.

        Returns:
            FunctionResolver: The function resolver instance.
        """
        if self._function_resolver is None:
            self._setup_local_function_resolver()
        return self._function_resolver

    @property
    def empty(self) -> bool:
        return len(self._pois) == 0

    def set_mode(self, mode: str):
        self._mode = mode

    @property
    def mode(self) -> str:
        return self._mode

    def add_poi(self, poi: Path):
        raise NotImplementedError("This method should be implemented in a subclass.")

    def remove_all_pois(self):
        self._pois = []

    def get_next_poi(self) -> Generator[dict, None, None]:
        for poi in self._pois:
            yield poi

    def get_all_pois(self) -> list:
        """
        A function that retrieves all POIs.

        Returns:
            list: A list of all POIs.
        """
        return self._pois

    def get_function_index_from_poi(self, function_index_str: str) -> FunctionIndex:
        """
        A function that retrieves the function index from a given string.

        Args:
            function_index_str (str): The function index string.

        Returns:
            FunctionIndex: The function index object.
        """
        try:
            resolved_function_index_key = self.function_resolver.find_matching_index(
                function_index_str,
                scope="focus",
                can_include_self=False,
                can_include_build_generated=False,
            )
        except:
            logger.warning(
                f"Could not find matching index key for {function_index_str}"
            )
            resolved_function_index_key = None

        if resolved_function_index_key is not None:
            try:
                resolved_function_index = self.function_resolver.get(
                    resolved_function_index_key
                )
            except:
                logger.warning(
                    f"Could not resolve function index key {resolved_function_index_key}"
                )
                resolved_function_index = None
            logger.debug(f"Using function index key: {resolved_function_index_key}")
            logger.debug(f"{resolved_function_index.is_generated_during_build=}")
            return resolved_function_index

        logger.debug(
            f"Finding source locations from function index key: {function_index_str}"
        )
        try:
            resolved_function_index = self.function_resolver.get(function_index_str)
        except:
            logger.warning(f"Could not resolve function index key {function_index_str}")
            resolved_function_index = None

        if resolved_function_index is not None:
            logger.debug(f"Using function index key: {function_index_str}")
            logger.debug(f"{resolved_function_index.is_generated_during_build=}")
            return resolved_function_index

        src_location = function_index_to_source_location(
            function_index_str, resolved_function_index
        )
        try:
            candidates = self.function_resolver.resolve_source_location(
                src_location,
                num_top_matches=3,
                allow_build_generated=False,
                focus_repo_only=True,
            )
        except:
            logger.warning(f"Could not resolve source location for {src_location}")
            candidates = []

        if not candidates:
            logger.warning(f"Could not find candidate indices for {function_index_str}")
            raise ValueError(
                f"Function index {function_index_str} could not be resolved."
            )
        try:
            actual_key = candidates[0][0]
        except IndexError:
            logger.warning(
                f"Could not resolve function index for {function_index_str}: {candidates}"
            )
            raise ValueError(
                f"Function index {function_index_str} could not be resolved."
            )
        logger.debug(f"Resolved function index {function_index_str} to {actual_key}")
        ret_val = None
        try:
            ret_val = self.function_resolver.get(actual_key)
        except:
            logger.warning(f"Could not resolve function index key {actual_key}")
        return ret_val

    def find_harness_binaries(
        self, outdir: Path, project_yaml: Path | None = None
    ) -> list[Path]:
        """Find harness binaries in the output directory.

        Args:
            outdir (Path): Path to the output directory for the OSS Fuzz project.
            project_yaml (Path | None, optional): Path to the project YAML file containing harness information. Defaults to None.

        Returns:
            list[Path]: A list of harness binary paths.
        """
        all_files: list[Path] = []
        yaml_config = yaml.safe_load(project_yaml.read_text())
        if "shellphish_harness_paths" not in yaml_config:
            logger.warning(
                f"No harnesses found in {project_yaml}. Identifying ELF files."
            )
            all_files = [
                x for x in outdir.iterdir() if x.is_file() and POI.is_elf_file(x)
            ]
        else:
            logger.debug(f"Found harnesses in {project_yaml}.")
            all_files = [
                outdir / harness for harness in yaml_config["shellphish_harness_paths"]
            ]
        return all_files

    def analyze_harness_binaries(
        self, outdir: Path, project_yaml: Path, harness_name: str | None = None
    ) -> None:
        """Find the harness binaries in the output directory and generate a callgraph yaml file

        Args:
            outdir (Path): Path to the out directory of the project
            project_yaml (Path): Path to the project YAML file containing harness information.
            harness_name (str | None, optional): Name of the harness to analyze. Defaults to None.
        """
        if self.harness_cfg:
            logger.debug("Harness binaries already analyzed, skipping.")
            return
        yaml_dir: Path = outdir / "callgraph"
        yaml_dir.mkdir(exist_ok=True)
        callgraphs: dict[str, str] = {}
        if not harness_name:
            all_files: list[Path] = self.find_harness_binaries(outdir, project_yaml)
        else:
            all_files: list[Path] = [outdir / harness_name]
        with ProcessPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(
                    POI._parallel_process_harness_file, file, yaml_dir
                ): file
                for file in all_files
            }
            for future in as_completed(futures):
                name, filename = future.result()
                if filename is None:
                    logger.warning(f"Skipping {name} as IDA script failed.")
                    continue
                yaml_file = Path(filename)
                callgraphs[name] = str(yaml_file.resolve())
                logger.debug(
                    f"Generating callgraph for harness {name} from {yaml_file}"
                )
                self.harness_cfg[name] = POI.gen_callgraph_from_file(yaml_file)

        logger.debug(f"Saving callgraphs to {outdir / 'callgraphs.json'}")
        (outdir / "callgraphs.json").write_text(json.dumps(callgraphs, indent=4))

    def get_call_path_to(
        self, sink_funcname: str, timeout_seconds: int = 600
    ) -> list[str]:
        """Generate the call path to a sink function.

        Args:
            sink_funcname (str): The name of the sink function.
            timeout_seconds (int, optional): Maximum time in seconds to spend finding paths. Defaults to 30.

        Returns:
            list[str]: A list of function names representing the call path to the sink function.

        Raises:
            TimeoutError: If the function execution exceeds the timeout duration.
        """

        def _find_paths():
            call_path = [sink_funcname]
            for harness in self.harness_cfg:
                cg = self.harness_cfg[harness]
                start_node = (
                    "LLVMFuzzerTestOneInput"
                    if "LLVMFuzzerTestOneInput" in cg
                    else "main"
                )
                sink_node = sink_funcname
                if start_node in cg:
                    logger.debug(
                        f"Finding paths from {start_node} to {sink_node} in call graph for harness {harness}."
                    )
                    try:
                        paths = nx.all_simple_paths(
                            cg, source=start_node, target=sink_node
                        )
                        for path in paths:
                            call_path.extend(path)
                    except nx.NetworkXNoPath:
                        logger.debug(f"No path found from {start_node} to {sink_node}")
                else:
                    logger.debug(
                        f"Finding longest paths to {sink_node} in call graph for harness {harness}."
                    )
                    paths = self.find_longest_paths(cg, sink_node)
                    for path in paths:
                        call_path.extend(path)
            return list(set(call_path))

        # Apply timeout decorator
        timed_find_paths = with_timeout(timeout_seconds)(_find_paths)
        try:
            return timed_find_paths()
        except TimeoutError:
            logger.warning(
                f"Finding call paths to {sink_funcname} timed out after {timeout_seconds} seconds. "
                f"Returning partial results."
            )
            return [sink_funcname]

    def find_longest_paths(self, cg: nx.DiGraph, sink_node: str) -> list[list[str]]:
        """Find the longest paths to the sink node in the call graph.

        Args:
            cg (nx.DiGraph): The call graph.
            sink_node (str): The name of the sink node.

        Returns:
            list[list[str]]: A list of longest paths to the sink node.
        """
        longest_paths = [sink_node]
        if sink_node not in cg:
            logger.warning(f"Sink node {sink_node} not found in call graph.")
            return [longest_paths]
        worklist = list(cg.predecessors(sink_node))
        seen = set(worklist)
        longest_paths.extend(worklist)
        while worklist:
            current_node = worklist.pop()
            predecessors = list(cg.predecessors(current_node))
            longest_paths.extend(predecessors)
            for pred in predecessors:
                if pred not in seen:
                    seen.add(pred)
                    worklist.append(pred)
        return [longest_paths]

    @staticmethod
    def _parallel_process_harness_file(
        file: Path, yaml_dir: Path
    ) -> tuple[str, str | None]:
        try:
            yaml_file = POI.run_idascript(file, yaml_dir)
        except ValueError:
            # This happens when the IDA_PATH is not set
            # Default to angr
            yaml_file = POI.run_angrscript(file, yaml_dir)
        return file.name, str(yaml_file.resolve()) if yaml_file else None

    @staticmethod
    def is_elf_file(file: Path) -> bool:
        with file.open("rb") as f:
            return f.read(4) == b"\x7fELF"

    @staticmethod
    def contains_symbol(symbol: str, file: Path) -> bool:
        """Check if the given ELF file contains the specified symbol.

        Args:
            symbol (str): The symbol to check for in the ELF file.
            file (Path): The path to the ELF file.

        Returns:
            bool: True if the symbol is found, False otherwise.
        """
        cmd = ["nm", "-D", str(file)]
        try:
            output = run(cmd, capture_output=True, text=True, check=True)
            return any(symbol in line for line in output.stdout.splitlines())
        except CalledProcessError as e:
            logger.error(f"Error running nm on {file}: {e}")
            return False

    @staticmethod
    def run_idascript(file: Path, yaml_dir: Path) -> Path | None:
        """Run an IDA script on the given file and return the path to the generated YAML file.

        Args:
            file (Path): The path to the file to analyze.

        Returns:
            Path: The path to the generated YAML file.
        """
        ida_path = os.environ.get("IDA_PATH")
        if ida_path is None:
            raise ValueError("IDA_PATH environment variable is not set.")
        idat_path = Path(ida_path) / "idat64"
        assert idat_path.is_file(), f"IDA executable not found at {idat_path}"
        cmd = [
            str(idat_path),
            "-A",
            f"-S{str(IDA_SCRIPT)}",
            str(file),
        ]
        logger.debug(f"Running IDA script with command: {' '.join(cmd)}")
        try:
            retcode = run(cmd, check=True, timeout=3600, stdout=PIPE)
        except Exception as e:
            logger.error(f"Error running IDA script: {e}")
            return None
        except TimeoutExpired as e:
            logger.error(f"IDA script timed out: {e}")
            return None
        assert retcode.returncode == 0, (
            f"IDA script failed with return code {retcode.returncode}. Output: {retcode.stdout.decode()}"
        )
        callgraph_file = Path(f"{file.name}_callgraph.yaml")
        assert callgraph_file.is_file(), (
            "IDA script did not generate callgraph.yaml file."
        )
        logger.debug(f"IDA script generated callgraph file: {callgraph_file}")
        shutil.move(callgraph_file, yaml_dir / f"{file.stem}_callgraph.yaml")
        return yaml_dir / f"{file.stem}_callgraph.yaml"

    @staticmethod
    def run_angrscript(file: Path, yaml_dir: Path) -> Path | None:
        """Run an angr script on the given file and return the path to the generated YAML file.

        Args:
            file (Path): The path to the file to analyze.

        Returns:
            Path: The path to the generated YAML file.
        """
        cmd = [
            sys.executable,
            f"{str(ANGR_SCRIPT)}",
            str(file),
        ]
        logger.debug(f"Running angr script with command: {' '.join(cmd)}")
        try:
            retcode = run(cmd, check=True, timeout=3600, stdout=PIPE)
        except Exception as e:
            logger.error(f"Error running angr script: {e}")
            return None
        except TimeoutExpired as e:
            logger.error(f"angr script timed out: {e}")
            return None
        assert retcode.returncode == 0, (
            f"angr script failed with return code {retcode.returncode}. Output: {retcode.stdout.decode()}"
        )
        callgraph_file = Path(f"{file.name}_callgraph.yaml")
        assert callgraph_file.is_file(), (
            "angr script did not generate callgraph.yaml file."
        )
        logger.debug(f"angr script generated callgraph file: {callgraph_file}")
        shutil.move(callgraph_file, yaml_dir / f"{file.stem}_callgraph.yaml")
        return yaml_dir / f"{file.stem}_callgraph.yaml"

    @staticmethod
    def gen_callgraph_from_file(yaml_file: Path) -> nx.DiGraph:
        """Generate a call graph from the given YAML file.

        Args:
            yaml_file (Path): The path to the YAML file containing the call graph data.

        Returns:
            nx.DiGraph: A directed graph representing the call graph.
        """
        assert yaml_file.is_file(), f"YAML file {yaml_file} does not exist."
        callgraph = nx.DiGraph()
        obj = yaml.safe_load(yaml_file.read_text())
        for key in obj:
            for value in obj[key]:
                callgraph.add_edge(key, value)
        return callgraph
