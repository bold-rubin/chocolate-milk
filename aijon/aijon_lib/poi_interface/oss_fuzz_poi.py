import json
import yaml
from pathlib import Path

from loguru import logger

from .poi_poi import POI


class OSSFuzzPOI(POI):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def add_poi(self, target_file: Path):
        """Add a Point of Interest (POI) to the POI list.

        Args:
            optimal_targets_json (Path): The path to the optimal targets JSON file.
        """
        assert target_file.is_file(), (
            f"File {target_file} does not exist."
        )
        if target_file.suffix == ".json":
            target_functions = json.loads(target_file.read_text())
            self.parse_poi_from_optimal_targets(target_functions)
        elif target_file.suffix == ".yaml":
            target_functions = yaml.load(target_file.read_text(), Loader=yaml.FullLoader)
            self.parse_poi_from_codeql_report(target_functions)


    def parse_poi_from_codeql_report(self, codeql_report: dict):
        """
        Parse vulnerability locations from YAML data.
        
        Args:
            codeql_report: Dictionary loaded from YAML file
            
        Returns:
            List of dictionaries containing file and startLine for each location
        """
    
        if 'vulnerabilities' in codeql_report:
            # Use a set for efficient duplicate checking (O(1) lookup instead of O(n))
            seen_indices = {poi['function_index_key'] for poi in self._pois}
            
            for vulnerability in codeql_report['vulnerabilities']:
                if 'locations' in vulnerability:
                    for location in vulnerability['locations']:
                        func_index = self.get_funcindex_from_codeql_report(location.get('file'), location.get('startLine'))
                        if func_index and func_index not in seen_indices:
                            self._pois.append(
                                {
                                    "function_index_key": func_index,
                                    "vulnerability_name": vulnerability.get('name'),
                                }
                            )
                            seen_indices.add(func_index)
                        if len(self._pois) > 100:
                            logger.warning("More than 100 POIs found, stopping further processing.")
                            break
    
    def get_funcindex_from_codeql_report(self, file: Path, start_line: int) -> str | None:
        return self.get_funcindex_from_json("", str(file), start_line)


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
        return [
            x
            for x in outdir.iterdir()
            if x.is_file()
            and POI.is_elf_file(x)
            and POI.contains_symbol("LLVMFuzzerTestOneInput", x)
        ]

    def get_funcindex_from_json(
        self, func_name: str, file_path: str, line_number: int
    ) -> str | None:
        """
        Extract the function index key from the diff hunk
        """
        func_indices = []
        for index_key in self.function_resolver.find_by_filename(file_path):
            function_index = self.function_resolver.get(index_key)
            if function_index is None:
                continue
            if function_index.start_line <= line_number <= function_index.end_line:
                logger.trace(
                    f"Found function index {index_key} for file {file_path} at line {line_number}"
                )
                func_indices.append(index_key)

        logger.trace(f"Found {len(func_indices)} function indices")
        foo = filter(lambda x: file_path in x, func_indices)
        fixed_indices = list(
            set(
                self.function_resolver.find_matching_indices(list(foo), scope="focus")[
                    0
                ].values()
            )
        )
        if len(fixed_indices) < 1:
            # If we don't find any function indices, we return None
            return None

        return fixed_indices[0]

    def parse_poi_from_optimal_targets(
        self,
        optimal_targets: dict,
    ):
        for function_obj in optimal_targets.get("functions", []):
            if function_obj.get("is_reached", False) is False:
                logger.debug(
                    f"Skipping function {function_obj.get('raw_function_name', '')} "
                    "as it is not reached."
                )
                continue
            filename: str = str(Path(function_obj.get("function_filename", "")).resolve())
            start_line = int(function_obj.get("source_line_begin", 0))
            end_line = int(function_obj.get("source_line_end", 0))
            if start_line == 0 or end_line == 0:
                logger.warning(
                    f"Skipping function {function_obj.get('raw_function_name', '')} "
                    f"due to invalid start or end line: {start_line}, {end_line}"
                )
                continue
            func_index = self.get_funcindex_from_json(
                function_obj.get("raw_function_name", ""),
                filename,
                start_line,
            )

            if func_index is None:
                continue

            if len(self._pois) > 100:
                logger.warning("More than 100 POIs found, stopping further processing.")
                break
            self._pois.append(
                {
                    "function_index_key": func_index,
                    "runtime_coverage_percent": function_obj.get(
                        "runtime_coverage_percent", 0
                    ),
                    "accummulated_complexity": function_obj.get(
                        "accummulated_complexity", 0
                    ),
                }
            )
