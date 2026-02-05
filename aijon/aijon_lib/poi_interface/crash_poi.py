import re
from pathlib import Path

from loguru import logger

from .poi_poi import POI


class CrashPOI(POI):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def add_poi(self, crash_report: Path):
        """Add a Point of Interest (POI) to the POI list.

        Args:
            crash_report (Path): The path to the Crash report.
        """
        assert crash_report.is_file(), f"File {crash_report} does not exist."
        self._block_leaders: list[str] = []
        self._block_leaders_call_path: dict[str, list[str]] = {}

        self.parse_poi_from_crash_report(crash_report)

    def get_call_path_to(self, sink_funcname: str) -> list[str]:
        call_path: list[str] = []
        if (
            len(self.harness_cfg) == 1
            and "LLVMFuzzerTestOneInput" not in list(self.harness_cfg.values())[0]
        ):
            if "main" in list(self.harness_cfg.values())[0]:
                call_path.append("main")
        # if sink_funcname not in self._block_leaders:
        #     return call_path
        # return call_path + [sink_funcname]
        return (
            call_path
            + [sink_funcname]
            + self._block_leaders_call_path.get(sink_funcname, [])
        )

    def get_funcindex_from_backtrace(
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

    def parse_poi_from_crash_report(self, report: Path) -> None:
        """Parse the patch to extract Points of Interest (POIs).

        Args:
            report (Path): The path to the crash report.

        Returns:
            dict: A dictionary representing the POI extracted from the patch.
        """
        sanitizer_pattern = re.compile(
            r"(?:^==\d+==.*?)(?=\n\n|$)",
            re.DOTALL | re.MULTILINE | re.VERBOSE,
        )

        block_pattern = r"(.*\n)?(    #0 .*(?:\n(?!\s*$).*)*?)\n\s*\n"
        line_pattern = r"#\d+\s+[^\s]+\s+in\s+(.+?)\s+(/\S+:\d+)"
        content = report.read_text(encoding="utf-8")
        matches = re.findall(block_pattern, content)

        actual_error = sanitizer_pattern.findall(content)
        if not actual_error:
            # Probably UBSan
            actual_error = re.findall(r"^.* runtime error: .*", content)
        actual_error_str = "\n".join(actual_error).strip()

        # For assertion errors and stuff
        if "deadly signal" in actual_error_str:
            content_lines = content.split("\n")
            for idx in range(1, len(content_lines)):
                if "libFuzzer: deadly signal" in content_lines[idx]:
                    actual_error_str = content_lines[idx - 1]
                    break

        error_summary = re.search(r"^SUMMARY:.*", content, re.MULTILINE)

        seen_func_indices: set(str) = set()
        first_leader = None
        for block in matches:
            leader = None
            line_matches = re.findall(line_pattern, block[1])
            for func, loc in line_matches:
                if "LLVMFuzzerTestOneInput" in func:
                    break
                elif "__libc_start_main" in func:
                    break

                try:
                    filepath, line_number, _ = loc.rsplit(":", 2)
                except ValueError:
                    continue
                func_index = self.get_funcindex_from_backtrace(
                    func, Path(filepath).name, int(line_number)
                )

                if func_index is None:
                    continue
                elif func_index in seen_func_indices:
                    continue
                seen_func_indices.add(func_index)
                poi_obj = {
                    "function_index_key": func_index,
                    "error_summary": error_summary.group(0) if error_summary else None,
                    "error_str": actual_error_str,
                    "backtrace": block,
                }
                funcname = self.function_resolver.get(func_index).funcname
                if leader is None:
                    leader = func_index
                    self._block_leaders.append(funcname)
                    self._block_leaders_call_path[funcname] = []
                else:
                    self._block_leaders_call_path[
                        self.function_resolver.get(leader).funcname
                    ].append(funcname)

                if first_leader is None:
                    first_leader = leader
                    poi_obj["function_contains_vulnerability"] = True
                else:
                    poi_obj["function_contains_vulnerability"] = False

                if len(self._pois) < 100:
                    self._pois.append(poi_obj)
                else:
                    logger.warning(
                        "Maximum number of POIs reached. Skipping additional POI."
                    )
