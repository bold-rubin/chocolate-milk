#!/usr/bin/env python3
"""
ASAN Report Analyzer

This script analyzes ASAN (AddressSanitizer) crash reports to:
1. Extract vulnerability type and function name from stderr files
2. Find matching ASAN reports in other crash files
3. Provide a summary of vulnerability patterns
"""

import os
import re
import sys
import glob
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass


@dataclass
class AsanReport:
    """Data class to hold ASAN report information"""
    vulnerability_type: str
    function_name: str
    file_path: str
    line_number: Optional[int] = None
    source_file: Optional[str] = None
    timestamp: Optional[int] = None


class AsanAnalyzer:
    """Main analyzer class for ASAN reports"""
    
    def __init__(self, project_directory: str):
        self.project_dir = project_directory
        self.stderr_file = None
        self.crash_files = glob.glob(os.path.join(project_directory, "id:*_asan.txt"))
    
    def parse_stderr_report(self) -> Optional[AsanReport]:
        """Parse the stderr file to extract vulnerability information"""
        if not os.path.exists(self.stderr_file):
            print(f"stderr file not found: {self.stderr_file}")
            return None
        
        with open(self.stderr_file, 'r', errors='ignore') as f:
            content = f.read()
        
        # Extract vulnerability type
        vuln_type = self._extract_vulnerability_type(content)
        if not vuln_type:
            return None
        
        # Extract function name from the first stack frame
        function_name = self._extract_function_name(content)
        if not function_name:
            return None
        
        # Extract additional details
        source_file, line_number = self._extract_source_info(content)
        
        return AsanReport(
            vulnerability_type=vuln_type,
            function_name=function_name,
            file_path=self.stderr_file,
            source_file=source_file,
            line_number=line_number
        )
    
    def _extract_vulnerability_type(self, content: str) -> Optional[str]:
        """Extract vulnerability type from ASAN report"""
        # Common ASAN vulnerability patterns
        patterns = [
            r'ERROR: AddressSanitizer: (heap-buffer-overflow)',
            r'ERROR: AddressSanitizer: (heap-use-after-free)',
            r'ERROR: AddressSanitizer: (stack-buffer-overflow)',
            r'ERROR: AddressSanitizer: (stack-overflow)',
            r'ERROR: AddressSanitizer: (global-buffer-overflow)',
            r'ERROR: AddressSanitizer: (use-after-poison)',
            r'ERROR: AddressSanitizer: (double-free)',
            r'ERROR: AddressSanitizer: (SEGV)',
            r'AddressSanitizer:DEADLYSIGNAL',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, content)
            if match:
                if pattern.endswith('DEADLYSIGNAL'):
                    return 'SEGV'  # DEADLYSIGNAL usually indicates SEGV
                return match.group(1)
        
        return None
    
    def _extract_function_name(self, content: str) -> Optional[str]:
        """Extract function name from the first meaningful stack frame"""
        # Look for stack trace lines with function names
        # Pattern: #0 0xaddr in function_name file:line:col
        stack_pattern = r'#\d+\s+0x[0-9a-fA-F]+\s+in\s+([^\s]+)'
        
        matches = re.findall(stack_pattern, content)
        if matches:
            # Skip common interceptor functions and return the first meaningful function
            skip_functions = ['printf_common', 'vfprintf', 'vprintf', 'malloc', 'free', 'strlen']
            for func in matches:
                if func not in skip_functions:
                    return func
            # If all functions are interceptors, return the first one anyway
            return matches[0]
        
        return None
    
    def _extract_source_info(self, content: str) -> Tuple[Optional[str], Optional[int]]:
        """Extract source file and line number information"""
        # Look for source file and line in the summary or stack trace
        source_pattern = r'(/[^\s:]+\.(c|cpp|cc|h|hpp)):(\d+):?\d*'
        
        match = re.search(source_pattern, content)
        if match:
            source_file = match.group(1)
            line_number = int(match.group(3))
            return os.path.basename(source_file), line_number
        
        return None, None
    
    def _extract_timestamp(self, crash_file: str) -> int:
        for part in crash_file.split(','):
            if part.startswith("time"):
                return int(part.split(":")[1])
    
    def parse_crash_files(self) -> List[AsanReport]:
        """Parse all crash files to find matching ASAN reports"""
        crash_reports = []
        
        for crash_file in self.crash_files:
            try:
                with open(crash_file, 'r', errors='ignore') as f:
                    content = f.read()
                
                vuln_type = self._extract_vulnerability_type(content)
                function_name = self._extract_function_name(content)
                timestamp = self._extract_timestamp(crash_file)
                
                if vuln_type and function_name:
                    source_file, line_number = self._extract_source_info(content)
                    
                    report = AsanReport(
                        vulnerability_type=vuln_type,
                        function_name=function_name,
                        file_path=crash_file,
                        source_file=source_file,
                        line_number=line_number,
                        timestamp=timestamp
                    )
                    crash_reports.append(report)
                    
            except Exception as e:
                print(f"Error parsing {crash_file}: {e}")
                continue
        
        return crash_reports
    
    def find_matching_reports(self, stderr_report: AsanReport, crash_reports: List[AsanReport]) -> List[AsanReport]:
        """Find crash reports that match the stderr report"""
        matches = []
        
        for crash_report in crash_reports:
            # Check if vulnerability type and function match
            if (crash_report.vulnerability_type == stderr_report.vulnerability_type and 
                crash_report.function_name == stderr_report.function_name):
                matches.append(crash_report)
        
        return matches
    
    def analyze(self, stderr_file: Path) -> Dict:
        """Main analysis function"""
        self.stderr_file = str(stderr_file)
        result = {
            'project': os.path.basename(self.project_dir),
            'stderr_report': None,
            'matching_crashes': [],
            'all_crashes': [],
            'summary': {}
        }
        
        # Parse stderr report
        stderr_report = self.parse_stderr_report()
        if stderr_report:
            result['stderr_report'] = stderr_report
        
        # Parse all crash files
        crash_reports = self.parse_crash_files()
        result['all_crashes'] = crash_reports
        
        # Find matches
        if stderr_report:
            matching_reports = self.find_matching_reports(stderr_report, crash_reports)
            result['matching_crashes'] = matching_reports
        
        # Generate summary statistics
        result['summary'] = self._generate_summary(stderr_report, crash_reports)
        
        return result
    
    def _generate_summary(self, stderr_report: Optional[AsanReport], crash_reports: List[AsanReport]) -> Dict:
        """Generate summary statistics"""
        summary = {
            'total_crashes': len(crash_reports),
            'vulnerability_types': {},
            'functions': {},
            'matching_count': 0
        }
        
        # Count vulnerability types
        for report in crash_reports:
            vuln_type = report.vulnerability_type
            summary['vulnerability_types'][vuln_type] = summary['vulnerability_types'].get(vuln_type, 0) + 1
        
        # Count functions
        for report in crash_reports:
            func = report.function_name
            summary['functions'][func] = summary['functions'].get(func, 0) + 1
        
        # Count matches with stderr
        if stderr_report:
            for report in crash_reports:
                if (report.vulnerability_type == stderr_report.vulnerability_type and
                    report.function_name == stderr_report.function_name):
                    summary['matching_count'] += 1
        
        return summary


def analyze_project(project_path: str, stderr_file: Path):
    """Analyze a single project directory"""
    print(f"\n{'='*60}")
    print(f"Analyzing project: {os.path.basename(project_path)}")
    print(f"{'='*60}")
    
    analyzer = AsanAnalyzer(project_path)
    result = analyzer.analyze(stderr_file)
    
    # Print stderr report
    if result['stderr_report']:
        stderr_report = result['stderr_report']
        print(f"\nSTDERR REPORT:")
        print(f"  Vulnerability Type: {stderr_report.vulnerability_type}")
        print(f"  Function: {stderr_report.function_name}")
        if stderr_report.source_file:
            print(f"  Source: {stderr_report.source_file}:{stderr_report.line_number}")
    else:
        print("\nNo valid ASAN report found in stderr")
        return
    
    # Print summary
    summary = result['summary']
    print(f"\nSUMMARY:")
    print(f"  Total crash files: {summary['total_crashes']}")
    print(f"  Matching crashes: {summary['matching_count']}")
    
    print(f"\n  Vulnerability types found:")
    for vuln_type, count in sorted(summary['vulnerability_types'].items()):
        print(f"    {vuln_type}: {count}")
    
    print(f"\n  Functions involved:")
    for func, count in sorted(summary['functions'].items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"    {func}: {count}")
    
    # Print matching reports
    if result['matching_crashes']:
        print(f"\nMATCHING CRASH FILES:")
        for i, report in enumerate(result['matching_crashes'][:5], 1):  # Show first 5 matches
            filename = os.path.basename(report.file_path)
            print(f"  {i}. {filename}")
        
        if len(result['matching_crashes']) > 5:
            print(f"  ... and {len(result['matching_crashes']) - 5} more")

        earliest_matching_crash = sorted(result['matching_crashes'], key=lambda x: x.timestamp or 0)[0] if result['matching_crashes'] else None
        if earliest_matching_crash:
            time_in_minutes = ((earliest_matching_crash.timestamp * 1.0) / 1000 ) / 60
            print(f"  Earliest matching crash: {earliest_matching_crash.file_path} at {time_in_minutes}")
    else:
        print(f"\nNo matching crash files found")


def main(project_path: Path, stderr_file: Path):
    """Main function to analyze all projects in the directory"""
    
    # Analyze each project
    try:
        analyze_project(project_path, stderr_file)
    except Exception as e:
        print(f"Error analyzing {project_path}: {e}")
    
    print(f"\n{'='*60}")
    print("Analysis complete!")
    print(f"{'='*60}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python asan_analyzer.py <crash_analysis_directory> <stderr_file>")
        sys.exit(1)
    project_directory = Path(sys.argv[1])
    stderr_file = Path(sys.argv[2])
    assert project_directory.is_dir(), f"Provided path is not a directory: {project_directory}"
    assert stderr_file.is_file(), f"Provided stderr path is not a file: {stderr_file}"
    main(project_directory, stderr_file)
