"""
Issue Classifier
Determines whether issues are introduced by the current change or pre-existing.
"""
from typing import Dict, List, Any, Set, Tuple
from pathlib import Path


class IssueClassifier:
    """
    Classifies issues as introduced or pre-existing.

    Uses diff information to determine if an issue's location
    falls within changed lines (introduced) or unchanged lines (pre-existing).
    """

    def __init__(self):
        """Initialize issue classifier."""
        pass

    def classify_issue_origin(self, finding: Dict[str, Any], diff_context: Dict[str, Any]) -> str:
        """
        Determine if issue is introduced or pre-existing.

        Args:
            finding: Finding dictionary with 'filename' and 'line'
            diff_context: Diff information with changed line ranges per file

        Returns:
            'introduced' if in changed lines, 'pre-existing' if in unchanged lines
        """
        filename = finding.get('filename', '')
        line_num = finding.get('line')

        if not filename or line_num is None:
            # No location info, assume introduced
            return 'introduced'

        # Get changed lines for this file
        file_diff = diff_context.get(filename, {})
        changed_lines = file_diff.get('changed_lines', set())

        if not changed_lines:
            # No diff info, assume introduced
            return 'introduced'

        # Check if line is in changed lines
        if line_num in changed_lines:
            return 'introduced'
        else:
            return 'pre-existing'

    def classify_findings(self, findings: List[Dict[str, Any]],
                         diff_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Classify all findings as introduced or pre-existing.

        Args:
            findings: List of finding dictionaries
            diff_context: Diff information

        Returns:
            List of findings with 'origin' field set
        """
        classified = []

        for finding in findings:
            origin = self.classify_issue_origin(finding, diff_context)
            finding['origin'] = origin
            classified.append(finding)

        return classified

    def parse_diff_context(self, diff_text: str) -> Dict[str, Any]:
        """
        Parse git diff output to extract changed line ranges.

        Args:
            diff_text: Git diff output (unified diff format)

        Returns:
            Dictionary mapping filenames to changed line info
        """
        context = {}
        current_file = None

        for line in diff_text.split('\n'):
            # Parse file headers (diff --git a/file b/file)
            if line.startswith('diff --git'):
                parts = line.split()
                if len(parts) >= 4:
                    # Extract filename (remove a/ or b/ prefix)
                    filename = parts[2].lstrip('a/')
                    current_file = filename
                    context[current_file] = {
                        'changed_lines': set(),
                        'hunks': []
                    }

            # Parse unified diff headers (@@ -start,count +start,count @@)
            elif line.startswith('@@') and current_file:
                hunk_info = self._parse_hunk_header(line)
                if hunk_info:
                    context[current_file]['hunks'].append(hunk_info)
                    # Add all lines in the new range as changed
                    start, count = hunk_info['new_start'], hunk_info['new_count']
                    for line_num in range(start, start + count):
                        context[current_file]['changed_lines'].add(line_num)

        return context

    def parse_pr_files(self, pr_files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Parse GitHub PR files to extract changed line ranges.

        GitHub provides 'patch' field with unified diff format.

        Args:
            pr_files: List of file dictionaries from GitHub PR API

        Returns:
            Dictionary mapping filenames to changed line info
        """
        context = {}

        for file_data in pr_files:
            filename = file_data.get('filename', '')
            patch = file_data.get('patch', '')
            status = file_data.get('status', '')

            if not filename:
                continue

            # For new files, all lines are "introduced"
            if status == 'added':
                # Get file size to mark all lines as changed
                additions = file_data.get('additions', 0)
                context[filename] = {
                    'changed_lines': set(range(1, additions + 1)),
                    'hunks': [],
                    'status': 'added'
                }
                continue

            # For deleted files, no lines exist anymore
            if status == 'removed':
                context[filename] = {
                    'changed_lines': set(),
                    'hunks': [],
                    'status': 'removed'
                }
                continue

            # Parse patch to get changed lines
            if patch:
                file_context = self._parse_patch(patch)
                file_context['status'] = status
                context[filename] = file_context

        return context

    def _parse_hunk_header(self, header: str) -> Dict[str, int]:
        """
        Parse unified diff hunk header.

        Format: @@ -old_start,old_count +new_start,new_count @@

        Args:
            header: Hunk header line

        Returns:
            Dictionary with start and count for old and new versions
        """
        import re

        # Extract line range info
        match = re.search(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@', header)
        if not match:
            return None

        old_start = int(match.group(1))
        old_count = int(match.group(2)) if match.group(2) else 1
        new_start = int(match.group(3))
        new_count = int(match.group(4)) if match.group(4) else 1

        return {
            'old_start': old_start,
            'old_count': old_count,
            'new_start': new_start,
            'new_count': new_count,
        }

    def _parse_patch(self, patch: str) -> Dict[str, Any]:
        """
        Parse a patch string to extract changed lines.

        Args:
            patch: Unified diff patch text

        Returns:
            Dictionary with changed_lines set and hunk info
        """
        changed_lines = set()
        hunks = []
        current_line = 0

        for line in patch.split('\n'):
            if line.startswith('@@'):
                hunk_info = self._parse_hunk_header(line)
                if hunk_info:
                    hunks.append(hunk_info)
                    current_line = hunk_info['new_start']
            elif line.startswith('+') and not line.startswith('+++'):
                # Added line
                changed_lines.add(current_line)
                current_line += 1
            elif line.startswith('-') and not line.startswith('---'):
                # Deleted line (don't increment current_line)
                pass
            elif line.startswith(' '):
                # Context line (unchanged)
                current_line += 1

        return {
            'changed_lines': changed_lines,
            'hunks': hunks,
        }

    def get_classification_stats(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Get statistics on classified findings.

        Args:
            findings: List of classified findings

        Returns:
            Dictionary with classification stats
        """
        stats = {
            'total': len(findings),
            'introduced': 0,
            'pre-existing': 0,
            'unknown': 0,
        }

        for finding in findings:
            origin = finding.get('origin', 'unknown')
            if origin in stats:
                stats[origin] += 1
            else:
                stats['unknown'] += 1

        return stats

    def filter_by_origin(self, findings: List[Dict[str, Any]],
                        origin: str) -> List[Dict[str, Any]]:
        """
        Filter findings by origin.

        Args:
            findings: List of findings
            origin: 'introduced' or 'pre-existing'

        Returns:
            Filtered list
        """
        return [f for f in findings if f.get('origin') == origin]
