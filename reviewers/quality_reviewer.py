"""
Quality Reviewer
Wraps existing quality_analyzer for Phase 2 multi-reviewer architecture.
"""
from typing import List, Dict, Any
from reviewers.base_reviewer import BaseReviewer
from models.finding import Finding
from quality_analyzer import QualityAnalyzer


class QualityReviewer(BaseReviewer):
    """
    Code quality-focused reviewer.

    Wraps the existing QualityAnalyzer (complexity, maintainability metrics)
    and converts results to Finding objects with proper attribution.

    Focus areas:
    - Cyclomatic complexity
    - Function/file length
    - Missing docstrings
    - Code smells (magic numbers, TODO comments)
    - Language-specific issues (var usage, console.log, etc.)
    """

    def __init__(self):
        """Initialize quality reviewer."""
        super().__init__(
            name='quality',
            focus='Code quality, maintainability, and best practices',
            severity_levels={'high', 'medium', 'low'}
        )
        self.analyzer = QualityAnalyzer()

    def is_relevant(self, filename: str) -> bool:
        """
        Determine if file should be quality reviewed.

        Args:
            filename: File path

        Returns:
            True if file is source code (including tests)
        """
        # Review all source files (including tests)
        return self._is_source_file(filename)

    def review(self, files: List[Dict[str, Any]], context: Dict[str, str]) -> List[Finding]:
        """
        Perform quality review using existing quality analyzer.

        Args:
            files: List of file dictionaries with 'filename' and 'content'
            context: Project context (not used by quality analyzer)

        Returns:
            List of Finding objects with quality issues
        """
        findings = []

        for file_data in files:
            filename = file_data.get('filename', '')
            content = file_data.get('content', '')

            if not self.is_relevant(filename):
                continue

            # Run quality analyzer
            result = self.analyzer.analyze_file(filename, content)

            # Extract issues from result dict
            issues = result.get('issues', [])

            # Convert to Finding objects
            for issue in issues:
                finding = Finding(
                    tool=issue.get('tool', 'quality-analyzer'),
                    type='quality',
                    severity=issue.get('severity', 'medium'),
                    issue=issue.get('issue', 'unknown'),
                    description=issue.get('description', ''),
                    filename=filename,
                    line=issue.get('line'),
                    code=issue.get('code'),
                    matched=issue.get('matched'),
                    recommendation=issue.get('recommendation', 'Review and refactor for better maintainability'),
                    reviewer='quality',
                    origin='introduced',  # Will be classified later
                    verified=False,
                    confidence='high',  # Metrics are generally accurate
                )
                findings.append(finding)

        return findings

    def get_summary(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Get quality findings summary.

        Args:
            findings: List of findings from this reviewer

        Returns:
            Summary dictionary
        """
        severity_counts = {'high': 0, 'medium': 0, 'low': 0}
        issue_types = {}

        for finding in findings:
            severity = finding.severity.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

            issue_type = finding.issue
            issue_types[issue_type] = issue_types.get(issue_type, 0) + 1

        # Find most common issues
        top_issues = sorted(issue_types.items(), key=lambda x: x[1], reverse=True)[:5]

        return {
            'total_issues': len(findings),
            'high': severity_counts['high'],
            'medium': severity_counts['medium'],
            'low': severity_counts['low'],
            'top_issues': top_issues,
            'files_analyzed': len(set(f.filename for f in findings)),
        }
