"""
Security Reviewer
Wraps existing security_scanner for Phase 2 multi-reviewer architecture.
"""
from typing import List, Dict, Any
from reviewers.base_reviewer import BaseReviewer
from models.finding import Finding
from security_scanner import SecurityScanner


class SecurityReviewer(BaseReviewer):
    """
    Security-focused reviewer.

    Wraps the existing SecurityScanner (Semgrep, Bandit, custom patterns)
    and converts results to Finding objects with proper attribution.

    Focus areas:
    - SQL injection
    - XSS vulnerabilities
    - Command injection
    - Hardcoded secrets (including AWS credentials)
    - Path traversal
    - Unsafe deserialization
    - Weak cryptography
    """

    def __init__(self):
        """Initialize security reviewer."""
        super().__init__(
            name='security',
            focus='Security vulnerabilities and attack vectors',
            severity_levels={'critical', 'high', 'medium', 'low'}
        )
        self.scanner = SecurityScanner()

    def is_relevant(self, filename: str) -> bool:
        """
        Determine if file should be security reviewed.

        Args:
            filename: File path

        Returns:
            True if file is source code (not test files)
        """
        # Review source files, skip tests (tests often have fake credentials)
        return self._is_source_file(filename) and not self._is_test_file(filename)

    def review(self, files: List[Dict[str, Any]], context: Dict[str, str]) -> List[Finding]:
        """
        Perform security review using existing security scanner.

        Args:
            files: List of file dictionaries with 'filename' and 'content'
            context: Project context (not used by security scanner)

        Returns:
            List of Finding objects with security issues
        """
        findings = []

        for file_data in files:
            filename = file_data.get('filename', '')
            content = file_data.get('content', '')

            if not self.is_relevant(filename):
                continue

            # Run security scanner
            issues = self.scanner.scan_file(filename, content)

            # Convert to Finding objects
            for issue in issues:
                finding = Finding(
                    tool=issue.get('tool', 'security-scanner'),
                    type='security',
                    severity=issue.get('severity', 'medium'),
                    issue=issue.get('issue', 'unknown'),
                    description=issue.get('description', ''),
                    filename=filename,
                    line=issue.get('line'),
                    code=issue.get('code'),
                    matched=issue.get('matched'),
                    recommendation=issue.get('recommendation', ''),
                    reviewer='security',
                    origin='introduced',  # Will be classified later
                    verified=False,  # Will be verified by FindingVerifier
                    confidence=issue.get('confidence', 'high'),
                )
                findings.append(finding)

        return findings

    def get_summary(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Get security findings summary.

        Args:
            findings: List of findings from this reviewer

        Returns:
            Summary dictionary
        """
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        for finding in findings:
            severity = finding.severity.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        return {
            'total_issues': len(findings),
            'critical': severity_counts['critical'],
            'high': severity_counts['high'],
            'medium': severity_counts['medium'],
            'low': severity_counts['low'],
            'has_critical': severity_counts['critical'] > 0,
            'has_high': severity_counts['high'] > 0,
        }
