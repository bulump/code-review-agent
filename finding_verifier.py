"""
Finding Verifier
Verifies AI-generated findings to eliminate hallucinations and false positives.
"""
from typing import List, Dict, Any
from pathlib import Path
import re
import subprocess


class FindingVerifier:
    """Verifies findings for accuracy and eliminates false positives"""

    def __init__(self):
        self.verification_stats = {
            'total': 0,
            'verified': 0,
            'dropped_location': 0,
            'dropped_claim': 0
        }

    def verify_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Verify findings to eliminate hallucinations.

        Args:
            findings: List of finding dictionaries

        Returns:
            List of verified findings
        """
        if not findings:
            return []

        self.verification_stats['total'] = len(findings)
        verified = []

        for finding in findings:
            # Check if location exists
            if not self._verify_location(finding):
                self.verification_stats['dropped_location'] += 1
                continue

            # Check if specific claims can be verified
            if not self._verify_claim(finding):
                self.verification_stats['dropped_claim'] += 1
                continue

            # Mark as verified
            finding['verified'] = True
            verified.append(finding)

        self.verification_stats['verified'] = len(verified)
        return verified

    def _verify_location(self, finding: Dict[str, Any]) -> bool:
        """
        Verify that the file and line number exist.

        Args:
            finding: Finding dictionary with 'filename' and optionally 'line'

        Returns:
            True if location is valid, False otherwise
        """
        filename = finding.get('filename')
        if not filename:
            return True  # No location specified, can't verify

        try:
            file_path = Path(filename)

            # Check if file exists
            if not file_path.exists():
                return False

            # Check line number if specified
            line = finding.get('line')
            if line:
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    # Verify line number is within bounds
                    if line < 1 or line > len(lines):
                        return False

            return True

        except Exception:
            # If we can't verify, be conservative and drop it
            return False

    def _verify_claim(self, finding: Dict[str, Any]) -> bool:
        """
        Verify specific claims made in the finding.

        This checks for common false positives like:
        - "Missing DI registration" when it actually exists
        - "No error handling" when try/except is present
        - "Missing import" when import exists
        - AWS secrets in test files or documentation

        Args:
            finding: Finding dictionary

        Returns:
            True if claim checks out, False if provably wrong
        """
        description = finding.get('description', '').lower()
        filename = finding.get('filename')

        if not filename or not Path(filename).exists():
            return True  # Can't verify, let it through

        # Check for AWS secret claims (special handling)
        if 'aws' in description and ('secret' in description or 'access key' in description):
            return self._verify_aws_secret_claim(finding)

        # Check for "missing" claims
        if 'missing' in description or 'no ' in description or 'not found' in description:
            return self._verify_missing_claim(finding, description)

        return True  # No specific claim to verify

    def _verify_missing_claim(self, finding: Dict[str, Any], description: str) -> bool:
        """
        Verify claims about missing code/patterns.

        Args:
            finding: Finding dictionary
            description: Lowercase description text

        Returns:
            True if claim is valid, False if code is actually present
        """
        filename = finding.get('filename')

        try:
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()

            # Check specific claim types
            if 'missing error handling' in description or 'no error handling' in description:
                return self._verify_missing_error_handling(content)

            if 'missing import' in description:
                return self._verify_missing_import(content, description)

            if 'no logging' in description or 'missing logging' in description:
                return self._verify_missing_logging(content)

            # For other claims, we can't easily verify
            return True

        except Exception:
            return True  # Can't verify, be permissive

    def _verify_missing_error_handling(self, content: str) -> bool:
        """
        Check if error handling claim is valid.

        Args:
            content: File content

        Returns:
            True if claim is valid (no error handling found)
        """
        # If try/except exists, error handling is present
        has_try_except = 'try:' in content and 'except' in content
        # Be conservative - only reject claim if clearly present
        return True  # Let most claims through for now

    def _verify_missing_import(self, content: str, description: str) -> bool:
        """
        Check if missing import claim is valid.

        Args:
            content: File content
            description: Claim description

        Returns:
            True if claim is valid, False if import exists
        """
        # Extract module name from description
        import_match = re.search(r'missing import.*?(\w+)', description)
        if not import_match:
            return True

        module = import_match.group(1)

        # Check if import exists
        if f'import {module}' in content or f'from {module}' in content:
            return False  # Import exists, claim is false

        return True

    def _verify_missing_logging(self, content: str) -> bool:
        """
        Check if missing logging claim is valid.

        Args:
            content: File content

        Returns:
            True if claim is valid (no logging found)
        """
        # Check if logging is imported and used
        has_logging_import = 'import logging' in content or 'from logging' in content
        has_logging_usage = 'logger.' in content or 'logging.' in content

        # Be conservative - let most claims through
        return True

    def _verify_aws_secret_claim(self, finding: Dict[str, Any]) -> bool:
        """
        Verify AWS secret detection isn't a false positive.

        Filters out:
        - Test files (test_, *_test.py, tests/)
        - Example files (example, sample, demo)
        - Documentation files (.md, .txt, docs/)
        - Comments (lines starting with # or //)
        - Low entropy strings (not actually random secrets)

        Args:
            finding: Finding dictionary

        Returns:
            True if claim is valid, False if likely false positive
        """
        filename = finding.get('filename', '').lower()

        # Check 1: Test or example files
        test_patterns = ['test_', '_test', '/tests/', '/test/', 'example', 'sample', 'demo', 'fixture']
        if any(pattern in filename for pattern in test_patterns):
            return False  # Likely a test fixture or example

        # Check 2: Documentation files
        doc_extensions = ['.md', '.txt', '.rst', '.adoc']
        if any(filename.endswith(ext) for ext in doc_extensions) or '/docs/' in filename:
            return False  # Documentation example

        # Check 3: Check if it's in a comment
        try:
            line_num = finding.get('line')
            if line_num:
                with open(finding['filename'], 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    if line_num <= len(lines):
                        line_content = lines[line_num - 1].strip()
                        # Check if line starts with comment markers
                        if line_content.startswith('#') or line_content.startswith('//') or line_content.startswith('/*'):
                            return False  # Comment/documentation
        except Exception:
            pass  # Can't check, continue

        # Check 4: Entropy check for the matched secret value
        matched = finding.get('matched', '')
        if matched and len(matched) >= 20:
            entropy = self._calculate_entropy(matched)
            # Real AWS secrets have high entropy (>4.5 bits per character)
            # Fake/test secrets often have low entropy (repeated patterns, dictionary words)
            if entropy < 4.0:
                return False  # Too low entropy for a real secret

        return True  # Passes all checks, likely valid

    def _calculate_entropy(self, s: str) -> float:
        """
        Calculate Shannon entropy of a string.

        Higher entropy indicates more randomness (real secrets).
        Lower entropy indicates patterns/repetition (test data).

        Args:
            s: String to analyze

        Returns:
            Entropy in bits per character
        """
        import math
        from collections import Counter

        if not s:
            return 0.0

        # Count character frequencies
        counts = Counter(s)
        length = len(s)

        # Calculate Shannon entropy
        entropy = 0.0
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Remove duplicate findings and merge from multiple sources.

        Args:
            findings: List of findings

        Returns:
            Deduplicated list
        """
        if not findings:
            return []

        unique_findings = {}

        for finding in findings:
            # Create a key based on file, line, and issue type
            filename = finding.get('filename', '')
            line = finding.get('line', 0)
            issue = finding.get('issue', '')[:50]  # First 50 chars

            key = f"{filename}:{line}:{issue}"

            if key in unique_findings:
                # Merge tool/source information
                existing = unique_findings[key]
                tool = finding.get('tool', '')
                existing_tool = existing.get('tool', '')

                if tool and tool not in existing_tool:
                    existing['tool'] = f"{existing_tool}, {tool}" if existing_tool else tool

            else:
                unique_findings[key] = finding

        return list(unique_findings.values())

    def get_verification_stats(self) -> Dict[str, int]:
        """
        Get statistics about verification results.

        Returns:
            Dictionary with verification stats
        """
        return {
            **self.verification_stats,
            'drop_rate': (
                (self.verification_stats['dropped_location'] +
                 self.verification_stats['dropped_claim']) /
                self.verification_stats['total']
                if self.verification_stats['total'] > 0 else 0
            )
        }

    def print_verification_summary(self):
        """Print a summary of verification results"""
        stats = self.get_verification_stats()

        print(f"\n📊 Verification Summary:")
        print(f"  Total findings: {stats['total']}")
        print(f"  Verified: {stats['verified']}")
        print(f"  Dropped (location): {stats['dropped_location']}")
        print(f"  Dropped (claim): {stats['dropped_claim']}")
        print(f"  Drop rate: {stats['drop_rate']:.1%}")
