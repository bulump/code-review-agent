"""
Testing Reviewer
AI-based reviewer focusing on test coverage and test quality.
"""
from typing import List, Dict, Any
from reviewers.base_reviewer import BaseReviewer
from models.finding import Finding
from anthropic import Anthropic
import os
import json
from ai_reviewer import DEFAULT_MODEL


class TestingReviewer(BaseReviewer):
    """
    Testing-focused AI reviewer.

    Uses Claude AI to analyze:
    - Test coverage gaps
    - Test quality (assertions, mocking, fixtures)
    - Edge case coverage
    - Test maintainability
    - Test naming and organization
    - Missing negative tests
    """

    def __init__(self, api_key: str = None):
        """
        Initialize testing reviewer.

        Args:
            api_key: Anthropic API key (defaults to ANTHROPIC_API_KEY env var)
        """
        super().__init__(
            name='testing',
            focus='Test coverage, test quality, and edge case analysis',
            severity_levels={'high', 'medium', 'low'}
        )
        self.api_key = api_key or os.getenv('ANTHROPIC_API_KEY')
        if self.api_key:
            self.client = Anthropic(api_key=self.api_key)
        else:
            self.client = None

    def is_relevant(self, filename: str) -> bool:
        """
        Determine if file should be testing reviewed.

        Args:
            filename: File path

        Returns:
            True if file is a test file or source file that needs testing
        """
        # Review test files and source files
        return self._is_source_file(filename)

    def review(self, files: List[Dict[str, Any]], context: Dict[str, str]) -> List[Finding]:
        """
        Perform AI-based testing review.

        Args:
            files: List of file dictionaries with 'filename' and 'content'
            context: Project context from ContextLoader

        Returns:
            List of Finding objects with testing issues
        """
        if not self.client:
            return []  # Skip if no API key

        # Separate test files from source files
        test_files = [f for f in files if self._is_test_file(f.get('filename', ''))]
        source_files = [f for f in files if self.is_relevant(f.get('filename', '')) and not self._is_test_file(f.get('filename', ''))]

        if not test_files and not source_files:
            return []

        # Build prompt
        prompt = self._build_testing_prompt(test_files, source_files, context)

        try:
            message = self.client.messages.create(
                model=DEFAULT_MODEL,
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}]
            )

            # Parse AI response into findings
            findings = self._parse_ai_response(message.content[0].text, files)
            return findings

        except Exception as e:
            # If AI review fails, return empty
            print(f"Testing review failed: {e}")
            return []

    def _build_testing_prompt(self, test_files: List[Dict[str, Any]],
                             source_files: List[Dict[str, Any]],
                             context: Dict[str, str]) -> str:
        """
        Build testing review prompt.

        Args:
            test_files: Test files
            source_files: Source files
            context: Project context

        Returns:
            Formatted prompt
        """
        test_summary = []
        for test_file in test_files[:3]:
            filename = test_file.get('filename', '')
            content = test_file.get('content', '')
            lines = content.count('\n') + 1
            test_summary.append(f"**{filename}** ({lines} lines)")

        source_summary = []
        for source_file in source_files[:3]:
            filename = source_file.get('filename', '')
            content = source_file.get('content', '')
            lines = content.count('\n') + 1
            source_summary.append(f"**{filename}** ({lines} lines)")

        prompt = f"""You are a testing expert performing a test quality review.

Focus on:
- Test coverage gaps (missing tests for source files)
- Edge cases and boundary conditions
- Negative test cases (error handling)
- Test assertions (strong vs weak)
- Test maintainability and clarity
- Mock/stub usage
- Test naming and organization

Test Files ({len(test_files)} files):
{chr(10).join(test_summary) if test_summary else 'No test files'}

Source Files ({len(source_files)} files):
{chr(10).join(source_summary) if source_summary else 'No source files'}

Provide 2-4 specific testing recommendations in JSON format:
[
  {{
    "filename": "path/to/file.py",
    "line": null,
    "severity": "high|medium|low",
    "issue": "Missing test coverage",
    "description": "Brief description",
    "recommendation": "Add tests for X, Y, Z"
  }}
]

Focus on the most critical testing gaps. Be specific about what needs testing."""

        return prompt

    def _parse_ai_response(self, response: str, files: List[Dict[str, Any]]) -> List[Finding]:
        """
        Parse AI response into Finding objects.

        Args:
            response: AI response text
            files: Files that were reviewed

        Returns:
            List of Finding objects
        """
        findings = []

        try:
            # Try to extract JSON from response
            start_idx = response.find('[')
            end_idx = response.rfind(']') + 1

            if start_idx >= 0 and end_idx > start_idx:
                json_str = response[start_idx:end_idx]
                issues = json.loads(json_str)

                for issue in issues:
                    finding = Finding(
                        tool='ai-testing',
                        type='quality',
                        severity=issue.get('severity', 'medium'),
                        issue=issue.get('issue', 'Testing concern'),
                        description=issue.get('description', ''),
                        filename=issue.get('filename', files[0].get('filename', '') if files else ''),
                        line=issue.get('line'),
                        code=None,
                        matched=None,
                        recommendation=issue.get('recommendation', ''),
                        reviewer='testing',
                        origin='introduced',
                        verified=False,
                        confidence='medium',  # AI findings need verification
                    )
                    findings.append(finding)

        except json.JSONDecodeError:
            pass

        return findings

    def _build_prompt(self, files: List[Dict[str, Any]], context: Dict[str, str]) -> str:
        """Override base method for testing-specific prompts."""
        test_files = [f for f in files if self._is_test_file(f.get('filename', ''))]
        source_files = [f for f in files if not self._is_test_file(f.get('filename', ''))]
        return self._build_testing_prompt(test_files, source_files, context)
