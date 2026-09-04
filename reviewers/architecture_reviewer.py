"""
Architecture Reviewer
AI-based reviewer focusing on software design patterns and principles.
"""
from typing import List, Dict, Any
from reviewers.base_reviewer import BaseReviewer
from models.finding import Finding
from anthropic import Anthropic
import os
import json
from ai_reviewer import DEFAULT_MODEL


class ArchitectureReviewer(BaseReviewer):
    """
    Architecture and design-focused AI reviewer.

    Uses Claude AI to analyze:
    - Design patterns (Factory, Strategy, Observer, etc.)
    - SOLID principles violations
    - Coupling and cohesion
    - Abstraction levels
    - Separation of concerns
    - Dependency injection
    - Interface design
    """

    def __init__(self, api_key: str = None):
        """
        Initialize architecture reviewer.

        Args:
            api_key: Anthropic API key (defaults to ANTHROPIC_API_KEY env var)
        """
        super().__init__(
            name='architecture',
            focus='Software design patterns, SOLID principles, and system architecture',
            severity_levels={'high', 'medium', 'low'}
        )
        self.api_key = api_key or os.getenv('ANTHROPIC_API_KEY')
        if self.api_key:
            self.client = Anthropic(api_key=self.api_key)
        else:
            self.client = None

    def is_relevant(self, filename: str) -> bool:
        """
        Determine if file should be architecture reviewed.

        Args:
            filename: File path

        Returns:
            True if file is source code (not tests, not config)
        """
        # Review source files that likely contain architecture
        return (
            self._is_source_file(filename) and
            not self._is_test_file(filename) and
            not self._is_config_file(filename)
        )

    def review(self, files: List[Dict[str, Any]], context: Dict[str, str]) -> List[Finding]:
        """
        Perform AI-based architecture review.

        Args:
            files: List of file dictionaries with 'filename' and 'content'
            context: Project context from ContextLoader

        Returns:
            List of Finding objects with architecture issues
        """
        if not self.client:
            return []  # Skip if no API key

        relevant_files = [f for f in files if self.is_relevant(f.get('filename', ''))]
        if not relevant_files:
            return []

        # Build prompt
        prompt = self._build_architecture_prompt(relevant_files, context)

        try:
            message = self.client.messages.create(
                model=DEFAULT_MODEL,
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}]
            )

            # Parse AI response into findings
            findings = self._parse_ai_response(message.content[0].text, relevant_files)
            return findings

        except Exception as e:
            # If AI review fails, return empty (don't block other reviewers)
            print(f"Architecture review failed: {e}")
            return []

    def _build_architecture_prompt(self, files: List[Dict[str, Any]], context: Dict[str, str]) -> str:
        """
        Build architecture review prompt.

        Args:
            files: Files to review
            context: Project context

        Returns:
            Formatted prompt
        """
        # Summarize files
        file_summaries = []
        for file_data in files[:5]:  # Limit to 5 files for prompt size
            filename = file_data.get('filename', '')
            content = file_data.get('content', '')
            lines = content.count('\n') + 1

            file_summaries.append(f"**{filename}** ({lines} lines)")

        # Get project context
        project_conventions = context.get('claude_md', '')
        context_section = f"\n## Project Conventions\n{project_conventions}" if project_conventions else ""

        prompt = f"""You are a senior software architect performing a design review.

Focus on architecture and design patterns:
- SOLID principles (Single Responsibility, Open/Closed, Liskov, Interface Segregation, Dependency Inversion)
- Design patterns (Factory, Strategy, Observer, etc.)
- Coupling and cohesion
- Abstraction levels
- Dependency injection
- Separation of concerns

Files to Review ({len(files)} files):
{chr(10).join(file_summaries)}
{context_section}

Provide 2-4 specific, actionable architecture recommendations in JSON format:
[
  {{
    "filename": "path/to/file.py",
    "line": 42,
    "severity": "high|medium|low",
    "issue": "High coupling detected",
    "description": "Brief description of the issue",
    "recommendation": "How to fix it"
  }}
]

Focus on the most impactful issues. Be concise."""

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
            # Look for JSON array in the response
            start_idx = response.find('[')
            end_idx = response.rfind(']') + 1

            if start_idx >= 0 and end_idx > start_idx:
                json_str = response[start_idx:end_idx]
                issues = json.loads(json_str)

                for issue in issues:
                    finding = Finding(
                        tool='ai-architecture',
                        type='quality',
                        severity=issue.get('severity', 'medium'),
                        issue=issue.get('issue', 'Architecture concern'),
                        description=issue.get('description', ''),
                        filename=issue.get('filename', files[0].get('filename', '')),
                        line=issue.get('line'),
                        code=None,
                        matched=None,
                        recommendation=issue.get('recommendation', ''),
                        reviewer='architecture',
                        origin='introduced',
                        verified=False,
                        confidence='medium',  # AI findings need verification
                    )
                    findings.append(finding)

        except json.JSONDecodeError:
            # If JSON parsing fails, return empty
            pass

        return findings

    def _build_prompt(self, files: List[Dict[str, Any]], context: Dict[str, str]) -> str:
        """Override base method for architecture-specific prompts."""
        return self._build_architecture_prompt(files, context)
