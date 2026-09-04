"""
Narrative Reviewer
AI-based lead reviewer focusing on PR coherence, scope, and commit story.
"""
from typing import List, Dict, Any
from reviewers.base_reviewer import BaseReviewer
from models.finding import Finding
from anthropic import Anthropic
import os
import json
from ai_reviewer import DEFAULT_MODEL


class NarrativeReviewer(BaseReviewer):
    """
    Narrative-focused AI lead reviewer.

    Acts as the "lead reviewer" analyzing the big picture:
    - PR scope and coherence (does it do one thing well?)
    - Commit story (logical progression)
    - Loose ends (incomplete features, TODOs, commented code)
    - Naming consistency across files
    - Overall code organization
    - Missing documentation
    - Breaking changes and migration paths
    """

    def __init__(self, api_key: str = None):
        """
        Initialize narrative reviewer.

        Args:
            api_key: Anthropic API key (defaults to ANTHROPIC_API_KEY env var)
        """
        super().__init__(
            name='narrative',
            focus='PR scope, coherence, completeness, and overall story',
            severity_levels={'high', 'medium', 'low', 'suggestion', 'nit'}
        )
        self.api_key = api_key or os.getenv('ANTHROPIC_API_KEY')
        if self.api_key:
            self.client = Anthropic(api_key=self.api_key)
        else:
            self.client = None

    def is_relevant(self, filename: str) -> bool:
        """
        Determine if file should be narrative reviewed.

        Args:
            filename: File path

        Returns:
            True for all files (narrative reviewer sees everything)
        """
        # Narrative reviewer sees ALL files to understand the complete picture
        return True

    def review(self, files: List[Dict[str, Any]], context: Dict[str, str]) -> List[Finding]:
        """
        Perform AI-based narrative review.

        Args:
            files: List of file dictionaries with 'filename' and 'content'
            context: Project context from ContextLoader

        Returns:
            List of Finding objects with narrative/coherence issues
        """
        if not self.client:
            return []  # Skip if no API key

        if not files:
            return []

        # Build prompt
        prompt = self._build_narrative_prompt(files, context)

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
            print(f"Narrative review failed: {e}")
            return []

    def _build_narrative_prompt(self, files: List[Dict[str, Any]], context: Dict[str, str]) -> str:
        """
        Build narrative review prompt.

        Args:
            files: All files in the PR
            context: Project context

        Returns:
            Formatted prompt
        """
        # Categorize files
        source_files = [f for f in files if self._is_source_file(f.get('filename', ''))]
        test_files = [f for f in files if self._is_test_file(f.get('filename', ''))]
        config_files = [f for f in files if self._is_config_file(f.get('filename', ''))]
        doc_files = [f for f in files if self._is_documentation(f.get('filename', ''))]

        # File summary
        file_summary = f"""
Source files: {len(source_files)}
Test files: {len(test_files)}
Config files: {len(config_files)}
Documentation: {len(doc_files)}
Total files: {len(files)}
"""

        # List key files
        key_files = []
        for f in files[:10]:
            filename = f.get('filename', '')
            content = f.get('content', '')
            lines = content.count('\n') + 1
            key_files.append(f"- {filename} ({lines} lines)")

        # Get project context
        project_conventions = context.get('claude_md', '')
        context_section = f"\n## Project Context\n{project_conventions[:500]}..." if project_conventions else ""

        prompt = f"""You are the lead code reviewer analyzing the overall PR story and coherence.

{context_section}

## PR Overview
{file_summary}

Key Files:
{chr(10).join(key_files)}

## Review Focus

Analyze the PR from a high level:
1. **Scope**: Does this PR do one thing well, or is it trying to do too much?
2. **Completeness**: Are there loose ends, TODOs, or incomplete features?
3. **Coherence**: Do the changes tell a logical story?
4. **Documentation**: Are breaking changes documented? Is there a migration path?
5. **Organization**: Is the code organized logically across files?
6. **Naming**: Is naming consistent across the codebase?

Provide 2-4 narrative-level recommendations in JSON format:
[
  {{
    "filename": null,
    "line": null,
    "severity": "high|medium|low|suggestion",
    "issue": "PR scope concern",
    "description": "Brief description of the narrative issue",
    "recommendation": "How to improve the overall PR"
  }}
]

Focus on the big picture, not individual code details."""

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
                        tool='ai-narrative',
                        type='quality',
                        severity=issue.get('severity', 'suggestion'),
                        issue=issue.get('issue', 'PR narrative concern'),
                        description=issue.get('description', ''),
                        filename=issue.get('filename') or (files[0].get('filename', '') if files else ''),
                        line=issue.get('line'),
                        code=None,
                        matched=None,
                        recommendation=issue.get('recommendation', ''),
                        reviewer='narrative',
                        origin='introduced',
                        verified=False,
                        confidence='medium',  # AI findings need verification
                    )
                    findings.append(finding)

        except json.JSONDecodeError:
            pass

        return findings

    def _build_prompt(self, files: List[Dict[str, Any]], context: Dict[str, str]) -> str:
        """Override base method for narrative-specific prompts."""
        return self._build_narrative_prompt(files, context)
