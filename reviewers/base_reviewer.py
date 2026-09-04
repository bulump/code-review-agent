"""
Base Reviewer
Abstract base class for all code reviewers in Phase 2 multi-reviewer architecture.
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Set
from pathlib import Path
from models.finding import Finding


class BaseReviewer(ABC):
    """
    Abstract base class for all reviewers.

    Each reviewer specializes in a specific aspect of code review:
    - SecurityReviewer: Security vulnerabilities
    - QualityReviewer: Code quality and maintainability
    - ArchitectureReviewer: Design patterns, SOLID principles, coupling
    - TestingReviewer: Test coverage, test quality, edge cases
    - NarrativeReviewer: PR coherence, commit story, loose ends (lead reviewer)

    All reviewers must implement:
    - is_relevant(): Determine if a file is relevant to this reviewer
    - review(): Perform the review and return findings
    """

    def __init__(self, name: str, focus: str, severity_levels: Set[str] = None):
        """
        Initialize base reviewer.

        Args:
            name: Reviewer identifier (e.g., 'security', 'quality')
            focus: What this reviewer focuses on (e.g., 'Security vulnerabilities')
            severity_levels: Severity levels this reviewer can produce
        """
        self.name = name
        self.focus = focus
        self.severity_levels = severity_levels or {'critical', 'high', 'medium', 'low'}

    @abstractmethod
    def is_relevant(self, filename: str) -> bool:
        """
        Determine if this file is relevant to this reviewer.

        Args:
            filename: File path to check

        Returns:
            True if this reviewer should review this file
        """
        pass

    @abstractmethod
    def review(self, files: List[Dict[str, Any]], context: Dict[str, str]) -> List[Finding]:
        """
        Perform review and return findings.

        Args:
            files: List of file dictionaries with 'filename' and 'content'
            context: Project context from ContextLoader (CLAUDE.md, REVIEW.md, rules)

        Returns:
            List of Finding objects
        """
        pass

    def build_prompt(self, files: List[Dict[str, Any]], context: Dict[str, str]) -> str:
        """
        Build reviewer-specific prompt for AI-based reviewers.

        Args:
            files: List of files to review
            context: Project context

        Returns:
            Formatted prompt string
        """
        # Default implementation - subclasses can override
        file_summaries = []
        for file_data in files[:10]:  # Limit to 10 files
            file_summaries.append({
                'filename': file_data['filename'],
                'lines': file_data.get('content', '').count('\n') + 1
            })

        prompt = f"""You are a {self.focus} expert performing code review.

Focus: {self.focus}

Files to Review ({len(files)} files):
{file_summaries}

Provide specific, actionable feedback."""

        return prompt

    def _is_source_file(self, filename: str) -> bool:
        """Check if file is a source code file."""
        source_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rs',
            '.rb', '.php', '.cs', '.cpp', '.c', '.h', '.hpp', '.swift',
            '.kt', '.scala', '.sh', '.bash'
        }
        return Path(filename).suffix.lower() in source_extensions

    def _is_test_file(self, filename: str) -> bool:
        """Check if file is a test file."""
        filename_lower = filename.lower()
        return (
            'test_' in filename_lower or
            '_test.' in filename_lower or
            '/tests/' in filename_lower or
            '/test/' in filename_lower or
            '.test.' in filename_lower or
            '.spec.' in filename_lower
        )

    def _is_config_file(self, filename: str) -> bool:
        """Check if file is a configuration file."""
        config_extensions = {
            '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf'
        }
        config_names = {
            'package.json', 'tsconfig.json', 'requirements.txt',
            'Dockerfile', 'docker-compose.yml', '.env', '.gitignore'
        }
        return (
            Path(filename).suffix.lower() in config_extensions or
            Path(filename).name in config_names
        )

    def _is_documentation(self, filename: str) -> bool:
        """Check if file is documentation."""
        doc_extensions = {'.md', '.rst', '.txt', '.adoc'}
        return Path(filename).suffix.lower() in doc_extensions

    def _get_language(self, filename: str) -> str:
        """Determine programming language from filename."""
        extension_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.tsx': 'typescript',
            '.jsx': 'javascript',
            '.java': 'java',
            '.go': 'go',
            '.rs': 'rust',
            '.rb': 'ruby',
            '.php': 'php',
            '.cs': 'csharp',
            '.cpp': 'cpp',
            '.c': 'c',
            '.swift': 'swift',
            '.kt': 'kotlin',
        }
        return extension_map.get(Path(filename).suffix.lower(), 'unknown')

    def __str__(self) -> str:
        """String representation."""
        return f"{self.name.capitalize()}Reviewer({self.focus})"

    def __repr__(self) -> str:
        """Detailed representation."""
        return f"<{self.__class__.__name__} name={self.name!r} focus={self.focus!r}>"
