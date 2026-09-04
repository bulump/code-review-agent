"""
Context Loader
Loads project-specific context for code reviews (CLAUDE.md, REVIEW.md, rules).
"""
from typing import Dict, List, Set
from pathlib import Path
import os


class ContextLoader:
    """Loads project conventions and review rules"""

    # Files/directories that should never be loaded for context
    # Note: These are checked as path components or filenames, not substrings
    SENSITIVE_FILENAMES = {
        '.env', '.env.local', '.env.production', '.env.development',
        'credentials', 'secrets', 'private.key', 'private.pem',
        '.key', '.pem', '.p12',
        'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
        '.aws', '.ssh', '.gnupg', 'password.txt', 'token',
        '.git', 'config',
        '.boto', '.s3cfg', 'aws-credentials'  # AWS-specific credential files
    }

    SENSITIVE_PATTERNS = {
        'credentials', 'secret', 'password', 'token', 'api_key', 'apikey'
    }

    def __init__(self, repo_path: str = None):
        """
        Initialize context loader with security checks.

        Args:
            repo_path: Path to repository root (defaults to current directory)
        """
        if repo_path:
            self.repo_path = Path(repo_path).resolve()
        else:
            self.repo_path = Path.cwd().resolve()

        # Ensure repo_path is a valid directory
        if not self.repo_path.is_dir():
            raise ValueError(f"Repository path must be a directory: {self.repo_path}")

    def _is_safe_path(self, file_path: Path) -> bool:
        """
        Verify that a file path is safe to read.

        Prevents path traversal attacks and sensitive file access.

        Args:
            file_path: Path to validate

        Returns:
            True if path is safe, False otherwise
        """
        try:
            # Resolve to absolute path
            resolved = file_path.resolve()

            # Check if path is within repo_path (prevents traversal)
            try:
                resolved.relative_to(self.repo_path)
            except ValueError:
                # Path is outside repo_path
                return False

            # Check filename against sensitive filenames
            filename = resolved.name.lower()
            if filename in self.SENSITIVE_FILENAMES:
                return False

            # Check path components against sensitive patterns
            path_parts = [p.lower() for p in resolved.parts]
            for part in path_parts:
                if part in self.SENSITIVE_FILENAMES:
                    return False

            # Check for sensitive patterns in filename
            for pattern in self.SENSITIVE_PATTERNS:
                if pattern in filename:
                    return False

            # Check file extension
            if resolved.suffix.lower() in {'.key', '.pem', '.p12', '.pfx'}:
                return False

            # Must be a file (not a directory or symlink to outside repo)
            if not resolved.is_file():
                return False

            return True

        except Exception:
            # If any error during validation, reject the path
            return False

    def load_context(self, changed_files: List[str] = None) -> Dict[str, str]:
        """
        Load all relevant context for code review.

        Args:
            changed_files: List of changed file paths (optional, for language-specific rules)

        Returns:
            Dictionary with context sections
        """
        context = {}

        # Load CLAUDE.md from repo root or .claude directory
        claude_md = self._load_claude_md()
        if claude_md:
            context['claude_md'] = claude_md

        # Load REVIEW.md if it exists
        review_md = self._load_review_md()
        if review_md:
            context['review_md'] = review_md

        # Load language-specific rules if changed_files provided
        if changed_files:
            rules = self._load_language_rules(changed_files)
            if rules:
                context['language_rules'] = rules

        return context

    def _load_claude_md(self) -> str:
        """
        Load CLAUDE.md from repo root or .claude directory.

        Returns:
            Contents of CLAUDE.md or empty string
        """
        # Check .claude/CLAUDE.md first
        claude_path = self.repo_path / '.claude' / 'CLAUDE.md'
        if self._is_safe_path(claude_path) and claude_path.exists():
            try:
                # Size limit: 100KB for context files
                if claude_path.stat().st_size > 100 * 1024:
                    return ""
                with open(claude_path, 'r', encoding='utf-8') as f:
                    return f.read()
            except Exception:
                pass

        # Fallback to root CLAUDE.md
        claude_path = self.repo_path / 'CLAUDE.md'
        if self._is_safe_path(claude_path) and claude_path.exists():
            try:
                if claude_path.stat().st_size > 100 * 1024:
                    return ""
                with open(claude_path, 'r', encoding='utf-8') as f:
                    return f.read()
            except Exception:
                pass

        return ""

    def _load_review_md(self) -> str:
        """
        Load REVIEW.md with project-specific review rules.

        Returns:
            Contents of REVIEW.md or empty string
        """
        review_path = self.repo_path / 'REVIEW.md'
        if self._is_safe_path(review_path) and review_path.exists():
            try:
                # Size limit: 50KB
                if review_path.stat().st_size > 50 * 1024:
                    return ""
                with open(review_path, 'r', encoding='utf-8') as f:
                    return f.read()
            except Exception:
                pass

        return ""

    def _load_language_rules(self, changed_files: List[str]) -> str:
        """
        Load language-specific rules from .claude/rules/ directory.

        Args:
            changed_files: List of changed file paths

        Returns:
            Combined language rules text
        """
        # Determine which language rule files to load
        file_types = self._get_file_types(changed_files)

        rules_dir = self.repo_path / '.claude' / 'rules'
        if not rules_dir.exists() or not rules_dir.is_dir():
            return ""

        combined_rules = []

        for file_type in file_types:
            # Validate file_type to prevent path injection
            if not file_type.isalnum():
                continue

            rule_file = rules_dir / f'{file_type}.md'

            # Security validation
            if not self._is_safe_path(rule_file):
                continue

            if rule_file.exists():
                try:
                    # Size limit: 20KB per rule file
                    if rule_file.stat().st_size > 20 * 1024:
                        continue

                    with open(rule_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        combined_rules.append(f"## {file_type.upper()} Rules\n\n{content}")
                except Exception:
                    pass

        return "\n\n".join(combined_rules) if combined_rules else ""

    def _get_file_types(self, files: List[str]) -> Set[str]:
        """
        Determine which rule files to load based on file extensions.

        Args:
            files: List of file paths

        Returns:
            Set of file type identifiers (e.g., 'python', 'javascript')
        """
        file_types = set()

        # Extension to rule file mapping
        ext_mapping = {
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
            '.cs': 'dotnet',
            '.cpp': 'cpp',
            '.c': 'c',
            '.h': 'c',
            '.hpp': 'cpp',
            '.sh': 'shell',
            '.bash': 'shell',
            '.sql': 'sql',
            '.yaml': 'yaml',
            '.yml': 'yaml',
        }

        for file_path in files:
            ext = Path(file_path).suffix.lower()
            if ext in ext_mapping:
                file_types.add(ext_mapping[ext])

        return file_types

    def format_context_for_prompt(self, context: Dict[str, str]) -> str:
        """
        Format loaded context for inclusion in AI prompts.

        Args:
            context: Context dictionary from load_context()

        Returns:
            Formatted string for prompt inclusion
        """
        sections = []

        if context.get('claude_md'):
            sections.append("## Project Conventions (CLAUDE.md)\n\n" + context['claude_md'])

        if context.get('review_md'):
            sections.append("## Review Rules (REVIEW.md)\n\n" + context['review_md'])

        if context.get('language_rules'):
            sections.append("## Language-Specific Rules\n\n" + context['language_rules'])

        if not sections:
            return "No project-specific conventions available."

        return "\n\n".join(sections)

    def has_context(self, context: Dict[str, str]) -> bool:
        """
        Check if any context was loaded.

        Args:
            context: Context dictionary

        Returns:
            True if any context exists
        """
        return bool(context.get('claude_md') or
                   context.get('review_md') or
                   context.get('language_rules'))
