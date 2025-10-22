"""
GitHub Pull Request Analyzer
Fetches PR data and parses code changes for review.
"""
from github import Github
from typing import Dict, List, Any, Optional
import os
import git
from pathlib import Path


class PRAnalyzer:
    """Analyzes GitHub pull requests and extracts code changes."""

    def __init__(self, token: str = None):
        """Initialize PR analyzer with GitHub token."""
        self.token = token or os.getenv('GITHUB_TOKEN')
        self.client = Github(self.token) if self.token else None

    def get_pr_details(self, repo_name: str, pr_number: int) -> Dict[str, Any]:
        """
        Fetch pull request details and code changes.

        Args:
            repo_name: Repository name (owner/repo)
            pr_number: Pull request number

        Returns:
            Dictionary containing PR details and file changes
        """
        if not self.client:
            raise ValueError("GITHUB_TOKEN must be set for PR reviews")

        try:
            repo = self.client.get_repo(repo_name)
            pr = repo.get_pull(pr_number)

            # Get all files changed in the PR
            files = []
            for file in pr.get_files():
                # Only analyze code files
                if self._is_code_file(file.filename):
                    file_data = {
                        'filename': file.filename,
                        'status': file.status,  # added, modified, deleted
                        'additions': file.additions,
                        'deletions': file.deletions,
                        'changes': file.changes,
                        'patch': file.patch if file.patch else '',
                        'raw_url': file.raw_url,
                    }

                    # Try to get file content
                    if file.status != 'removed':
                        try:
                            content = repo.get_contents(file.filename, ref=pr.head.sha)
                            file_data['content'] = content.decoded_content.decode('utf-8')
                        except:
                            file_data['content'] = None

                    files.append(file_data)

            pr_details = {
                'number': pr.number,
                'title': pr.title,
                'description': pr.body or '',
                'author': pr.user.login,
                'created_at': pr.created_at.isoformat(),
                'updated_at': pr.updated_at.isoformat(),
                'state': pr.state,
                'base_branch': pr.base.ref,
                'head_branch': pr.head.ref,
                'files': files,
                'total_additions': sum(f['additions'] for f in files),
                'total_deletions': sum(f['deletions'] for f in files),
                'files_changed': len(files),
            }

            return pr_details

        except Exception as e:
            raise Exception(f"Failed to fetch PR details: {str(e)}")

    def analyze_local_changes(self, repo_path: str) -> Dict[str, Any]:
        """
        Analyze uncommitted changes in a local repository.

        Args:
            repo_path: Path to git repository

        Returns:
            Dictionary containing changed files and their diffs
        """
        try:
            repo = git.Repo(repo_path)

            # Get unstaged and staged changes
            changed_files = []

            # Get diff for staged changes
            staged_diff = repo.index.diff('HEAD')
            unstaged_diff = repo.index.diff(None)

            all_diffs = list(staged_diff) + list(unstaged_diff)

            for diff_item in all_diffs:
                if self._is_code_file(diff_item.a_path):
                    file_path = Path(repo_path) / diff_item.a_path

                    file_data = {
                        'filename': diff_item.a_path,
                        'status': 'modified',
                        'patch': str(diff_item.diff),
                    }

                    # Get file content if it exists
                    if file_path.exists():
                        with open(file_path, 'r', encoding='utf-8') as f:
                            file_data['content'] = f.read()

                    changed_files.append(file_data)

            return {
                'files': changed_files,
                'files_changed': len(changed_files),
                'repo_path': repo_path,
            }

        except Exception as e:
            raise Exception(f"Failed to analyze local changes: {str(e)}")

    def analyze_files(self, file_paths: List[str]) -> Dict[str, Any]:
        """
        Analyze specific files.

        Args:
            file_paths: List of file paths to analyze

        Returns:
            Dictionary containing file data
        """
        files = []

        for file_path in file_paths:
            if not os.path.exists(file_path):
                print(f"Warning: {file_path} not found, skipping")
                continue

            if not self._is_code_file(file_path):
                print(f"Warning: {file_path} is not a code file, skipping")
                continue

            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                files.append({
                    'filename': file_path,
                    'status': 'review',
                    'content': content,
                    'patch': '',
                })
            except Exception as e:
                print(f"Error reading {file_path}: {e}")

        return {
            'files': files,
            'files_changed': len(files),
        }

    def _is_code_file(self, filename: str) -> bool:
        """Check if file is a code file worth reviewing."""
        code_extensions = {
            '.py', '.js', '.ts', '.tsx', '.jsx', '.java', '.go', '.rs',
            '.c', '.cpp', '.h', '.hpp', '.cs', '.rb', '.php', '.swift',
            '.kt', '.scala', '.sh', '.bash', '.sql', '.yaml', '.yml',
            '.json', '.xml', '.html', '.css', '.scss', '.vue',
        }

        # Skip certain paths
        skip_paths = {
            'node_modules/', 'venv/', 'env/', '__pycache__/',
            '.git/', 'dist/', 'build/', 'target/', '.idea/',
            'vendor/', 'coverage/', '.next/', 'out/',
        }

        # Check if in skip path
        for skip in skip_paths:
            if skip in filename:
                return False

        # Check extension
        ext = Path(filename).suffix.lower()
        return ext in code_extensions

    def get_diff_context(self, patch: str) -> List[Dict[str, Any]]:
        """
        Parse a git patch and extract changed lines with context.

        Args:
            patch: Git diff patch string

        Returns:
            List of changed sections with context
        """
        if not patch:
            return []

        changes = []
        current_section = None

        for line in patch.split('\n'):
            if line.startswith('@@'):
                # New hunk
                if current_section:
                    changes.append(current_section)
                current_section = {
                    'header': line,
                    'added': [],
                    'removed': [],
                    'context': [],
                }
            elif current_section:
                if line.startswith('+') and not line.startswith('+++'):
                    current_section['added'].append(line[1:])
                elif line.startswith('-') and not line.startswith('---'):
                    current_section['removed'].append(line[1:])
                else:
                    current_section['context'].append(line)

        if current_section:
            changes.append(current_section)

        return changes
