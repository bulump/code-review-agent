"""
File Classifier
Routes files to appropriate reviewers based on file type and characteristics.
"""
from typing import List, Dict, Set
from pathlib import Path


class FileClassifier:
    """
    Classifies files and routes them to appropriate reviewers.

    Each reviewer gets a list of relevant files based on:
    - File type (source code, tests, config, docs)
    - Language
    - Purpose
    """

    def classify(self, files: List[str]) -> Dict[str, List[str]]:
        """
        Route files to relevant reviewers.

        Args:
            files: List of file paths

        Returns:
            Dictionary mapping reviewer names to lists of relevant files
        """
        return {
            'security': self._get_security_files(files),
            'quality': self._get_quality_files(files),
            'architecture': self._get_architecture_files(files),
            'testing': self._get_testing_files(files),
            'narrative': files,  # Narrative reviewer sees all files
        }

    def _get_security_files(self, files: List[str]) -> List[str]:
        """
        Get files relevant for security review.

        Args:
            files: All files

        Returns:
            Files that should be security reviewed
        """
        security_files = []
        for f in files:
            # Source code files (not tests)
            if self._is_source(f) and not self._is_test(f):
                security_files.append(f)
            # Config files with potential secrets
            elif self._is_sensitive_config(f):
                security_files.append(f)

        return security_files

    def _get_quality_files(self, files: List[str]) -> List[str]:
        """
        Get files relevant for quality review.

        Args:
            files: All files

        Returns:
            Files that should be quality reviewed
        """
        # Quality reviewer checks all source code
        return [f for f in files if self._is_source(f)]

    def _get_architecture_files(self, files: List[str]) -> List[str]:
        """
        Get files relevant for architecture review.

        Args:
            files: All files

        Returns:
            Files that should be architecture reviewed
        """
        architecture_files = []
        for f in files:
            # Source code (not tests, not config)
            if self._is_source(f) and not self._is_test(f):
                # Prioritize files that define classes, interfaces, modules
                if self._is_architecture_significant(f):
                    architecture_files.append(f)

        return architecture_files if architecture_files else self._get_security_files(files)

    def _get_testing_files(self, files: List[str]) -> List[str]:
        """
        Get files relevant for testing review.

        Args:
            files: All files

        Returns:
            Files that should be testing reviewed
        """
        testing_files = []

        # Test files themselves
        test_files = [f for f in files if self._is_test(f)]
        testing_files.extend(test_files)

        # Source files that should have tests
        source_files = [f for f in files if self._is_source(f) and not self._is_test(f)]
        for source_file in source_files:
            # Check if there's a corresponding test file
            if not self._has_corresponding_test(source_file, files):
                testing_files.append(source_file)

        return testing_files

    def _is_source(self, filename: str) -> bool:
        """Check if file is source code."""
        source_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rs',
            '.rb', '.php', '.cs', '.cpp', '.c', '.h', '.hpp', '.swift',
            '.kt', '.scala', '.sh', '.bash', '.sql'
        }
        return Path(filename).suffix.lower() in source_extensions

    def _is_test(self, filename: str) -> bool:
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

    def _is_sensitive_config(self, filename: str) -> bool:
        """Check if config file might contain secrets."""
        sensitive_configs = {
            '.env', '.env.local', '.env.production',
            'config.yml', 'config.yaml', 'secrets.yml',
            'docker-compose.yml', 'k8s.yaml'
        }
        return Path(filename).name.lower() in sensitive_configs

    def _is_architecture_significant(self, filename: str) -> bool:
        """
        Check if file is likely to contain significant architecture.

        Looks for files that define:
        - Classes and interfaces
        - Modules and packages
        - Service definitions
        - API endpoints
        """
        filename_lower = filename.lower()

        # Keyword-based detection
        arch_keywords = [
            'service', 'controller', 'repository', 'model', 'entity',
            'interface', 'abstract', 'factory', 'builder', 'strategy',
            'handler', 'manager', 'provider', 'client', 'api', 'router'
        ]

        return any(keyword in filename_lower for keyword in arch_keywords)

    def _has_corresponding_test(self, source_file: str, all_files: List[str]) -> bool:
        """
        Check if a source file has a corresponding test file.

        Args:
            source_file: Source file path
            all_files: All files in the changeset

        Returns:
            True if corresponding test file exists
        """
        source_path = Path(source_file)
        source_stem = source_path.stem

        # Common test file patterns
        test_patterns = [
            f"test_{source_stem}",
            f"{source_stem}_test",
            f"{source_stem}.test",
            f"{source_stem}.spec",
        ]

        # Check if any test file matches
        for file in all_files:
            if self._is_test(file):
                test_stem = Path(file).stem
                if any(pattern in test_stem.lower() for pattern in [p.lower() for p in test_patterns]):
                    return True

        return False

    def get_file_summary(self, files: List[str]) -> Dict[str, int]:
        """
        Get summary statistics of file types.

        Args:
            files: List of files

        Returns:
            Dictionary with counts of different file types
        """
        return {
            'total': len(files),
            'source': len([f for f in files if self._is_source(f)]),
            'tests': len([f for f in files if self._is_test(f)]),
            'config': len([f for f in files if self._is_sensitive_config(f)]),
            'architecture': len([f for f in files if self._is_architecture_significant(f)]),
        }
