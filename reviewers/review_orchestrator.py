"""
Review Orchestrator
Coordinates parallel execution of multiple reviewers.
"""
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from models.finding import Finding
from reviewers.base_reviewer import BaseReviewer
from reviewers.security_reviewer import SecurityReviewer
from reviewers.quality_reviewer import QualityReviewer
from reviewers.architecture_reviewer import ArchitectureReviewer
from reviewers.testing_reviewer import TestingReviewer
from reviewers.narrative_reviewer import NarrativeReviewer
from reviewers.file_classifier import FileClassifier
from context_loader import ContextLoader
from finding_verifier import FindingVerifier


class ReviewOrchestrator:
    """
    Orchestrates multiple reviewers in parallel.

    Coordinates:
    1. File classification (routing files to reviewers)
    2. Parallel reviewer execution
    3. Finding collection and merging
    4. Verification and deduplication
    5. Result aggregation
    """

    def __init__(self, enabled_reviewers: List[str] = None, enable_verification: bool = True):
        """
        Initialize review orchestrator.

        Args:
            enabled_reviewers: List of reviewer names to enable (default: all)
            enable_verification: Enable finding verification
        """
        self.enabled_reviewers = enabled_reviewers or ['security', 'quality', 'architecture', 'testing', 'narrative']
        self.enable_verification = enable_verification

        # Initialize components
        self.file_classifier = FileClassifier()
        self.context_loader = ContextLoader()
        self.verifier = FindingVerifier() if enable_verification else None

        # Initialize reviewers
        self.reviewers = self._init_reviewers()

    def _init_reviewers(self) -> Dict[str, BaseReviewer]:
        """
        Initialize all reviewers.

        Returns:
            Dictionary mapping reviewer names to instances
        """
        all_reviewers = {
            'security': SecurityReviewer(),
            'quality': QualityReviewer(),
            'architecture': ArchitectureReviewer(),
            'testing': TestingReviewer(),
            'narrative': NarrativeReviewer(),
        }

        # Filter to only enabled reviewers
        return {
            name: reviewer
            for name, reviewer in all_reviewers.items()
            if name in self.enabled_reviewers
        }

    def run_parallel_review(self, files: List[Dict[str, Any]], repo_path: str = None) -> Dict[str, Any]:
        """
        Run all reviewers in parallel.

        Args:
            files: List of file dictionaries with 'filename' and 'content'
            repo_path: Repository path for context loading

        Returns:
            Dictionary with findings and metadata
        """
        # Load project context
        changed_files = [f.get('filename', '') for f in files]
        context = self.context_loader.load_context(changed_files) if repo_path else {}

        # Classify files for routing
        file_paths = [f.get('filename', '') for f in files]
        classified_files = self.file_classifier.classify(file_paths)

        # Prepare reviewer-specific file lists
        reviewer_files = {}
        for reviewer_name in self.reviewers.keys():
            relevant_filenames = classified_files.get(reviewer_name, [])
            reviewer_files[reviewer_name] = [
                f for f in files if f.get('filename', '') in relevant_filenames
            ]

        # Run reviewers in parallel
        all_findings = []
        reviewer_results = {}

        with ThreadPoolExecutor(max_workers=5) as executor:
            # Submit all reviewer tasks
            future_to_reviewer = {
                executor.submit(
                    self._run_single_reviewer,
                    reviewer_name,
                    self.reviewers[reviewer_name],
                    reviewer_files[reviewer_name],
                    context
                ): reviewer_name
                for reviewer_name in self.reviewers.keys()
            }

            # Collect results as they complete
            for future in as_completed(future_to_reviewer):
                reviewer_name = future_to_reviewer[future]
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                    reviewer_results[reviewer_name] = {
                        'findings_count': len(findings),
                        'status': 'completed',
                    }
                except Exception as e:
                    reviewer_results[reviewer_name] = {
                        'findings_count': 0,
                        'status': 'error',
                        'error': str(e),
                    }

        # Verify findings if enabled
        if self.enable_verification and self.verifier:
            verified_findings = self.verifier.verify_findings([f.to_dict() for f in all_findings])
            # Convert back to Finding objects
            all_findings = [Finding.from_dict(f) for f in verified_findings]

            # Deduplicate
            deduplicated = self.verifier.deduplicate_findings([f.to_dict() for f in all_findings])
            all_findings = [Finding.from_dict(f) for f in deduplicated]

        # Sort findings by severity
        all_findings = self._sort_findings(all_findings)

        return {
            'findings': all_findings,
            'total_findings': len(all_findings),
            'reviewer_results': reviewer_results,
            'verification_stats': self.verifier.get_verification_stats() if self.verifier else {},
            'file_classification': self.file_classifier.get_file_summary(file_paths),
        }

    def _run_single_reviewer(self, name: str, reviewer: BaseReviewer,
                            files: List[Dict[str, Any]], context: Dict[str, str]) -> List[Finding]:
        """
        Run a single reviewer.

        Args:
            name: Reviewer name
            reviewer: Reviewer instance
            files: Files to review
            context: Project context

        Returns:
            List of findings from this reviewer
        """
        try:
            findings = reviewer.review(files, context)
            return findings
        except Exception as e:
            print(f"Reviewer {name} failed: {e}")
            return []

    def _sort_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Sort findings by severity.

        Args:
            findings: List of findings

        Returns:
            Sorted list (critical/blocker first, then high, medium, low, suggestion, nit)
        """
        severity_order = {
            'critical': 0,
            'blocker': 0,
            'high': 1,
            'warning': 2,
            'medium': 3,
            'low': 4,
            'suggestion': 5,
            'nit': 6,
        }

        return sorted(
            findings,
            key=lambda f: (
                severity_order.get(f.severity.lower(), 10),
                f.filename,
                f.line or 0
            )
        )

    def get_summary_by_reviewer(self, findings: List[Finding]) -> Dict[str, Dict[str, int]]:
        """
        Get summary of findings grouped by reviewer.

        Args:
            findings: List of findings

        Returns:
            Dictionary mapping reviewer names to summary stats
        """
        summary = {}

        for finding in findings:
            reviewer = finding.reviewer
            if reviewer not in summary:
                summary[reviewer] = {
                    'total': 0,
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                }

            summary[reviewer]['total'] += 1
            severity = finding.severity.lower()
            if severity in ['critical', 'blocker']:
                summary[reviewer]['critical'] += 1
            elif severity in ['high', 'warning']:
                summary[reviewer]['high'] += 1
            elif severity == 'medium':
                summary[reviewer]['medium'] += 1
            elif severity in ['low', 'suggestion', 'nit']:
                summary[reviewer]['low'] += 1

        return summary
