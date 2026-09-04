"""
Finding Model
Represents a code review finding with enhanced metadata for Phase 2 multi-reviewer architecture.
"""
from dataclasses import dataclass, field
from typing import Optional, Dict, Any


@dataclass
class Finding:
    """
    Represents a code review finding.

    Enhanced for Phase 2 multi-reviewer architecture with:
    - Reviewer attribution
    - Origin tracking (introduced vs pre-existing)
    - Verification status
    - Confidence levels
    """

    # Core fields (from existing system)
    tool: str  # 'pattern-matcher', 'semgrep', 'bandit', 'ai'
    type: str  # 'security' or 'quality'
    severity: str  # 'critical', 'high', 'medium', 'low', 'blocker', 'warning', 'suggestion', 'nit'
    issue: str  # Issue name/ID
    description: str  # Human-readable description
    filename: str  # File path
    recommendation: str  # How to fix

    # Optional location fields
    line: Optional[int] = None  # Line number
    code: Optional[str] = None  # Code snippet
    matched: Optional[str] = None  # Matched pattern/text

    # Phase 2 enhancements
    reviewer: str = 'unknown'  # Which reviewer found this (security, quality, architecture, etc.)
    origin: str = 'introduced'  # 'introduced' or 'pre-existing'
    verified: bool = False  # Has this been verified by FindingVerifier?
    confidence: str = 'high'  # 'high', 'medium', 'low'

    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)  # Extra context

    def is_blocker(self) -> bool:
        """Check if this finding is a blocker."""
        return self.severity.lower() in ['blocker', 'critical']

    def is_pre_existing(self) -> bool:
        """Check if this finding is pre-existing (not introduced by this change)."""
        return self.origin == 'pre-existing'

    def is_high_confidence(self) -> bool:
        """Check if this finding has high confidence."""
        return self.confidence == 'high'

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert finding to dictionary format.

        Returns:
            Dictionary representation compatible with existing code
        """
        result = {
            'tool': self.tool,
            'type': self.type,
            'severity': self.severity,
            'issue': self.issue,
            'description': self.description,
            'filename': self.filename,
            'recommendation': self.recommendation,
            'reviewer': self.reviewer,
            'origin': self.origin,
            'verified': self.verified,
            'confidence': self.confidence,
        }

        # Add optional fields if present
        if self.line is not None:
            result['line'] = self.line
        if self.code is not None:
            result['code'] = self.code
        if self.matched is not None:
            result['matched'] = self.matched
        if self.metadata:
            result['metadata'] = self.metadata

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding':
        """
        Create Finding from dictionary.

        Args:
            data: Dictionary with finding data

        Returns:
            Finding instance
        """
        # Extract core required fields
        core_fields = {
            'tool': data.get('tool', 'unknown'),
            'type': data.get('type', 'quality'),
            'severity': data.get('severity', 'medium'),
            'issue': data.get('issue', ''),
            'description': data.get('description', ''),
            'filename': data.get('filename', ''),
            'recommendation': data.get('recommendation', ''),
        }

        # Extract optional fields
        optional_fields = {
            'line': data.get('line'),
            'code': data.get('code'),
            'matched': data.get('matched'),
            'reviewer': data.get('reviewer', 'unknown'),
            'origin': data.get('origin', 'introduced'),
            'verified': data.get('verified', False),
            'confidence': data.get('confidence', 'high'),
            'metadata': data.get('metadata', {}),
        }

        return cls(**core_fields, **optional_fields)

    def __str__(self) -> str:
        """String representation of finding."""
        location = f"{self.filename}:{self.line}" if self.line else self.filename
        return f"[{self.severity.upper()}] {self.issue} at {location}: {self.description}"

    def __repr__(self) -> str:
        """Detailed representation of finding."""
        return (
            f"Finding(issue={self.issue!r}, severity={self.severity!r}, "
            f"filename={self.filename!r}, line={self.line}, reviewer={self.reviewer!r})"
        )
