#!/usr/bin/env python3
"""
Multi-Reviewer Prototype
Test the enhanced architecture on real code
"""

from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from anthropic import Anthropic
from pathlib import Path
import os
import sys


# ============================================================================
# Enhanced Finding Model
# ============================================================================

@dataclass
class Finding:
    """Enhanced finding with origin tracking and verification"""
    reviewer: str
    severity: str  # BLOCKER, WARNING, SUGGESTION, NIT
    issue: str
    description: str
    filename: str
    line: int
    code: str
    recommendation: str
    origin: str = "introduced"  # "introduced" or "pre-existing"
    verified: bool = False

    def __post_init__(self):
        if self.origin == "pre-existing" and "PRE-EXISTING" not in self.severity:
            self.severity = f"PRE-EXISTING {self.severity}"

    def is_blocker(self) -> bool:
        return "BLOCKER" in self.severity

    def format(self, finding_id: int) -> str:
        """Format for display"""
        return f"""### #{finding_id} — {self.severity} ({self.reviewer}) — {self.issue}
**Location:** `{self.filename}:{self.line}`

{self.description}

**Recommendation:** {self.recommendation}
"""


# ============================================================================
# Base Reviewer
# ============================================================================

class BaseReviewer(ABC):
    """Abstract base class for all reviewers"""

    def __init__(self, name: str, focus_area: str):
        self.name = name
        self.focus_area = focus_area
        self.api_key = os.getenv('ANTHROPIC_API_KEY')
        self.client = Anthropic(api_key=self.api_key) if self.api_key else None

    @abstractmethod
    def is_relevant(self, filename: str) -> bool:
        """Determine if this file is relevant to this reviewer"""
        pass

    def build_prompt(self, files: List[Dict], context: Dict) -> str:
        """Build reviewer-specific prompt"""
        conventions = context.get('conventions', '')

        file_contents = "\n\n".join([
            f"## File: {f['filename']}\n```python\n{f.get('content', '')[:2000]}\n```"
            for f in files
        ])

        prompt = f"""You are the **{self.name} Reviewer** performing a code review.

## Your focus
{self.focus_area}

## Project conventions
{conventions if conventions else "No project-specific conventions provided."}

## Files to review
{file_contents}

## Output format
For each finding, output EXACTLY this format:

```
SEVERITY: Title of the finding
FILE: path/to/file.py
LINE: 45
DESCRIPTION: Description of the issue, why it matters.
RECOMMENDATION: What to do about it.
---
```

Severity levels (use EXACTLY these words):
- BLOCKER — Will cause bugs, security vulnerabilities, or broken builds
- WARNING — Likely to cause problems
- SUGGESTION — Would improve the code
- NIT — Minor style or clarity issue

Rules:
- Be specific with file paths and line numbers
- Focus on findings that developers might genuinely miss
- If nothing worth flagging, return exactly: "NO_FINDINGS"
- Quality over quantity - 3 high-signal findings beat 10 padded with noise
"""
        return prompt

    def review(self, files: List[Dict], context: Dict) -> List[Finding]:
        """Perform review and return findings"""
        if not files:
            return []

        # For prototype testing, use mock findings if API fails
        if not self.client:
            print(f"  ⚠ {self.name}: No API key, using mock findings")
            return self._get_mock_findings(files)

        prompt = self.build_prompt(files, context)

        try:
            message = self.client.messages.create(
                model="claude-sonnet-4-5-20250929",
                max_tokens=4000,
                messages=[{"role": "user", "content": prompt}]
            )
            response = message.content[0].text
            return self._parse_findings(response)
        except Exception as e:
            print(f"  ⚠ {self.name}: API error, using mock findings for demo")
            return self._get_mock_findings(files)

    def _get_mock_findings(self, files: List[Dict]) -> List[Finding]:
        """Generate mock findings for demonstration"""
        return []

    def _parse_findings(self, response: str) -> List[Finding]:
        """Parse AI response into Finding objects"""
        if "NO_FINDINGS" in response:
            return []

        findings = []
        current = {}

        for line in response.split('\n'):
            line = line.strip()

            if line.startswith('SEVERITY:'):
                if current.get('severity'):
                    # Save previous finding
                    findings.append(self._create_finding(current))
                current = {'severity': line.replace('SEVERITY:', '').strip()}

            elif line.startswith('FILE:'):
                current['filename'] = line.replace('FILE:', '').strip()

            elif line.startswith('LINE:'):
                try:
                    current['line'] = int(line.replace('LINE:', '').strip())
                except:
                    current['line'] = 0

            elif line.startswith('DESCRIPTION:'):
                current['description'] = line.replace('DESCRIPTION:', '').strip()

            elif line.startswith('RECOMMENDATION:'):
                current['recommendation'] = line.replace('RECOMMENDATION:', '').strip()

            elif line == '---':
                if current.get('severity'):
                    findings.append(self._create_finding(current))
                    current = {}

        # Don't forget the last one
        if current.get('severity'):
            findings.append(self._create_finding(current))

        return findings

    def _create_finding(self, data: Dict) -> Finding:
        """Create Finding object from parsed data"""
        severity = data.get('severity', 'WARNING')
        # Extract just the severity level
        severity_clean = severity.split('—')[0].strip() if '—' in severity else severity

        return Finding(
            reviewer=self.name,
            severity=severity_clean,
            issue=severity,  # Use full text as issue
            description=data.get('description', ''),
            filename=data.get('filename', ''),
            line=data.get('line', 0),
            code='',
            recommendation=data.get('recommendation', '')
        )


# ============================================================================
# Concrete Reviewers
# ============================================================================

class SecurityReviewer(BaseReviewer):
    """Focuses on security vulnerabilities"""

    def __init__(self):
        super().__init__(
            name="Security",
            focus_area="""Injection risks (SQL, command, XSS), hardcoded secrets/API keys,
authentication/authorization gaps, input validation, unsafe deserialization,
use of eval/exec, insecure random for crypto, debug mode in production"""
        )

    def is_relevant(self, filename: str) -> bool:
        source_exts = {'.py', '.js', '.ts', '.tsx', '.jsx', '.java', '.go', '.rb', '.php'}
        test_indicators = {'test_', '_test.', '.test.', '/tests/', '/test/'}

        ext = Path(filename).suffix.lower()
        if ext not in source_exts:
            return False

        filename_lower = filename.lower()
        return not any(indicator in filename_lower for indicator in test_indicators)

    def _get_mock_findings(self, files: List[Dict]) -> List[Finding]:
        """Demo findings for security reviewer"""
        findings = []
        for f in files:
            if 'security_scanner.py' in f['filename']:
                findings.append(Finding(
                    reviewer=self.name,
                    severity="WARNING",
                    issue="Potential exception swallowing in tool scanner integration",
                    description="Lines 140-146 catch all exceptions without logging, which could hide security tool failures",
                    filename=f['filename'],
                    line=145,
                    code="except Exception as e: pass",
                    recommendation="Log exceptions to ensure security scan failures are visible"
                ))
        return findings


class ArchitectureReviewer(BaseReviewer):
    """Focuses on design and architecture"""

    def __init__(self):
        super().__init__(
            name="Architecture",
            focus_area="""Design patterns, SOLID principles, coupling between modules,
abstraction levels, separation of concerns, code organization,
dependency management, breaking changes to APIs"""
        )

    def is_relevant(self, filename: str) -> bool:
        source_exts = {'.py', '.js', '.ts', '.tsx', '.jsx', '.java', '.go', '.rb', '.php'}
        test_indicators = {'test_', '_test.', '.test.', '/tests/', '/test/'}

        ext = Path(filename).suffix.lower()
        if ext not in source_exts:
            return False

        filename_lower = filename.lower()
        return not any(indicator in filename_lower for indicator in test_indicators)

    def _get_mock_findings(self, files: List[Dict]) -> List[Finding]:
        """Demo findings for architecture reviewer"""
        findings = []
        for f in files:
            if 'code_review_agent.py' in f['filename']:
                findings.append(Finding(
                    reviewer=self.name,
                    severity="SUGGESTION",
                    issue="Display logic mixed with orchestration logic",
                    description="Functions like _display_security_results() and _display_quality_results() mix formatting concerns with business logic. Consider extracting to a separate OutputFormatter class",
                    filename=f['filename'],
                    line=235,
                    code="_display_security_results() function",
                    recommendation="Extract display logic into dedicated formatter classes for better separation of concerns"
                ))
        return findings


class QualityReviewer(BaseReviewer):
    """Focuses on code quality and readability"""

    def __init__(self):
        super().__init__(
            name="Quality",
            focus_area="""Naming clarity, function/file length, complexity,
dead code, magic numbers, misleading comments, readability,
maintainability for the next developer"""
        )

    def is_relevant(self, filename: str) -> bool:
        source_exts = {'.py', '.js', '.ts', '.tsx', '.jsx', '.java', '.go', '.rb', '.php', '.md'}
        return Path(filename).suffix.lower() in source_exts

    def _get_mock_findings(self, files: List[Dict]) -> List[Finding]:
        """Demo findings for quality reviewer"""
        findings = []
        for f in files:
            if 'ai_reviewer.py' in f['filename']:
                findings.append(Finding(
                    reviewer=self.name,
                    severity="NIT",
                    issue="Model identifier hardcoded in multiple locations",
                    description="The model name 'claude-sonnet-4-20250514' appears in 3 locations. Consider extracting to a constant",
                    filename=f['filename'],
                    line=38,
                    code='model="claude-sonnet-4-20250514"',
                    recommendation="Define MODEL_NAME = 'claude-sonnet-4-20250514' at module level and reference it"
                ))
            if 'security_scanner.py' in f['filename']:
                # Duplicate finding - will test deduplication
                findings.append(Finding(
                    reviewer=self.name,
                    severity="WARNING",
                    issue="Silent exception handling",
                    description="Exception caught without logging at line 145, making debugging difficult",
                    filename=f['filename'],
                    line=145,
                    code="except Exception as e: pass",
                    recommendation="Add logging to track when exceptions occur"
                ))
        return findings


# ============================================================================
# Supporting Classes
# ============================================================================

class FileClassifier:
    """Routes files to relevant reviewers"""

    def classify(self, files: List[str], reviewers: List[BaseReviewer]) -> Dict[str, List[str]]:
        classification = {reviewer.name: [] for reviewer in reviewers}

        for file in files:
            for reviewer in reviewers:
                if reviewer.is_relevant(file):
                    classification[reviewer.name].append(file)

        return classification


class ReviewOrchestrator:
    """Coordinates parallel reviewer execution"""

    def __init__(self, reviewers: List[BaseReviewer]):
        self.reviewers = reviewers

    def run_parallel_review(
        self,
        classified_files: Dict[str, List[Dict]],
        context: Dict
    ) -> List[Finding]:
        print(f"\n🔍 Running {len(self.reviewers)} reviewers in parallel...")

        all_findings = []

        with ThreadPoolExecutor(max_workers=len(self.reviewers)) as executor:
            future_to_reviewer = {
                executor.submit(
                    reviewer.review,
                    classified_files.get(reviewer.name, []),
                    context
                ): reviewer
                for reviewer in self.reviewers
            }

            for future in as_completed(future_to_reviewer):
                reviewer = future_to_reviewer[future]
                try:
                    findings = future.result()
                    print(f"  ✓ {reviewer.name}: {len(findings)} findings")
                    all_findings.extend(findings)
                except Exception as e:
                    print(f"  ✗ {reviewer.name}: Error - {e}")

        return all_findings


class FindingVerifier:
    """Verifies findings for accuracy"""

    def verify_findings(self, findings: List[Finding]) -> List[Finding]:
        print(f"\n🔍 Verifying {len(findings)} findings...")
        verified = []

        for finding in findings:
            if self._verify_location(finding):
                finding.verified = True
                verified.append(finding)
            else:
                print(f"  ✗ Dropped: {finding.issue[:50]} (location not found)")

        print(f"  ✓ {len(verified)} findings verified")
        return verified

    def _verify_location(self, finding: Finding) -> bool:
        try:
            file_path = Path(finding.filename)
            if not file_path.exists():
                return False

            with open(file_path) as f:
                lines = f.readlines()
                return 1 <= finding.line <= len(lines)
        except:
            return False

    def deduplicate(self, findings: List[Finding]) -> List[Finding]:
        print(f"\n🔍 Deduplicating findings...")
        unique_findings = {}

        for finding in findings:
            key = f"{finding.filename}:{finding.line}:{finding.issue[:30]}"

            if key in unique_findings:
                existing = unique_findings[key]
                if finding.reviewer not in existing.reviewer:
                    existing.reviewer = f"{existing.reviewer}, {finding.reviewer}"
            else:
                unique_findings[key] = finding

        result = list(unique_findings.values())
        print(f"  ✓ {len(result)} unique findings")
        return result


# ============================================================================
# Main Test Function
# ============================================================================

def test_on_current_repo():
    """Test the multi-reviewer system on files in this repo"""

    print("=" * 70)
    print("Multi-Reviewer Prototype Test")
    print("=" * 70)

    # Files to review (real files from this repo)
    files_to_review = [
        'security_scanner.py',
        'ai_reviewer.py',
        'code_review_agent.py'
    ]

    # Load file contents
    files = []
    for filename in files_to_review:
        file_path = Path(filename)
        if file_path.exists():
            with open(file_path) as f:
                content = f.read()
                files.append({
                    'filename': filename,
                    'content': content
                })
        else:
            print(f"⚠ Warning: {filename} not found, skipping")

    if not files:
        print("❌ No files found to review")
        return

    print(f"\n📁 Reviewing {len(files)} files:")
    for f in files:
        print(f"  - {f['filename']}")

    # Load context from CLAUDE.md if it exists
    context = {}
    claude_md = Path('.claude/CLAUDE.md')
    if claude_md.exists():
        with open(claude_md) as f:
            context['conventions'] = f.read()
            print(f"\n📚 Loaded conventions from .claude/CLAUDE.md")

    # Create reviewers
    reviewers = [
        SecurityReviewer(),
        ArchitectureReviewer(),
        QualityReviewer()
    ]

    # Classify files
    classifier = FileClassifier()
    file_list = [f['filename'] for f in files]
    classified = classifier.classify(file_list, reviewers)

    print(f"\n📋 File classification:")
    for reviewer_name, filenames in classified.items():
        print(f"  {reviewer_name}: {len(filenames)} files")

    # Map back to full file data
    file_map = {f['filename']: f for f in files}
    classified_files = {
        reviewer_name: [file_map[fn] for fn in filenames]
        for reviewer_name, filenames in classified.items()
    }

    # Run parallel review
    orchestrator = ReviewOrchestrator(reviewers)
    findings = orchestrator.run_parallel_review(classified_files, context)

    # Verify and deduplicate
    verifier = FindingVerifier()
    findings = verifier.verify_findings(findings)
    findings = verifier.deduplicate(findings)

    # Sort by severity
    severity_order = {
        'BLOCKER': 0,
        'WARNING': 1,
        'SUGGESTION': 2,
        'NIT': 3,
        'PRE-EXISTING BLOCKER': 4,
        'PRE-EXISTING WARNING': 5,
        'PRE-EXISTING SUGGESTION': 6,
        'PRE-EXISTING NIT': 7
    }
    findings.sort(key=lambda f: severity_order.get(f.severity, 99))

    # Display results
    print("\n" + "=" * 70)
    print("FINDINGS")
    print("=" * 70)

    if not findings:
        print("\n✅ No issues found. The code looks good!\n")
    else:
        for idx, finding in enumerate(findings, 1):
            print(finding.format(idx))

    # Summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)

    blockers = sum(1 for f in findings if 'BLOCKER' in f.severity)
    warnings = sum(1 for f in findings if 'WARNING' in f.severity)
    suggestions = sum(1 for f in findings if 'SUGGESTION' in f.severity)
    nits = sum(1 for f in findings if 'NIT' in f.severity)

    print(f"\n{len(findings)} findings: {blockers} blockers, {warnings} warnings, "
          f"{suggestions} suggestions, {nits} nits\n")

    if blockers > 0:
        print("❌ Blockers found - must be addressed before merge")
    elif warnings > 0:
        print("⚠️  Warnings found - strongly recommended to address")
    else:
        print("✅ No critical issues - looks good!")

    print()


if __name__ == "__main__":
    test_on_current_repo()
