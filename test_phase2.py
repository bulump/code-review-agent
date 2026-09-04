#!/usr/bin/env python3
"""
Test Phase 2: Multi-Reviewer Architecture
Validates all Phase 2 components and parallel reviewer execution.
"""
import pytest
import tempfile
from pathlib import Path
from models.finding import Finding
from reviewers.base_reviewer import BaseReviewer
from reviewers.file_classifier import FileClassifier
from reviewers.security_reviewer import SecurityReviewer
from reviewers.quality_reviewer import QualityReviewer
from reviewers.review_orchestrator import ReviewOrchestrator


def test_finding_model():
    """Test Finding dataclass"""
    # Create a finding
    finding = Finding(
        tool='semgrep',
        type='security',
        severity='critical',
        issue='sql_injection',
        description='SQL injection vulnerability detected',
        filename='app.py',
        line=42,
        recommendation='Use parameterized queries',
        reviewer='security',
        origin='introduced',
        verified=True,
        confidence='high',
    )

    # Test methods
    assert finding.is_blocker(), "Critical should be blocker"
    assert not finding.is_pre_existing(), "Origin is introduced"
    assert finding.is_high_confidence(), "Confidence is high"

    # Test to_dict/from_dict round-trip
    finding_dict = finding.to_dict()
    finding_restored = Finding.from_dict(finding_dict)

    assert finding_restored.severity == finding.severity
    assert finding_restored.reviewer == finding.reviewer


def test_file_classifier():
    """Test FileClassifier routing"""
    classifier = FileClassifier()

    files = [
        'src/services/user_service.py',
        'src/controllers/api.py',
        'tests/test_user_service.py',
        'config/database.yml',
        'README.md',
    ]

    classified = classifier.classify(files)

    # Security: source files (not tests)
    assert 'src/services/user_service.py' in classified['security']
    assert 'tests/test_user_service.py' not in classified['security']

    # Quality: all source files
    assert 'src/services/user_service.py' in classified['quality']
    assert 'tests/test_user_service.py' in classified['quality']

    # Testing: tests + source without tests
    assert 'tests/test_user_service.py' in classified['testing']

    # Narrative: all files
    assert len(classified['narrative']) == len(files)


def test_security_reviewer():
    """Test SecurityReviewer"""
    reviewer = SecurityReviewer()

    # Test code with SQL injection
    test_code = '''
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    return db.execute(query)
'''

    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        test_file = f.name

    try:
        files = [{
            'filename': test_file,
            'content': test_code,
        }]

        findings = reviewer.review(files, {})

        assert len(findings) > 0, "Should detect SQL injection"

        for finding in findings:
            assert isinstance(finding, Finding), "Should return Finding objects"
            assert finding.reviewer == 'security', "Should tag with security reviewer"

    finally:
        Path(test_file).unlink()


def test_quality_reviewer():
    """Test QualityReviewer"""
    reviewer = QualityReviewer()

    # Test code with quality issues (long function, no docstring)
    test_code = '''
def process_data(data):
''' + '\n'.join([f"    x = {i}" for i in range(50)]) + '''
    return x
'''

    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        test_file = f.name

    try:
        files = [{
            'filename': test_file,
            'content': test_code,
        }]

        findings = reviewer.review(files, {})

        assert len(findings) > 0, "Should detect quality issues"

        for finding in findings:
            assert finding.reviewer == 'quality', "Should tag with quality reviewer"

    finally:
        Path(test_file).unlink()


def test_review_orchestrator():
    """Test ReviewOrchestrator parallel execution"""
    # Create test files
    test_files = []

    # Source file with issues
    source_code = '''
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    return db.execute(query)
'''

    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(source_code)
        source_file = f.name
        test_files.append(source_file)

    try:
        files = [{
            'filename': source_file,
            'content': source_code,
        }]

        # Run orchestrator with only security and quality (skip AI reviewers for speed)
        orchestrator = ReviewOrchestrator(
            enabled_reviewers=['security', 'quality'],
            enable_verification=False  # Skip verification for speed
        )

        result = orchestrator.run_parallel_review(files)

        # Verify findings
        findings = result['findings']
        assert len(findings) > 0, "Should have findings"

        # Check reviewer attribution
        reviewers_found = set(f.reviewer for f in findings)
        assert len(reviewers_found) > 0, "Should have reviewer attribution"

    finally:
        for f in test_files:
            Path(f).unlink()


def test_finding_serialization():
    """Test Finding serialization for Phase 2 compatibility"""
    # Test that Finding can be created from old-style dict
    old_style_dict = {
        'tool': 'semgrep',
        'type': 'security',
        'severity': 'high',
        'issue': 'hardcoded-password',
        'description': 'Hardcoded password detected',
        'filename': 'config.py',
        'line': 10,
        'recommendation': 'Use environment variables',
    }

    finding = Finding.from_dict(old_style_dict)

    assert finding.reviewer == 'unknown', "Should default to 'unknown'"
    assert finding.origin == 'introduced', "Should default to 'introduced'"
    assert finding.confidence == 'high', "Should default to 'high'"

    # Test new-style dict with all fields
    new_style_dict = {
        **old_style_dict,
        'reviewer': 'security',
        'origin': 'pre-existing',
        'verified': True,
        'confidence': 'medium',
    }

    finding2 = Finding.from_dict(new_style_dict)

    assert finding2.reviewer == 'security'
    assert finding2.origin == 'pre-existing'
    assert finding2.verified == True
    assert finding2.confidence == 'medium'
