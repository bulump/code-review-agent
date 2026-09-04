#!/usr/bin/env python3
"""
Test AWS Secret Detection
Validates context-aware, proximity-based, and entropy-verified AWS detection.
"""
import pytest
import tempfile
from pathlib import Path
from security_scanner import SecurityScanner
from finding_verifier import FindingVerifier


def test_aws_access_key_detection():
    """Test AWS Access Key ID pattern detection"""
    scanner = SecurityScanner()

    test_code = """
config = {
    'access_key': 'AKIAIOSFODNN7EXAMPLE',
    'region': 'us-east-1',
    'secret': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
}
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        test_file = f.name

    try:
        issues = scanner.scan_file(test_file, test_code)

        # Should detect AWS-related issues
        aws_issues = [i for i in issues if 'aws' in i.get('issue', '').lower() or 'aws' in i.get('description', '').lower()]

        assert len(aws_issues) > 0, "Should detect AWS credentials"

        # Check for Access Key detection
        access_key_detected = any(
            'AKIAIOSFODNN7EXAMPLE' in str(i.get('matched', '')) or
            'access key' in i.get('description', '').lower()
            for i in aws_issues
        )
        assert access_key_detected, "Should detect AWS Access Key ID"

    finally:
        Path(test_file).unlink()


def test_context_aware_aws_secret():
    """Test context-aware AWS Secret Key detection"""
    scanner = SecurityScanner()

    # Should detect: variable name contains AWS keywords
    test_code = """
aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        test_file = f.name

    try:
        issues = scanner.scan_file(test_file, test_code)

        # Should detect AWS secret (look for 'secret', 'password', or 'hardcoded')
        aws_secret_issues = [
            i for i in issues
            if 'secret' in i.get('issue', '').lower()
            or 'password' in i.get('issue', '').lower()
            or 'hardcoded' in i.get('description', '').lower()
        ]

        assert len(aws_secret_issues) > 0, "Should detect context-aware AWS secret"

    finally:
        Path(test_file).unlink()


def test_proximity_based_detection():
    """Test proximity-based AWS secret detection"""
    scanner = SecurityScanner()

    # 40-char string near AWS Access Key should be flagged
    test_code = """
config = {
    'access_key': 'AKIAIOSFODNN7EXAMPLE',
    'region': 'us-east-1',
    'secret': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
}
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        test_file = f.name

    try:
        issues = scanner.scan_file(test_file, test_code)

        # Check proximity detection
        proximity_issues = [i for i in issues if 'proximity' in i.get('issue', '').lower()]

        assert len(proximity_issues) > 0, "Should detect secret via proximity"

        # Should have high confidence
        high_confidence_found = any(i.get('confidence') == 'high' for i in proximity_issues)
        assert high_confidence_found, "Proximity detection should have high confidence"

    finally:
        Path(test_file).unlink()


def test_verification_filters_test_files():
    """Test that verification filters out test file findings"""
    verifier = FindingVerifier()

    # Test file findings should be filtered
    test_findings = [
        {
            'tool': 'pattern-matcher',
            'issue': 'aws_secret_key_context',
            'filename': 'test_config.py',  # Test file
            'matched': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        },
        {
            'tool': 'pattern-matcher',
            'issue': 'aws_secret_key_context',
            'filename': 'example_credentials.py',  # Example file
            'matched': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        },
        {
            'tool': 'pattern-matcher',
            'issue': 'aws_secret_key_context',
            'filename': 'production_config.py',  # Real file
            'matched': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        },
    ]

    verified = verifier.verify_findings(test_findings)

    # Only production file should pass verification
    assert len(verified) < len(test_findings), "Should filter out test/example files"

    dropped = len(test_findings) - len(verified)
    drop_rate = (dropped / len(test_findings)) * 100

    assert drop_rate > 50, "Should drop majority of test/example findings"


def test_entropy_based_filtering():
    """Test entropy-based filtering of low-entropy secrets"""
    verifier = FindingVerifier()

    # Low entropy (repeated chars) vs high entropy
    findings = [
        {
            'tool': 'pattern-matcher',
            'issue': 'aws_secret_key_proximity',
            'filename': 'config.py',
            'matched': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',  # Low entropy
        },
        {
            'tool': 'pattern-matcher',
            'issue': 'aws_secret_key_proximity',
            'filename': 'config.py',
            'matched': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',  # High entropy
        },
    ]

    # Check entropy calculation
    low_entropy_str = findings[0]['matched']
    high_entropy_str = findings[1]['matched']

    low_entropy = verifier._calculate_entropy(low_entropy_str)
    high_entropy = verifier._calculate_entropy(high_entropy_str)

    assert low_entropy < 4.0, "Repeated chars should have low entropy"
    assert high_entropy >= 4.0, "Random string should have high entropy"

    # Verify findings - low entropy should be filtered
    verified = verifier.verify_findings(findings)

    assert len(verified) == 0, "Low entropy strings should be filtered as test data"


def test_false_positive_prevention():
    """Test that SHA-1 hashes and other 40-char strings aren't flagged"""
    scanner = SecurityScanner()

    # SHA-1 hash (should NOT be flagged as AWS secret)
    test_code = """
commit_hash = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
checksum = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4'
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        test_file = f.name

    try:
        issues = scanner.scan_file(test_file, test_code)

        # Check for proximity-based detections
        proximity_issues = [i for i in issues if 'proximity' in i.get('issue', '').lower()]

        # Should NOT flag these (no AWS Access Key nearby, and contains 'hash'/'checksum')
        assert len(proximity_issues) == 0, "Should not flag SHA-1 hashes or checksums"

    finally:
        Path(test_file).unlink()
