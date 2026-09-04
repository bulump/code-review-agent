#!/usr/bin/env python3
"""
Test AWS Secret Detection
Validates AWS Access Key ID and Secret Access Key detection with verification.
"""
from pathlib import Path
import tempfile
from security_scanner import SecurityScanner
from finding_verifier import FindingVerifier


def test_aws_access_key_detection():
    """Test that AWS Access Key IDs are detected"""
    print("=" * 70)
    print("TEST 1: AWS Access Key ID Detection")
    print("=" * 70)

    scanner = SecurityScanner()

    # Test code with AWS Access Key ID
    test_code = """
# Production AWS credentials (BAD!)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        test_file = f.name

    try:
        issues = scanner.scan_file(test_file, test_code)

        # Filter for AWS-related issues
        aws_issues = [i for i in issues if 'aws' in i.get('issue', '').lower() or 'aws' in i.get('description', '').lower()]

        print(f"\n📊 Found {len(aws_issues)} AWS-related issues:")
        for issue in aws_issues:
            print(f"  - {issue['issue']}: {issue['description']}")
            print(f"    Severity: {issue['severity']}")
            print(f"    Matched: {issue.get('matched', 'N/A')}")

        # Should detect at least the Access Key ID
        assert len(aws_issues) >= 1, f"Should detect AWS Access Key ID, found {len(aws_issues)} issues"

        # Check that Access Key ID is detected (either by pattern matcher or Semgrep)
        access_key_detected = any(
            'AKIAIOSFODNN7EXAMPLE' in str(i.get('matched', '')) or
            'access key' in i.get('description', '').lower()
            for i in aws_issues
        )
        assert access_key_detected, "Should detect AWS Access Key ID pattern"

        print("\n✅ AWS Access Key ID detection PASSED\n")

    finally:
        Path(test_file).unlink()


def test_aws_secret_key_context_detection():
    """Test context-aware AWS Secret Key detection"""
    print("=" * 70)
    print("TEST 2: Context-Aware AWS Secret Key Detection")
    print("=" * 70)

    scanner = SecurityScanner()

    # Test code with context-aware secret
    test_code = """
# AWS configuration
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        test_file = f.name

    try:
        issues = scanner.scan_file(test_file, test_code)

        # Filter for AWS secret issues (either pattern matcher or tools like Bandit)
        secret_issues = [i for i in issues if
                        'aws_secret_key_context' in i.get('issue', '') or
                        'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' in i.get('description', '')]

        print(f"\n📊 Found {len(secret_issues)} AWS secret issues:")
        for issue in secret_issues:
            print(f"  - {issue.get('issue', 'N/A')}: {issue['description']}")

        assert len(secret_issues) >= 1, "Should detect AWS secret (either via pattern or Bandit)"

        print("\n✅ Context-aware AWS Secret Key detection PASSED\n")

    finally:
        Path(test_file).unlink()


def test_aws_proximity_detection():
    """Test proximity-based AWS secret detection"""
    print("=" * 70)
    print("TEST 3: Proximity-Based AWS Secret Detection")
    print("=" * 70)

    scanner = SecurityScanner()

    # Test code with Access Key and Secret Key near each other
    test_code = """
# Bad practice: hardcoded credentials
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

        # Filter for proximity detection
        proximity_issues = [i for i in issues if 'proximity' in i.get('issue', '')]

        print(f"\n📊 Found {len(proximity_issues)} proximity-based AWS secret issues:")
        for issue in proximity_issues:
            print(f"  - {issue['description']}")
            print(f"    Line: {issue.get('line')}")
            print(f"    Confidence: {issue.get('confidence', 'N/A')}")

        # Should detect the secret near the access key
        assert len(proximity_issues) >= 1, "Should detect AWS secret via proximity"

        # Check confidence is high
        high_confidence = any(i.get('confidence') == 'high' for i in proximity_issues)
        assert high_confidence, "Proximity detection should have high confidence"

        print("\n✅ Proximity-based AWS secret detection PASSED\n")

    finally:
        Path(test_file).unlink()


def test_aws_verification_filters_test_files():
    """Test that AWS verification filters out test files"""
    print("=" * 70)
    print("TEST 4: AWS Verification Filters Test Files")
    print("=" * 70)

    scanner = SecurityScanner()
    verifier = FindingVerifier()

    # Test code in a test file
    test_code = """
# Test fixture
TEST_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
TEST_AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='_test.py', delete=False) as f:
        f.write(test_code)
        test_file = f.name

    try:
        issues = scanner.scan_file(test_file, test_code)

        print(f"\n📊 Found {len(issues)} issues before verification")

        # Verify findings
        verified_issues = verifier.verify_findings(issues)

        print(f"📊 Found {len(verified_issues)} issues after verification")

        stats = verifier.get_verification_stats()
        print(f"\n  Dropped (claim): {stats['dropped_claim']}")
        print(f"  Drop rate: {stats['drop_rate']:.1%}")

        # Should drop AWS secrets from test files
        assert len(verified_issues) < len(issues), "Should filter out some AWS secrets from test file"

        print("\n✅ AWS verification filtering PASSED\n")

    finally:
        Path(test_file).unlink()


def test_aws_verification_entropy_check():
    """Test that low entropy strings are filtered"""
    print("=" * 70)
    print("TEST 5: AWS Verification Entropy Check")
    print("=" * 70)

    verifier = FindingVerifier()

    # Test findings with different entropy levels
    findings = [
        {
            'filename': 'config.py',
            'issue': 'aws_secret_key_proximity',
            'description': 'Possible AWS Secret Access Key',
            'matched': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',  # Low entropy
            'line': 1,
        },
        {
            'filename': 'config.py',
            'issue': 'aws_secret_key_proximity',
            'description': 'Possible AWS Secret Access Key',
            'matched': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',  # High entropy
            'line': 2,
        }
    ]

    print("\n🔍 Testing entropy filtering...")

    # Calculate entropy for each
    for finding in findings:
        matched = finding['matched']
        entropy = verifier._calculate_entropy(matched)
        print(f"  String: {matched[:20]}...")
        print(f"  Entropy: {entropy:.2f} bits/char")

    # Verify findings
    verified = verifier.verify_findings(findings)

    print(f"\n📊 Before verification: {len(findings)} findings")
    print(f"📊 After verification: {len(verified)} findings")

    # Low entropy string should be filtered out
    assert len(verified) < len(findings), "Should filter low entropy strings"

    print("\n✅ Entropy-based filtering PASSED\n")


def test_false_positive_40_char_strings():
    """Test that non-AWS 40-char strings don't trigger false positives"""
    print("=" * 70)
    print("TEST 6: False Positive Prevention (40-char strings)")
    print("=" * 70)

    scanner = SecurityScanner()

    # Test code with SHA-1 hash (40 hex chars) - should NOT be flagged
    test_code = """
# Git commit hash
commit_sha1 = "356a192b7913b04c54574d18c28d46e6395428ab"

# Some other 40-char ID
transaction_id = "TX1234567890ABCDEFGHIJ1234567890ABCD"
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        test_file = f.name

    try:
        issues = scanner.scan_file(test_file, test_code)

        # Filter for proximity-based AWS secrets
        proximity_issues = [i for i in issues if 'proximity' in i.get('issue', '')]

        print(f"\n📊 Found {len(proximity_issues)} proximity-based detections:")
        for issue in proximity_issues:
            print(f"  - Line {issue.get('line')}: {issue.get('matched')}")

        # Should NOT detect these as AWS secrets (no access key nearby)
        assert len(proximity_issues) == 0, "Should not flag 40-char strings without nearby AWS Access Key"

        print("  ✓ No false positives on SHA-1 hashes or other 40-char strings")
        print("\n✅ False positive prevention PASSED\n")

    finally:
        Path(test_file).unlink()


def main():
    """Run all AWS detection tests"""
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 20 + "AWS SECRET DETECTION TESTS" + " " * 22 + "║")
    print("╚" + "=" * 68 + "╝")
    print()

    tests = [
        ("AWS Access Key ID Detection", test_aws_access_key_detection),
        ("Context-Aware AWS Secret Detection", test_aws_secret_key_context_detection),
        ("Proximity-Based Detection", test_aws_proximity_detection),
        ("Verification Filters Test Files", test_aws_verification_filters_test_files),
        ("Entropy-Based Filtering", test_aws_verification_entropy_check),
        ("False Positive Prevention", test_false_positive_40_char_strings),
    ]

    passed = 0
    failed = 0

    for name, test_func in tests:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"\n❌ {name} FAILED: {e}\n")
            failed += 1
        except Exception as e:
            print(f"\n❌ {name} ERROR: {e}\n")
            failed += 1

    # Summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"\n✅ Passed: {passed}")
    if failed > 0:
        print(f"❌ Failed: {failed}")
    else:
        print("\n🎉 All AWS detection tests passed!")

    print("\n" + "=" * 70)
    print("AWS DETECTION FEATURES VALIDATED")
    print("=" * 70)
    print("""
AWS Secret Detection:
  ✅ AWS Access Key ID pattern detection (AKIA*, ASIA*, etc.)
  ✅ Context-aware AWS Secret Key detection (variable name matching)
  ✅ Proximity-based detection (40-char strings near access keys)
  ✅ Verification filters test/example files
  ✅ Entropy-based filtering (low entropy = test data)
  ✅ False positive prevention (SHA-1 hashes not flagged)

Implementation:
  • Pattern matching in security_scanner.py
  • Proximity detection with 5-line window
  • AWS-specific verification in finding_verifier.py
  • Semgrep rules for additional coverage
  • Context loader blocks .boto, .aws, .s3cfg files

Recommendation: Use IAM roles, instance profiles, or AWS Secrets Manager
""")

    return failed == 0


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
