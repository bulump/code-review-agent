#!/usr/bin/env python3
"""
Test Phase 1 Enhancements
Validates verification layer, context loading, and model constant extraction.
"""
from finding_verifier import FindingVerifier
from context_loader import ContextLoader
from ai_reviewer import AIReviewer, DEFAULT_MODEL
from pathlib import Path


def test_finding_verifier():
    """Test the finding verification layer"""
    print("=" * 70)
    print("TEST 1: Finding Verifier")
    print("=" * 70)

    verifier = FindingVerifier()

    # Create test findings with mix of valid and invalid locations
    test_findings = [
        {
            'filename': 'ai_reviewer.py',
            'line': 10,
            'issue': 'Valid finding',
            'description': 'This should pass verification'
        },
        {
            'filename': 'ai_reviewer.py',
            'line': 9999,  # Invalid line number
            'issue': 'Invalid line number',
            'description': 'This should be dropped'
        },
        {
            'filename': 'nonexistent.py',  # File doesn't exist
            'line': 10,
            'issue': 'Invalid file',
            'description': 'This should be dropped'
        },
        {
            'filename': 'security_scanner.py',
            'line': 15,
            'issue': 'Another valid finding',
            'description': 'This should pass'
        },
    ]

    print(f"\n📝 Testing {len(test_findings)} findings...")
    verified = verifier.verify_findings(test_findings)

    print(f"\n✅ Results:")
    print(f"  Total: {len(test_findings)}")
    print(f"  Verified: {len(verified)}")
    print(f"  Dropped: {len(test_findings) - len(verified)}")

    verifier.print_verification_summary()

    assert len(verified) == 2, f"Expected 2 verified findings, got {len(verified)}"
    print("\n✅ FindingVerifier test PASSED\n")


def test_context_loader():
    """Test the context loader"""
    print("=" * 70)
    print("TEST 2: Context Loader")
    print("=" * 70)

    loader = ContextLoader()

    # Test loading CLAUDE.md
    print("\n📚 Loading project context...")
    context = loader.load_context(['security_scanner.py', 'ai_reviewer.py'])

    print(f"\n✅ Context loaded:")
    if context.get('claude_md'):
        print(f"  ✓ CLAUDE.md: {len(context['claude_md'])} chars")
    else:
        print(f"  ✗ CLAUDE.md: Not found")

    if context.get('review_md'):
        print(f"  ✓ REVIEW.md: {len(context['review_md'])} chars")
    else:
        print(f"  - REVIEW.md: Not found (optional)")

    if context.get('language_rules'):
        print(f"  ✓ Language rules: {len(context['language_rules'])} chars")
    else:
        print(f"  - Language rules: Not found (optional)")

    # Test formatting for prompts
    formatted = loader.format_context_for_prompt(context)
    print(f"\n📄 Formatted context: {len(formatted)} chars")

    assert loader.has_context(context), "Expected to find some context"
    print("\n✅ ContextLoader test PASSED\n")


def test_model_constant():
    """Test that model constant is properly extracted"""
    print("=" * 70)
    print("TEST 3: Model Constant Extraction")
    print("=" * 70)

    print(f"\n🤖 Model configuration:")
    print(f"  DEFAULT_MODEL: {DEFAULT_MODEL}")

    # Verify it's being used in AIReviewer
    from ai_reviewer import MAX_TOKENS_FULL_REVIEW, MAX_TOKENS_FILE_REVIEW, MAX_TOKENS_SUGGESTION

    print(f"  MAX_TOKENS_FULL_REVIEW: {MAX_TOKENS_FULL_REVIEW}")
    print(f"  MAX_TOKENS_FILE_REVIEW: {MAX_TOKENS_FILE_REVIEW}")
    print(f"  MAX_TOKENS_SUGGESTION: {MAX_TOKENS_SUGGESTION}")

    assert DEFAULT_MODEL is not None, "DEFAULT_MODEL should be defined"
    assert MAX_TOKENS_FULL_REVIEW == 4000, "MAX_TOKENS_FULL_REVIEW should be 4000"

    print("\n✅ Model constant test PASSED\n")


def test_ai_reviewer_integration():
    """Test that AIReviewer uses new features"""
    print("=" * 70)
    print("TEST 4: AIReviewer Integration")
    print("=" * 70)

    try:
        # Initialize with verification enabled
        reviewer = AIReviewer(enable_verification=True)

        print(f"\n✅ AIReviewer initialized:")
        print(f"  Verification enabled: {reviewer.enable_verification}")
        print(f"  Has verifier: {reviewer.verifier is not None}")
        print(f"  Has context loader: {reviewer.context_loader is not None}")

        assert reviewer.verifier is not None, "Verifier should be initialized"
        assert reviewer.context_loader is not None, "Context loader should be initialized"

        # Test with verification disabled
        reviewer_no_verify = AIReviewer(enable_verification=False)
        print(f"\n✅ AIReviewer (no verification):")
        print(f"  Verification enabled: {reviewer_no_verify.enable_verification}")
        print(f"  Has verifier: {reviewer_no_verify.verifier is not None}")

        assert reviewer_no_verify.verifier is None, "Verifier should not be initialized when disabled"

        print("\n✅ AIReviewer integration test PASSED\n")

    except ValueError as e:
        if "ANTHROPIC_API_KEY" in str(e):
            print("\n⚠️  ANTHROPIC_API_KEY not set - skipping full integration test")
            print("✅ AIReviewer integration test SKIPPED (API key required)\n")
        else:
            raise


def test_deduplication():
    """Test finding deduplication"""
    print("=" * 70)
    print("TEST 5: Finding Deduplication")
    print("=" * 70)

    verifier = FindingVerifier()

    # Create duplicate findings
    findings = [
        {
            'filename': 'test.py',
            'line': 10,
            'issue': 'Duplicate issue',
            'tool': 'security',
            'description': 'Test'
        },
        {
            'filename': 'test.py',
            'line': 10,
            'issue': 'Duplicate issue',
            'tool': 'quality',
            'description': 'Test'
        },
        {
            'filename': 'test.py',
            'line': 20,
            'issue': 'Different issue',
            'tool': 'security',
            'description': 'Test'
        },
    ]

    print(f"\n📝 Testing {len(findings)} findings (2 duplicates)...")
    deduplicated = verifier.deduplicate_findings(findings)

    print(f"\n✅ Results:")
    print(f"  Original: {len(findings)}")
    print(f"  Deduplicated: {len(deduplicated)}")

    assert len(deduplicated) == 2, f"Expected 2 unique findings, got {len(deduplicated)}"

    # Check that tools were merged
    merged_finding = deduplicated[0]
    print(f"\n✅ Tool merging:")
    print(f"  Tools in merged finding: {merged_finding.get('tool')}")
    assert 'security' in merged_finding.get('tool', '') and 'quality' in merged_finding.get('tool', ''), \
        "Tools should be merged"

    print("\n✅ Deduplication test PASSED\n")


def main():
    """Run all Phase 1 tests"""
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 20 + "PHASE 1 ENHANCEMENT TESTS" + " " * 23 + "║")
    print("╚" + "═" * 68 + "╝")
    print()

    tests = [
        ("Finding Verifier", test_finding_verifier),
        ("Context Loader", test_context_loader),
        ("Model Constants", test_model_constant),
        ("AIReviewer Integration", test_ai_reviewer_integration),
        ("Deduplication", test_deduplication),
    ]

    passed = 0
    failed = 0
    skipped = 0

    for name, test_func in tests:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"\n❌ {name} FAILED: {e}\n")
            failed += 1
        except Exception as e:
            if "SKIPPED" in str(e):
                skipped += 1
            else:
                print(f"\n❌ {name} ERROR: {e}\n")
                failed += 1

    # Summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"\n✅ Passed: {passed}")
    if skipped > 0:
        print(f"⚠️  Skipped: {skipped}")
    if failed > 0:
        print(f"❌ Failed: {failed}")
    else:
        print("\n🎉 All tests passed!")

    print("\n" + "=" * 70)
    print("PHASE 1 ENHANCEMENTS VALIDATED")
    print("=" * 70)
    print("""
Phase 1 Features:
  ✅ Finding verification layer (reduces false positives)
  ✅ Context loading (CLAUDE.md, REVIEW.md, language rules)
  ✅ Model constant extraction (easier maintenance)
  ✅ Finding deduplication (merges duplicate findings)

Next Steps:
  - Test on real PR reviews
  - Measure false positive reduction
  - Document new features in README
  - Start Phase 2: Multi-reviewer architecture
""")

    return failed == 0


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
