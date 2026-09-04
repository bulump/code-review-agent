#!/usr/bin/env python3
"""
Test Issue Classifier
Validates pre-existing vs introduced detection using controlled diffs.
"""
from issue_classifier import IssueClassifier


def test_parse_hunk_header():
    """Test parsing unified diff hunk headers"""
    print("=" * 70)
    print("TEST 1: Parse Hunk Header")
    print("=" * 70)

    classifier = IssueClassifier()

    # Test various hunk header formats
    test_cases = [
        ("@@ -10,5 +10,7 @@", {'old_start': 10, 'old_count': 5, 'new_start': 10, 'new_count': 7}),
        ("@@ -1 +1,2 @@", {'old_start': 1, 'old_count': 1, 'new_start': 1, 'new_count': 2}),
        ("@@ -42,3 +45,4 @@ def function():", {'old_start': 42, 'old_count': 3, 'new_start': 45, 'new_count': 4}),
    ]

    print("\n🔍 Testing hunk header parsing:")
    for header, expected in test_cases:
        result = classifier._parse_hunk_header(header)
        print(f"  Header: {header}")
        print(f"  Result: {result}")
        assert result == expected, f"Expected {expected}, got {result}"
        print("  ✓ Correct")

    print("\n✅ Hunk header parsing test PASSED\n")


def test_parse_patch():
    """Test parsing patch strings"""
    print("=" * 70)
    print("TEST 2: Parse Patch")
    print("=" * 70)

    classifier = IssueClassifier()

    # Sample patch with added and removed lines
    patch = """@@ -10,5 +10,7 @@ def function():
     existing_line_10
     existing_line_11
+    new_line_12
     existing_line_13
-    removed_line
+    new_line_14
     existing_line_15
+    new_line_16"""

    result = classifier._parse_patch(patch)

    print("\n📝 Patch analysis:")
    print(f"  Changed lines: {sorted(result['changed_lines'])}")
    print(f"  Hunks: {result['hunks']}")

    # Lines 12, 14, 16 should be marked as changed (added lines)
    expected_changed = {12, 14, 16}
    assert result['changed_lines'] == expected_changed, f"Expected {expected_changed}, got {result['changed_lines']}"
    print("  ✓ Correctly identified added lines")

    print("\n✅ Patch parsing test PASSED\n")


def test_classify_introduced_vs_preexisting():
    """Test classification of introduced vs pre-existing issues"""
    print("=" * 70)
    print("TEST 3: Classify Introduced vs Pre-existing")
    print("=" * 70)

    classifier = IssueClassifier()

    # Create diff context
    diff_context = {
        'app.py': {
            'changed_lines': {10, 11, 12, 20, 21},  # Lines that were added/modified
            'hunks': [],
        }
    }

    # Test findings at different locations
    findings = [
        {'filename': 'app.py', 'line': 10, 'issue': 'test1'},  # In changed lines
        {'filename': 'app.py', 'line': 11, 'issue': 'test2'},  # In changed lines
        {'filename': 'app.py', 'line': 15, 'issue': 'test3'},  # NOT in changed lines
        {'filename': 'app.py', 'line': 30, 'issue': 'test4'},  # NOT in changed lines
        {'filename': 'app.py', 'line': 20, 'issue': 'test5'},  # In changed lines
    ]

    print("\n🔍 Classifying findings:")
    for finding in findings:
        origin = classifier.classify_issue_origin(finding, diff_context)
        finding['origin'] = origin
        line = finding['line']
        print(f"  Line {line}: {origin}")

        if line in diff_context['app.py']['changed_lines']:
            assert origin == 'introduced', f"Line {line} should be introduced"
        else:
            assert origin == 'pre-existing', f"Line {line} should be pre-existing"

    # Verify stats
    stats = classifier.get_classification_stats(findings)
    print(f"\n📊 Classification stats:")
    print(f"  Total: {stats['total']}")
    print(f"  Introduced: {stats['introduced']}")
    print(f"  Pre-existing: {stats['pre-existing']}")

    assert stats['introduced'] == 3, "Should have 3 introduced issues"
    assert stats['pre-existing'] == 2, "Should have 2 pre-existing issues"
    print("  ✓ Correct classification counts")

    print("\n✅ Classification test PASSED\n")


def test_parse_github_pr_files():
    """Test parsing GitHub PR file format"""
    print("=" * 70)
    print("TEST 4: Parse GitHub PR Files")
    print("=" * 70)

    classifier = IssueClassifier()

    # Simulate GitHub PR files
    pr_files = [
        {
            'filename': 'src/new_file.py',
            'status': 'added',
            'additions': 50,
            'patch': None,
        },
        {
            'filename': 'src/modified.py',
            'status': 'modified',
            'patch': """@@ -10,3 +10,5 @@ def test():
     line_10
+    line_11_new
     line_12
+    line_13_new
     line_14""",
        },
        {
            'filename': 'src/deleted.py',
            'status': 'removed',
            'deletions': 30,
        },
    ]

    context = classifier.parse_pr_files(pr_files)

    print("\n📂 Parsed PR files:")

    # Check new file
    assert 'src/new_file.py' in context
    assert context['src/new_file.py']['status'] == 'added'
    print(f"  src/new_file.py: status={context['src/new_file.py']['status']}, " +
          f"changed_lines={len(context['src/new_file.py']['changed_lines'])}")
    assert len(context['src/new_file.py']['changed_lines']) == 50, "All lines in new file should be changed"
    print("    ✓ New file: all lines marked as introduced")

    # Check modified file
    assert 'src/modified.py' in context
    assert context['src/modified.py']['status'] == 'modified'
    changed = context['src/modified.py']['changed_lines']
    print(f"  src/modified.py: status={context['src/modified.py']['status']}, changed_lines={sorted(changed)}")
    assert 11 in changed and 13 in changed, "Added lines should be in changed_lines"
    print("    ✓ Modified file: only added lines marked as changed")

    # Check deleted file
    assert 'src/deleted.py' in context
    assert context['src/deleted.py']['status'] == 'removed'
    print(f"  src/deleted.py: status={context['src/deleted.py']['status']}")
    print("    ✓ Deleted file: marked as removed")

    print("\n✅ GitHub PR files parsing test PASSED\n")


def test_filter_by_origin():
    """Test filtering findings by origin"""
    print("=" * 70)
    print("TEST 5: Filter by Origin")
    print("=" * 70)

    classifier = IssueClassifier()

    findings = [
        {'issue': 'a', 'origin': 'introduced'},
        {'issue': 'b', 'origin': 'pre-existing'},
        {'issue': 'c', 'origin': 'introduced'},
        {'issue': 'd', 'origin': 'pre-existing'},
        {'issue': 'e', 'origin': 'introduced'},
    ]

    print("\n🔍 Filtering findings:")
    introduced = classifier.filter_by_origin(findings, 'introduced')
    pre_existing = classifier.filter_by_origin(findings, 'pre-existing')

    print(f"  Total findings: {len(findings)}")
    print(f"  Introduced: {len(introduced)}")
    print(f"  Pre-existing: {len(pre_existing)}")

    assert len(introduced) == 3, "Should have 3 introduced"
    assert len(pre_existing) == 2, "Should have 2 pre-existing"
    print("  ✓ Correct filtering")

    print("\n✅ Filter by origin test PASSED\n")


def main():
    """Run all issue classifier tests"""
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 20 + "ISSUE CLASSIFIER TESTS" + " " * 24 + "║")
    print("╚" + "=" * 68 + "╝")
    print()

    tests = [
        ("Parse Hunk Header", test_parse_hunk_header),
        ("Parse Patch", test_parse_patch),
        ("Classify Introduced vs Pre-existing", test_classify_introduced_vs_preexisting),
        ("Parse GitHub PR Files", test_parse_github_pr_files),
        ("Filter by Origin", test_filter_by_origin),
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
            import traceback
            traceback.print_exc()
            failed += 1

    # Summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"\n✅ Passed: {passed}")
    if failed > 0:
        print(f"❌ Failed: {failed}")
    else:
        print("\n🎉 All issue classifier tests passed!")

    print("\n" + "=" * 70)
    print("ISSUE CLASSIFICATION VALIDATED")
    print("=" * 70)
    print("""
Pre-existing vs Introduced Detection:
  ✅ Parses unified diff hunk headers
  ✅ Parses patch strings to extract changed lines
  ✅ Classifies findings based on line numbers
  ✅ Handles GitHub PR file format
  ✅ Filters findings by origin
  ✅ Provides classification statistics

Implementation:
  • Uses diff context to identify changed lines
  • Marks issues in changed lines as "introduced"
  • Marks issues in unchanged lines as "pre-existing"
  • Handles added, modified, and removed files
  • Compatible with GitHub PR API format

Benefits:
  • Focus reviews on newly introduced issues
  • Track technical debt (pre-existing issues)
  • Prioritize blockers on new code
  • Generate reports: "This PR introduces 5 new issues"
""")

    return failed == 0


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
