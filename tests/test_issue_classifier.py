#!/usr/bin/env python3
"""
Test Issue Classifier
Validates pre-existing vs introduced detection using controlled diffs.
"""
import pytest
from issue_classifier import IssueClassifier


def test_parse_hunk_header():
    """Test parsing unified diff hunk headers"""
    classifier = IssueClassifier()

    # Test various hunk header formats
    test_cases = [
        ("@@ -10,5 +10,7 @@", {'old_start': 10, 'old_count': 5, 'new_start': 10, 'new_count': 7}),
        ("@@ -1 +1,2 @@", {'old_start': 1, 'old_count': 1, 'new_start': 1, 'new_count': 2}),
        ("@@ -42,3 +45,4 @@ def function():", {'old_start': 42, 'old_count': 3, 'new_start': 45, 'new_count': 4}),
    ]

    for header, expected in test_cases:
        result = classifier._parse_hunk_header(header)
        assert result == expected, f"Expected {expected}, got {result}"


def test_parse_patch():
    """Test parsing patch strings"""
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

    # Lines 12, 14, 16 should be marked as changed (added lines)
    expected_changed = {12, 14, 16}
    assert result['changed_lines'] == expected_changed, f"Expected {expected_changed}, got {result['changed_lines']}"


def test_classify_introduced_vs_preexisting():
    """Test classification of introduced vs pre-existing issues"""
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

    for finding in findings:
        origin = classifier.classify_issue_origin(finding, diff_context)
        finding['origin'] = origin
        line = finding['line']

        if line in diff_context['app.py']['changed_lines']:
            assert origin == 'introduced', f"Line {line} should be introduced"
        else:
            assert origin == 'pre-existing', f"Line {line} should be pre-existing"

    # Verify stats
    stats = classifier.get_classification_stats(findings)

    assert stats['introduced'] == 3, "Should have 3 introduced issues"
    assert stats['pre-existing'] == 2, "Should have 2 pre-existing issues"


def test_parse_github_pr_files():
    """Test parsing GitHub PR file format"""
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

    # Check new file
    assert 'src/new_file.py' in context
    assert context['src/new_file.py']['status'] == 'added'
    assert len(context['src/new_file.py']['changed_lines']) == 50, "All lines in new file should be changed"

    # Check modified file
    assert 'src/modified.py' in context
    assert context['src/modified.py']['status'] == 'modified'
    changed = context['src/modified.py']['changed_lines']
    assert 11 in changed and 13 in changed, "Added lines should be in changed_lines"

    # Check deleted file
    assert 'src/deleted.py' in context
    assert context['src/deleted.py']['status'] == 'removed'


def test_filter_by_origin():
    """Test filtering findings by origin"""
    classifier = IssueClassifier()

    findings = [
        {'issue': 'a', 'origin': 'introduced'},
        {'issue': 'b', 'origin': 'pre-existing'},
        {'issue': 'c', 'origin': 'introduced'},
        {'issue': 'd', 'origin': 'pre-existing'},
        {'issue': 'e', 'origin': 'introduced'},
    ]

    introduced = classifier.filter_by_origin(findings, 'introduced')
    pre_existing = classifier.filter_by_origin(findings, 'pre-existing')

    assert len(introduced) == 3, "Should have 3 introduced"
    assert len(pre_existing) == 2, "Should have 2 pre-existing"
