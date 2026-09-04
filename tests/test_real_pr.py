#!/usr/bin/env python3
"""
Test Phase 1 Enhancements on Real Files
Simulates a PR review using the enhanced AI reviewer.
"""
from ai_reviewer import AIReviewer
from security_scanner import SecurityScanner
from quality_analyzer import QualityAnalyzer
from pathlib import Path
import json


def simulate_pr_review():
    """Simulate a PR review on recently modified files"""
    print("=" * 70)
    print("TESTING PHASE 1 ON REAL FILES")
    print("=" * 70)

    # Files we've been working on
    files_to_review = [
        'finding_verifier.py',
        'context_loader.py',
        'ai_reviewer.py'
    ]

    # Simulate PR data
    pr_data = {
        'title': 'Phase 1: Add AI verification layer and context loading',
        'description': 'Adds finding verification to reduce false positives and project context loading',
        'author': 'claude-code',
        'files': [],
        'total_additions': 0,
        'total_deletions': 0,
        'files_changed': len(files_to_review)
    }

    # Load file contents
    print(f"\n📁 Loading {len(files_to_review)} files...")
    for filename in files_to_review:
        file_path = Path(filename)
        if file_path.exists():
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = len(content.split('\n'))
                pr_data['files'].append({
                    'filename': filename,
                    'status': 'added',
                    'content': content,
                    'additions': lines,
                    'deletions': 0,
                    'changes': lines
                })
                pr_data['total_additions'] += lines
                print(f"  ✓ {filename} ({lines} lines)")
        else:
            print(f"  ✗ {filename} (not found)")

    if not pr_data['files']:
        print("\n❌ No files found to review")
        return

    # Step 1: Run security scanner
    print(f"\n🔒 Running security analysis...")
    security_scanner = SecurityScanner()
    all_security_issues = []

    for file_data in pr_data['files']:
        issues = security_scanner.scan_file(
            file_data['filename'],
            file_data['content']
        )
        all_security_issues.extend(issues)

    security_summary = security_scanner.get_summary(all_security_issues)
    print(f"  Security issues found: {security_summary['total_issues']}")
    print(f"    Critical: {security_summary['critical']}")
    print(f"    High: {security_summary['high']}")
    print(f"    Medium: {security_summary['medium']}")
    print(f"    Low: {security_summary['low']}")

    # Step 2: Run quality analyzer
    print(f"\n📊 Running quality analysis...")
    quality_analyzer = QualityAnalyzer()
    all_quality_issues = []

    for file_data in pr_data['files']:
        metrics = quality_analyzer.analyze_file(
            file_data['filename'],
            file_data['content']
        )
        all_quality_issues.extend(metrics.get('issues', []))

    print(f"  Quality issues found: {len(all_quality_issues)}")

    # Show top issues
    if all_quality_issues:
        high_priority = [i for i in all_quality_issues if i.get('severity') in ['high', 'medium']]
        if high_priority:
            print(f"    High/Medium priority: {len(high_priority)}")

    # Step 3: Run AI review WITH verification and context
    print(f"\n🤖 Running AI review with Phase 1 enhancements...")
    print(f"  Features enabled:")
    print(f"    ✓ AI finding verification")
    print(f"    ✓ Project context loading")
    print(f"    ✓ Model constants")

    try:
        # Initialize with verification enabled
        reviewer = AIReviewer(enable_verification=True)

        # Check initial counts
        print(f"\n  Before verification:")
        print(f"    Security issues: {len(all_security_issues)}")
        print(f"    Quality issues: {len(all_quality_issues)}")

        # Generate review (verification happens automatically)
        review = reviewer.review_changes(
            pr_data,
            all_security_issues,
            all_quality_issues
        )

        # Get verification stats
        if reviewer.verifier:
            stats = reviewer.verifier.get_verification_stats()
            print(f"\n  After verification:")
            print(f"    Total findings processed: {stats['total']}")
            print(f"    Verified findings: {stats['verified']}")
            print(f"    Dropped (location): {stats['dropped_location']}")
            print(f"    Dropped (claim): {stats['dropped_claim']}")
            if stats['total'] > 0:
                print(f"    Drop rate: {stats['drop_rate']:.1%}")

        # Check context loading
        if reviewer.context_loader:
            changed_files = [f['filename'] for f in pr_data['files']]
            context = reviewer.context_loader.load_context(changed_files)
            if reviewer.context_loader.has_context(context):
                print(f"\n  Context loaded:")
                if context.get('claude_md'):
                    print(f"    ✓ CLAUDE.md ({len(context['claude_md'])} chars)")
                if context.get('review_md'):
                    print(f"    ✓ REVIEW.md ({len(context['review_md'])} chars)")
                if context.get('language_rules'):
                    print(f"    ✓ Language rules ({len(context['language_rules'])} chars)")

        # Display review
        print("\n" + "=" * 70)
        print("AI REVIEW OUTPUT")
        print("=" * 70)
        print()
        print(review)
        print()
        print("=" * 70)

        # Summary
        print("\n✅ Phase 1 Review Complete!")
        print(f"\n📊 Summary:")
        print(f"  Files reviewed: {len(pr_data['files'])}")
        print(f"  Lines added: {pr_data['total_additions']}")
        print(f"  AI verification: {'ENABLED' if reviewer.enable_verification else 'DISABLED'}")
        print(f"  Context awareness: {'ENABLED' if reviewer.context_loader else 'DISABLED'}")

    except ValueError as e:
        if "ANTHROPIC_API_KEY" in str(e):
            print("\n⚠️  ANTHROPIC_API_KEY not set")
            print("  Set your API key to test AI review functionality")
            print("  Testing verification and context loading only...\n")

            # Test verification without AI
            from finding_verifier import FindingVerifier
            verifier = FindingVerifier()

            combined_issues = all_security_issues + all_quality_issues
            print(f"  Total findings before verification: {len(combined_issues)}")

            verified = verifier.verify_findings(combined_issues)
            print(f"  Verified findings: {len(verified)}")

            stats = verifier.get_verification_stats()
            print(f"  Dropped: {stats['dropped_location'] + stats['dropped_claim']}")
            if stats['total'] > 0:
                print(f"  Drop rate: {stats['drop_rate']:.1%}")

            # Test context loading
            from context_loader import ContextLoader
            loader = ContextLoader()
            context = loader.load_context(files_to_review)

            if loader.has_context(context):
                print(f"\n  Context loaded successfully:")
                if context.get('claude_md'):
                    print(f"    ✓ CLAUDE.md ({len(context['claude_md'])} chars)")

            print("\n✅ Verification and context loading work!")
            print("  (Full AI review requires ANTHROPIC_API_KEY)")
        else:
            raise


if __name__ == "__main__":
    simulate_pr_review()
