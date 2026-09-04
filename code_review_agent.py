#!/usr/bin/env python3
"""
Code Review Agent
AI-powered automated code review tool for pull requests.
"""
import warnings
# Suppress urllib3 NotOpenSSLWarning
warnings.filterwarnings('ignore', message='urllib3 v2 only supports OpenSSL 1.1.1+')

import click
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from dotenv import load_dotenv
import os

from pr_analyzer import PRAnalyzer
from security_scanner import SecurityScanner
from quality_analyzer import QualityAnalyzer
from ai_reviewer import AIReviewer

# Phase 2: Multi-Reviewer Architecture
from reviewers.review_orchestrator import ReviewOrchestrator
from issue_classifier import IssueClassifier

# Load environment variables (.env file takes precedence over shell environment)
load_dotenv(override=True)

console = Console()


@click.group()
def cli():
    """AI-Powered Code Review Agent - Automated security and quality analysis."""
    pass


@cli.command()
@click.argument('repo')
@click.argument('pr_number', type=int)
@click.option('--ai/--no-ai', default=True, help='Use AI-powered review')
@click.option('--output', '-o', type=click.Path(), help='Save review to file')
@click.option('--reviewers', help='Comma-separated list of reviewers (security,quality,architecture,testing,narrative)')
def review(repo, pr_number, ai, output, reviewers):
    """Review a GitHub pull request with Phase 2 multi-reviewer architecture."""
    console.print(f"\n[bold cyan]Reviewing PR #{pr_number} in {repo}[/bold cyan]\n")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            # Fetch PR data
            task1 = progress.add_task("Fetching PR data...", total=None)
            analyzer = PRAnalyzer()
            pr_data = analyzer.get_pr_details(repo, pr_number)
            progress.remove_task(task1)

            # Display PR info
            console.print(Panel(
                f"[bold]Title:[/bold] {pr_data['title']}\n"
                f"[bold]Author:[/bold] {pr_data['author']}\n"
                f"[bold]Files Changed:[/bold] {pr_data['files_changed']}\n"
                f"[bold]Changes:[/bold] +{pr_data['total_additions']} -{pr_data['total_deletions']}",
                title="Pull Request Info",
                border_style="cyan"
            ))

            # Phase 2: Multi-Reviewer Architecture
            task2 = progress.add_task("Running parallel review...", total=None)

            # Determine which reviewers to run
            if reviewers:
                enabled_reviewers = [r.strip() for r in reviewers.split(',')]
            elif ai:
                enabled_reviewers = ['security', 'quality', 'architecture', 'testing', 'narrative']
            else:
                enabled_reviewers = ['security', 'quality']

            # Run parallel review
            orchestrator = ReviewOrchestrator(
                enabled_reviewers=enabled_reviewers,
                enable_verification=True
            )

            result = orchestrator.run_parallel_review(pr_data['files'], repo_path=None)
            findings = result['findings']

            # Phase 3: Classify pre-existing vs introduced
            classifier = IssueClassifier()
            diff_context = classifier.parse_pr_files(pr_data['files'])

            for finding in findings:
                finding.origin = classifier.classify_issue_origin(finding.to_dict(), diff_context)

            progress.remove_task(task2)

            # Display results using Phase 2 format
            _display_phase2_results(findings, result['reviewer_results'])

            # Save to file if requested
            if output:
                review_text = _format_findings_as_markdown(findings, pr_data)
                with open(output, 'w') as f:
                    f.write(review_text)
                console.print(f"\n[green]✓ Review saved to {output}[/green]")

        console.print("\n[bold green]✓ Review complete![/bold green]\n")

    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {str(e)}\n")
        raise click.Abort()


@cli.command()
@click.argument('repo_path')
def review_local(repo_path):
    """Review uncommitted changes in a local repository."""
    console.print(f"\n[bold cyan]Reviewing local changes in {repo_path}[/bold cyan]\n")

    try:
        analyzer = PRAnalyzer()
        changes = analyzer.analyze_local_changes(repo_path)

        if not changes['files']:
            console.print("[yellow]No changes detected[/yellow]\n")
            return

        _review_files(changes['files'])

    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {str(e)}\n")
        raise click.Abort()


@cli.command()
@click.argument('files', nargs=-1, type=click.Path(exists=True))
def review_files(files):
    """Review specific files."""
    if not files:
        console.print("[yellow]No files specified[/yellow]\n")
        return

    console.print(f"\n[bold cyan]Reviewing {len(files)} file(s)[/bold cyan]\n")

    try:
        analyzer = PRAnalyzer()
        file_data = analyzer.analyze_files(list(files))

        _review_files(file_data['files'])

    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {str(e)}\n")
        raise click.Abort()


def _review_files(files):
    """Common logic for reviewing a list of files (Phase 2)."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Running parallel review...", total=None)

        # Check if AI key is available
        has_ai_key = bool(os.getenv('ANTHROPIC_API_KEY'))
        if has_ai_key:
            enabled_reviewers = ['security', 'quality', 'architecture', 'testing', 'narrative']
        else:
            enabled_reviewers = ['security', 'quality']
            console.print("[yellow]⚠️  ANTHROPIC_API_KEY not set - AI reviewers disabled[/yellow]\n")

        # Run Phase 2 parallel review
        orchestrator = ReviewOrchestrator(
            enabled_reviewers=enabled_reviewers,
            enable_verification=True
        )

        result = orchestrator.run_parallel_review(files, repo_path=None)
        findings = result['findings']

        progress.remove_task(task)

    # Display results using Phase 2 format
    _display_phase2_results(findings, result['reviewer_results'])

    console.print("\n[bold green]✓ Analysis complete![/bold green]\n")


def _display_security_results(issues, summary):
    """Display security analysis results."""
    console.print("\n[bold yellow]Security Analysis[/bold yellow]")

    if not issues:
        console.print("[green]✓ No security issues detected[/green]\n")
        return

    # Count issues by tool
    tool_counts = {}
    for issue in issues:
        tool = issue.get('tool', 'unknown')
        tool_counts[tool] = tool_counts.get(tool, 0) + 1

    tools_used = ", ".join([f"{tool}: {count}" for tool, count in tool_counts.items()])

    # Summary
    console.print(Panel(
        f"[bold red]Critical:[/bold red] {summary['critical']}\n"
        f"[bold yellow]High:[/bold yellow] {summary['high']}\n"
        f"[bold cyan]Medium:[/bold cyan] {summary['medium']}\n"
        f"[bold blue]Low:[/bold blue] {summary['low']}\n\n"
        f"[dim]Tools: {tools_used}[/dim]",
        title=f"Security Issues ({summary['total_issues']} total)",
        border_style="yellow"
    ))

    # Detailed issues (show critical and high only)
    critical_high = [i for i in issues if i.get('severity') in ['critical', 'high']]

    if critical_high:
        console.print("\n[bold]Critical & High Severity Issues:[/bold]\n")

        for issue in critical_high[:10]:  # Limit to 10
            severity_color = "red" if issue['severity'] == 'critical' else "yellow"
            tool_badge = f"[dim cyan]\\[{issue.get('tool', 'unknown')}][/dim cyan] " if issue.get('tool') else ""
            console.print(f"[{severity_color}]●[/{severity_color}] {tool_badge}[bold]{issue['issue']}[/bold]")
            console.print(f"  File: {issue.get('filename', 'N/A')}")
            if issue.get('line'):
                console.print(f"  Line: {issue['line']}")
            console.print(f"  {issue['description']}")
            if issue.get('confidence'):
                console.print(f"  Confidence: {issue['confidence']}")
            console.print(f"  [dim]→ {issue['recommendation']}[/dim]\n")


def _display_quality_results(issues):
    """Display code quality analysis results."""
    console.print("\n[bold cyan]Code Quality Analysis[/bold cyan]")

    if not issues:
        console.print("[green]✓ No quality issues detected[/green]\n")
        return

    # Count by severity
    severity_counts = {}
    for issue in issues:
        sev = issue.get('severity', 'info')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    console.print(Panel(
        f"[bold yellow]High:[/bold yellow] {severity_counts.get('high', 0)}\n"
        f"[bold cyan]Medium:[/bold cyan] {severity_counts.get('medium', 0)}\n"
        f"[bold blue]Low:[/bold blue] {severity_counts.get('low', 0)}\n"
        f"[bold]Info:[/bold] {severity_counts.get('info', 0)}",
        title=f"Quality Issues ({len(issues)} total)",
        border_style="cyan"
    ))

    # Show top issues
    high_medium = [i for i in issues if i.get('severity') in ['high', 'medium']]

    if high_medium:
        console.print("\n[bold]High & Medium Priority Issues:[/bold]\n")

        for issue in high_medium[:10]:  # Limit to 10
            console.print(f"● [bold]{issue['issue']}[/bold]")
            if issue.get('filename'):
                console.print(f"  File: {issue['filename']}")
            if issue.get('line'):
                console.print(f"  Line: {issue['line']}")
            console.print(f"  {issue['description']}")
            if issue.get('recommendation'):
                console.print(f"  [dim]→ {issue['recommendation']}[/dim]\n")


def _display_phase2_results(findings, reviewer_results):
    """Display Phase 2 multi-reviewer results."""
    # Reviewer summary
    console.print("\n[bold cyan]📊 Multi-Reviewer Results[/bold cyan]\n")

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Reviewer", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Findings", justify="right")

    for reviewer, stats in reviewer_results.items():
        status_icon = "✓" if stats['status'] == 'completed' else "✗"
        table.add_row(
            reviewer,
            f"{status_icon} {stats['status']}",
            str(stats['findings_count'])
        )

    console.print(table)

    if not findings:
        console.print("\n[green]✓ No issues detected[/green]\n")
        return

    # Group findings by severity
    by_severity = {}
    for finding in findings:
        severity = finding.severity
        if severity not in by_severity:
            by_severity[severity] = []
        by_severity[severity].append(finding)

    # Display summary panel
    severity_order = ['critical', 'high', 'medium', 'low']
    severity_counts = {s: len(by_severity.get(s, [])) for s in severity_order}

    console.print(Panel(
        f"[bold red]Critical:[/bold red] {severity_counts['critical']}\n"
        f"[bold yellow]High:[/bold yellow] {severity_counts['high']}\n"
        f"[bold cyan]Medium:[/bold cyan] {severity_counts['medium']}\n"
        f"[bold blue]Low:[/bold blue] {severity_counts['low']}",
        title=f"Findings Summary ({len(findings)} total)",
        border_style="yellow"
    ))

    # Display findings by severity
    for severity in severity_order:
        if severity in by_severity:
            severity_findings = by_severity[severity]

            # Color code
            colors = {
                'critical': 'red',
                'high': 'yellow',
                'medium': 'cyan',
                'low': 'blue'
            }
            color = colors.get(severity, 'white')

            # Only show critical and high in detail
            if severity in ['critical', 'high']:
                console.print(f"\n[bold {color}]{severity.upper()} Severity Issues:[/bold {color}]\n")

                for i, finding in enumerate(severity_findings[:10], 1):
                    # Reviewer badge
                    reviewer_badge = f"[dim cyan]\\[{finding.reviewer}][/dim cyan] " if finding.reviewer != 'unknown' else ""

                    # Pre-existing indicator
                    origin_badge = ""
                    if finding.origin == 'pre-existing':
                        origin_badge = " [dim yellow](pre-existing)[/dim yellow]"

                    console.print(f"[{color}]●[/{color}] {reviewer_badge}[bold]{finding.issue}[/bold]{origin_badge}")
                    console.print(f"  {finding.description}")
                    console.print(f"  File: {finding.filename}{':' + str(finding.line) if finding.line else ''}")
                    if finding.confidence != 'high':
                        console.print(f"  Confidence: {finding.confidence}")
                    console.print(f"  [dim]→ {finding.recommendation}[/dim]\n")

                if len(severity_findings) > 10:
                    console.print(f"  [dim]... and {len(severity_findings) - 10} more {severity} severity issues[/dim]\n")


def _format_findings_as_markdown(findings, pr_data):
    """Format findings as markdown for file output."""
    lines = []
    lines.append(f"# Code Review: {pr_data['title']}\n")
    lines.append(f"**Author:** {pr_data['author']}")
    lines.append(f"**Files Changed:** {pr_data['files_changed']}")
    lines.append(f"**Changes:** +{pr_data['total_additions']} -{pr_data['total_deletions']}\n")

    # Group by severity
    by_severity = {}
    for finding in findings:
        severity = finding.severity
        if severity not in by_severity:
            by_severity[severity] = []
        by_severity[severity].append(finding)

    # Summary
    lines.append("## Summary\n")
    for severity in ['critical', 'high', 'medium', 'low']:
        count = len(by_severity.get(severity, []))
        if count > 0:
            lines.append(f"- **{severity.capitalize()}:** {count}")

    lines.append(f"\n**Total Findings:** {len(findings)}\n")

    # Findings by severity
    for severity in ['critical', 'high', 'medium', 'low']:
        if severity in by_severity:
            lines.append(f"## {severity.capitalize()} Severity Issues\n")

            for i, finding in enumerate(by_severity[severity], 1):
                origin = " *(pre-existing)*" if finding.origin == 'pre-existing' else ""
                lines.append(f"### {i}. [{finding.reviewer}] {finding.issue}{origin}\n")
                lines.append(f"**File:** {finding.filename}{':' + str(finding.line) if finding.line else ''}\n")
                lines.append(f"**Description:** {finding.description}\n")
                lines.append(f"**Recommendation:** {finding.recommendation}\n")

    return "\n".join(lines)


if __name__ == '__main__':
    cli()
