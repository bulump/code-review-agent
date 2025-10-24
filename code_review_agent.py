#!/usr/bin/env python3
"""
Code Review Agent
AI-powered automated code review tool for pull requests.
"""
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

# Load environment variables
load_dotenv()

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
def review(repo, pr_number, ai, output):
    """Review a GitHub pull request."""
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

            # Security scan
            task2 = progress.add_task("Scanning for security issues...", total=None)
            security_scanner = SecurityScanner()
            all_security_issues = []

            for file_data in pr_data['files']:
                if file_data.get('content'):
                    issues = security_scanner.scan_file(
                        file_data['filename'],
                        file_data['content']
                    )
                    all_security_issues.extend(issues)

            security_summary = security_scanner.get_summary(all_security_issues)
            progress.remove_task(task2)

            # Quality analysis
            task3 = progress.add_task("Analyzing code quality...", total=None)
            quality_analyzer = QualityAnalyzer()
            all_quality_issues = []

            for file_data in pr_data['files']:
                if file_data.get('content'):
                    metrics = quality_analyzer.analyze_file(
                        file_data['filename'],
                        file_data['content']
                    )
                    all_quality_issues.extend(metrics.get('issues', []))

            progress.remove_task(task3)

            # Display security results
            _display_security_results(all_security_issues, security_summary)

            # Display quality results
            _display_quality_results(all_quality_issues)

            # AI Review
            if ai and (all_security_issues or all_quality_issues):
                task4 = progress.add_task("Generating AI review...", total=None)
                ai_reviewer = AIReviewer()

                quality_summary = {
                    'total_issues': len(all_quality_issues),
                    'functions': sum(1 for i in all_quality_issues if 'function' in i.get('issue', '')),
                    'lines_of_code': sum(f.get('additions', 0) for f in pr_data['files']),
                }

                review = ai_reviewer.review_changes(
                    pr_data,
                    all_security_issues,
                    all_quality_issues
                )

                summary = ai_reviewer.generate_review_summary({
                    'security_summary': security_summary,
                    'quality_summary': quality_summary,
                })

                progress.remove_task(task4)

                console.print("\n")
                console.print(Panel(
                    Markdown(summary),
                    title="Review Summary",
                    border_style="green"
                ))

                console.print("\n")
                console.print(Panel(
                    Markdown(review),
                    title="AI-Powered Review",
                    border_style="blue"
                ))

                # Save to file if requested
                if output:
                    full_review = f"{summary}\n\n{review}"
                    with open(output, 'w') as f:
                        f.write(full_review)
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
    """Common logic for reviewing a list of files."""
    security_scanner = SecurityScanner()
    quality_analyzer = QualityAnalyzer()

    all_security_issues = []
    all_quality_issues = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Analyzing files...", total=len(files))

        for file_data in files:
            if file_data.get('content'):
                # Security scan
                sec_issues = security_scanner.scan_file(
                    file_data['filename'],
                    file_data['content']
                )
                all_security_issues.extend(sec_issues)

                # Quality analysis
                metrics = quality_analyzer.analyze_file(
                    file_data['filename'],
                    file_data['content']
                )
                all_quality_issues.extend(metrics.get('issues', []))

            progress.advance(task)

    # Display results
    security_summary = security_scanner.get_summary(all_security_issues)
    _display_security_results(all_security_issues, security_summary)
    _display_quality_results(all_quality_issues)

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


if __name__ == '__main__':
    cli()
