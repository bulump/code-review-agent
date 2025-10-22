"""
AI Code Reviewer
Uses Claude AI to provide intelligent code review feedback.
"""
from anthropic import Anthropic
import os
import json
from typing import Dict, List, Any


class AIReviewer:
    """AI-powered code reviewer using Claude."""

    def __init__(self, api_key: str = None):
        """Initialize AI reviewer with Anthropic API key."""
        self.api_key = api_key or os.getenv('ANTHROPIC_API_KEY')
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY must be set")
        self.client = Anthropic(api_key=self.api_key)

    def review_changes(self, pr_data: Dict[str, Any],
                      security_issues: List[Dict],
                      quality_issues: List[Dict]) -> str:
        """
        Generate AI-powered code review.

        Args:
            pr_data: Pull request data with file changes
            security_issues: Security issues found
            quality_issues: Code quality issues found

        Returns:
            Comprehensive review feedback
        """
        prompt = self._build_review_prompt(pr_data, security_issues, quality_issues)

        message = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4000,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        return message.content[0].text

    def review_file(self, filename: str, content: str,
                   context: str = "") -> Dict[str, Any]:
        """
        Review a single file with AI.

        Args:
            filename: Name of the file
            content: File content
            context: Additional context about the change

        Returns:
            Review feedback dictionary
        """
        prompt = f"""You are an expert code reviewer. Review the following code file and provide feedback.

File: {filename}
{f"Context: {context}" if context else ""}

Code:
```
{content}
```

Provide a structured review covering:
1. **Security Concerns**: Any potential security vulnerabilities
2. **Code Quality**: Readability, maintainability, and best practices
3. **Performance**: Potential performance issues or optimizations
4. **Best Practices**: Language-specific conventions and patterns
5. **Positive Aspects**: What's done well

Focus on actionable, specific feedback with examples where helpful.
"""

        message = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        return {
            'filename': filename,
            'review': message.content[0].text
        }

    def suggest_improvements(self, code_snippet: str, issue_type: str) -> str:
        """
        Get AI suggestions for improving a specific code issue.

        Args:
            code_snippet: The problematic code
            issue_type: Type of issue (security, quality, performance)

        Returns:
            Improvement suggestions
        """
        prompt = f"""You are an expert code reviewer. A {issue_type} issue was detected in this code:

```
{code_snippet}
```

Provide:
1. A clear explanation of why this is an issue
2. Specific code example showing how to fix it
3. Best practices to prevent similar issues

Be concise but specific.
"""

        message = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1000,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        return message.content[0].text

    def _build_review_prompt(self, pr_data: Dict[str, Any],
                            security_issues: List[Dict],
                            quality_issues: List[Dict]) -> str:
        """Build comprehensive review prompt for AI."""

        # Summarize files changed
        files_summary = []
        for file_data in pr_data.get('files', [])[:10]:  # Limit to first 10 files
            files_summary.append({
                'filename': file_data['filename'],
                'status': file_data['status'],
                'additions': file_data.get('additions', 0),
                'deletions': file_data.get('deletions', 0),
            })

        # Categorize issues
        security_critical = [i for i in security_issues if i.get('severity') == 'critical']
        security_high = [i for i in security_issues if i.get('severity') == 'high']
        quality_medium_high = [i for i in quality_issues if i.get('severity') in ['high', 'medium']]

        prompt = f"""You are a senior software engineer performing a code review.

Pull Request: {pr_data.get('title', 'Untitled')}
Description: {pr_data.get('description', 'No description')}
Author: {pr_data.get('author', 'Unknown')}
Files Changed: {len(pr_data.get('files', []))}
Total Changes: +{pr_data.get('total_additions', 0)} -{pr_data.get('total_deletions', 0)}

Files Modified:
{json.dumps(files_summary, indent=2)}

Automated Analysis Found:
- {len(security_critical)} Critical Security Issues
- {len(security_high)} High Security Issues
- {len(quality_medium_high)} Medium/High Quality Issues

Critical Security Issues:
{json.dumps(security_critical[:5], indent=2) if security_critical else "None"}

High Priority Quality Issues:
{json.dumps(quality_medium_high[:5], indent=2) if quality_medium_high else "None"}

Please provide a comprehensive code review with:

1. **Overall Assessment** (2-3 sentences)
2. **Security Concerns** (prioritized list with severity)
3. **Code Quality Feedback** (maintainability, readability, best practices)
4. **Architecture & Design** (if applicable)
5. **Testing Recommendations** (what should be tested)
6. **Approval Recommendation** (Approve / Request Changes / Needs Discussion)

Be specific and actionable. Reference actual issues found. Consider the context and size of the change.
Format your response in clear markdown sections.
"""

        return prompt

    def generate_review_summary(self, review_results: Dict[str, Any]) -> str:
        """
        Generate a concise summary of review results.

        Args:
            review_results: Complete review results

        Returns:
            Markdown-formatted summary
        """
        security_summary = review_results.get('security_summary', {})
        quality_summary = review_results.get('quality_summary', {})

        summary = f"""# Code Review Summary

## Security Analysis
- **Critical**: {security_summary.get('critical', 0)} issues
- **High**: {security_summary.get('high', 0)} issues
- **Medium**: {security_summary.get('medium', 0)} issues
- **Low**: {security_summary.get('low', 0)} issues

## Code Quality
- **Total Issues**: {quality_summary.get('total_issues', 0)}
- **Functions Analyzed**: {quality_summary.get('functions', 0)}
- **Lines of Code**: {quality_summary.get('lines_of_code', 0)}

## Recommendation
"""

        if security_summary.get('critical', 0) > 0:
            summary += "❌ **Request Changes** - Critical security issues must be addressed\n"
        elif security_summary.get('high', 0) > 0:
            summary += "⚠️ **Request Changes** - High priority security issues found\n"
        elif quality_summary.get('total_issues', 0) > 10:
            summary += "⚠️ **Request Changes** - Multiple quality issues should be addressed\n"
        else:
            summary += "✅ **Approve with Comments** - Minor issues can be addressed in follow-up\n"

        return summary
