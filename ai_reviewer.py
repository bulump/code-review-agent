"""
AI Code Reviewer
Uses Claude AI to provide intelligent code review feedback.
"""
from anthropic import Anthropic
import os
import json
from typing import Dict, List, Any
from finding_verifier import FindingVerifier
from context_loader import ContextLoader

# Model configuration
DEFAULT_MODEL = "claude-sonnet-4-5-20250929"
MAX_TOKENS_FULL_REVIEW = 4000
MAX_TOKENS_FILE_REVIEW = 2000
MAX_TOKENS_SUGGESTION = 1000


class AIReviewer:
    """AI-powered code reviewer using Claude."""

    def __init__(self, api_key: str = None, enable_verification: bool = True):
        """
        Initialize AI reviewer with Anthropic API key.

        Args:
            api_key: Anthropic API key (defaults to ANTHROPIC_API_KEY env var)
            enable_verification: Enable finding verification to reduce false positives
        """
        self.api_key = api_key or os.getenv('ANTHROPIC_API_KEY')
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY must be set")

        # Validate API key format (basic check)
        if not self._is_valid_api_key_format(self.api_key):
            raise ValueError("Invalid API key format")

        self.client = Anthropic(api_key=self.api_key)

        # Enhanced features
        self.enable_verification = enable_verification
        self.verifier = FindingVerifier() if enable_verification else None
        self.context_loader = ContextLoader()

    def _is_valid_api_key_format(self, key: str) -> bool:
        """
        Validate API key format without exposing the key.

        Args:
            key: API key to validate

        Returns:
            True if format is valid
        """
        # Anthropic keys typically start with 'sk-ant-' and are alphanumeric
        return (
            isinstance(key, str) and
            len(key) > 20 and
            key.startswith('sk-ant-')
        )

    def _sanitize_error(self, error: Exception) -> str:
        """
        Sanitize error messages to remove API keys.

        Args:
            error: Exception to sanitize

        Returns:
            Safe error message
        """
        error_str = str(error)

        # Replace API key with redacted placeholder
        if self.api_key and self.api_key in error_str:
            error_str = error_str.replace(self.api_key, '[REDACTED_API_KEY]')

        # Also redact anything that looks like an API key
        import re
        error_str = re.sub(r'sk-ant-[a-zA-Z0-9\-]+', '[REDACTED_API_KEY]', error_str)

        return error_str

    def review_changes(self, pr_data: Dict[str, Any],
                      security_issues: List[Dict],
                      quality_issues: List[Dict]) -> str:
        """
        Generate AI-powered code review with verification and context.

        Args:
            pr_data: Pull request data with file changes
            security_issues: Security issues found
            quality_issues: Code quality issues found

        Returns:
            Comprehensive review feedback
        """
        # Load project context
        changed_files = [f['filename'] for f in pr_data.get('files', [])]
        context = self.context_loader.load_context(changed_files)

        # Verify findings if enabled
        if self.enable_verification and self.verifier:
            security_issues = self.verifier.verify_findings(security_issues)
            quality_issues = self.verifier.verify_findings(quality_issues)

        # Build prompt with context
        prompt = self._build_review_prompt(pr_data, security_issues, quality_issues, context)

        try:
            message = self.client.messages.create(
                model=DEFAULT_MODEL,
                max_tokens=MAX_TOKENS_FULL_REVIEW,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            return message.content[0].text

        except Exception as e:
            # Sanitize and re-raise
            sanitized_msg = self._sanitize_error(e)
            raise RuntimeError(f"AI review failed: {sanitized_msg}") from None

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
        # Load project context
        project_context = self.context_loader.load_context([filename])
        context_section = self.context_loader.format_context_for_prompt(project_context)

        prompt = f"""You are an expert code reviewer. Review the following code file and provide feedback.

File: {filename}
{f"Context: {context}" if context else ""}

{context_section}

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

        try:
            message = self.client.messages.create(
                model=DEFAULT_MODEL,
                max_tokens=MAX_TOKENS_FILE_REVIEW,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )

            return {
                'filename': filename,
                'review': message.content[0].text
            }

        except Exception as e:
            sanitized_msg = self._sanitize_error(e)
            raise RuntimeError(f"File review failed: {sanitized_msg}") from None

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

        try:
            message = self.client.messages.create(
                model=DEFAULT_MODEL,
                max_tokens=MAX_TOKENS_SUGGESTION,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            return message.content[0].text

        except Exception as e:
            sanitized_msg = self._sanitize_error(e)
            raise RuntimeError(f"Suggestion generation failed: {sanitized_msg}") from None

    def _build_review_prompt(self, pr_data: Dict[str, Any],
                            security_issues: List[Dict],
                            quality_issues: List[Dict],
                            context: Dict[str, str] = None) -> str:
        """
        Build comprehensive review prompt for AI.

        Args:
            pr_data: Pull request data
            security_issues: Security issues found
            quality_issues: Quality issues found
            context: Project context (CLAUDE.md, REVIEW.md, rules)

        Returns:
            Formatted prompt string
        """
        context = context or {}

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

        # Format project context
        context_section = self.context_loader.format_context_for_prompt(context)

        prompt = f"""You are a senior software engineer performing a code review.

Pull Request: {pr_data.get('title', 'Untitled')}
Description: {pr_data.get('description', 'No description')}
Author: {pr_data.get('author', 'Unknown')}
Files Changed: {len(pr_data.get('files', []))}
Total Changes: +{pr_data.get('total_additions', 0)} -{pr_data.get('total_deletions', 0)}

Files Modified:
{json.dumps(files_summary, indent=2)}

{context_section}

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
