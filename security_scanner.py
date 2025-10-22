"""
Security Vulnerability Scanner
Detects common security issues in code.
"""
import re
from typing import List, Dict, Any
from pathlib import Path


class SecurityScanner:
    """Scans code for security vulnerabilities."""

    def __init__(self):
        """Initialize security scanner with vulnerability patterns."""
        self.patterns = self._init_patterns()

    def scan_file(self, filename: str, content: str) -> List[Dict[str, Any]]:
        """
        Scan a file for security vulnerabilities.

        Args:
            filename: Name of the file
            content: File content

        Returns:
            List of security issues found
        """
        issues = []
        file_ext = Path(filename).suffix.lower()

        # Run pattern-based checks
        for check_name, pattern_info in self.patterns.items():
            # Check if this pattern applies to this file type
            if file_ext in pattern_info.get('extensions', ['*']):
                matches = self._find_pattern_matches(
                    content, pattern_info['pattern'], pattern_info['multiline']
                )

                for line_num, match, context in matches:
                    issues.append({
                        'type': 'security',
                        'severity': pattern_info['severity'],
                        'issue': check_name,
                        'description': pattern_info['description'],
                        'line': line_num,
                        'code': context,
                        'matched': match,
                        'recommendation': pattern_info['recommendation'],
                    })

        # Run language-specific checks
        if file_ext == '.py':
            issues.extend(self._check_python_security(content))
        elif file_ext in ['.js', '.ts', '.jsx', '.tsx']:
            issues.extend(self._check_javascript_security(content))
        elif file_ext in ['.sql']:
            issues.extend(self._check_sql_security(content))

        return issues

    def _init_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize security vulnerability patterns."""
        return {
            'hardcoded_password': {
                'pattern': r'(password|passwd|pwd)\s*=\s*["\']([^"\']+)["\']',
                'severity': 'high',
                'description': 'Hardcoded password detected',
                'recommendation': 'Use environment variables or secure secret management',
                'multiline': False,
                'extensions': ['*'],
            },
            'hardcoded_api_key': {
                'pattern': r'(api[_-]?key|apikey|access[_-]?token)\s*=\s*["\']([a-zA-Z0-9_-]{20,})["\']',
                'severity': 'critical',
                'description': 'Hardcoded API key or token detected',
                'recommendation': 'Store secrets in environment variables or secret manager',
                'multiline': False,
                'extensions': ['*'],
            },
            'sql_injection': {
                'pattern': r'(execute|executemany|cursor\.execute)\s*\([^)]*[+%]\s*\w+',
                'severity': 'critical',
                'description': 'Potential SQL injection vulnerability (string concatenation)',
                'recommendation': 'Use parameterized queries or prepared statements',
                'multiline': False,
                'extensions': ['.py', '.java', '.php', '.rb'],
            },
            'command_injection': {
                'pattern': r'(os\.system|subprocess\.call|exec|eval|shell_exec)\s*\([^)]*[+%]\s*\w+',
                'severity': 'critical',
                'description': 'Potential command injection vulnerability',
                'recommendation': 'Use subprocess with list arguments, avoid shell=True',
                'multiline': False,
                'extensions': ['.py', '.js', '.php', '.rb'],
            },
            'path_traversal': {
                'pattern': r'open\s*\([^)]*\+\s*\w+|os\.path\.join\s*\([^)]*user',
                'severity': 'high',
                'description': 'Potential path traversal vulnerability',
                'recommendation': 'Validate and sanitize file paths, use os.path.normpath()',
                'multiline': False,
                'extensions': ['.py', '.java', '.php'],
            },
            'insecure_random': {
                'pattern': r'import\s+random|from\s+random\s+import',
                'severity': 'medium',
                'description': 'Using insecure random for potential security context',
                'recommendation': 'Use secrets module for cryptographic operations',
                'multiline': False,
                'extensions': ['.py'],
            },
            'debug_mode': {
                'pattern': r'DEBUG\s*=\s*True|debug\s*=\s*True|app\.debug\s*=\s*True',
                'severity': 'medium',
                'description': 'Debug mode enabled',
                'recommendation': 'Disable debug mode in production',
                'multiline': False,
                'extensions': ['.py', '.js', '.java'],
            },
            'unsafe_deserialization': {
                'pattern': r'pickle\.loads|yaml\.load\(|eval\(|exec\(',
                'severity': 'high',
                'description': 'Unsafe deserialization detected',
                'recommendation': 'Use safe_load for YAML, avoid pickle with untrusted data',
                'multiline': False,
                'extensions': ['.py'],
            },
            'weak_crypto': {
                'pattern': r'md5|MD5|sha1|SHA1|DES|RC4',
                'severity': 'medium',
                'description': 'Weak cryptographic algorithm detected',
                'recommendation': 'Use SHA256, SHA384, or SHA512 for hashing',
                'multiline': False,
                'extensions': ['*'],
            },
            'missing_csrf_protection': {
                'pattern': r'@app\.route.*methods.*POST(?!.*csrf)',
                'severity': 'high',
                'description': 'POST endpoint without apparent CSRF protection',
                'recommendation': 'Implement CSRF protection for state-changing operations',
                'multiline': True,
                'extensions': ['.py'],
            },
        }

    def _find_pattern_matches(self, content: str, pattern: str, multiline: bool) -> List[tuple]:
        """Find all matches of a pattern in content."""
        matches = []
        lines = content.split('\n')

        if multiline:
            # Search entire content
            for match in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                context = lines[line_num - 1] if line_num <= len(lines) else ''
                matches.append((line_num, match.group(0), context))
        else:
            # Search line by line
            for line_num, line in enumerate(lines, 1):
                for match in re.finditer(pattern, line, re.IGNORECASE):
                    matches.append((line_num, match.group(0), line.strip()))

        return matches

    def _check_python_security(self, content: str) -> List[Dict[str, Any]]:
        """Python-specific security checks."""
        issues = []

        # Check for pickle without safety
        if 'pickle' in content and 'safe' not in content.lower():
            issues.append({
                'type': 'security',
                'severity': 'high',
                'issue': 'unsafe_pickle',
                'description': 'Using pickle without safety considerations',
                'recommendation': 'Validate pickle source, consider JSON or safer alternatives',
            })

        # Check for Flask without HTTPS
        if 'Flask' in content and 'ssl_context' not in content:
            issues.append({
                'type': 'security',
                'severity': 'medium',
                'issue': 'missing_https',
                'description': 'Flask app without HTTPS configuration',
                'recommendation': 'Use SSL/TLS in production',
            })

        return issues

    def _check_javascript_security(self, content: str) -> List[Dict[str, Any]]:
        """JavaScript-specific security checks."""
        issues = []

        # Check for eval usage
        if re.search(r'\beval\s*\(', content):
            issues.append({
                'type': 'security',
                'severity': 'high',
                'issue': 'eval_usage',
                'description': 'Use of eval() can lead to code injection',
                'recommendation': 'Avoid eval(), use JSON.parse() or safer alternatives',
            })

        # Check for innerHTML
        if re.search(r'\.innerHTML\s*=', content):
            issues.append({
                'type': 'security',
                'severity': 'medium',
                'issue': 'innerHTML_xss',
                'description': 'Using innerHTML can lead to XSS vulnerabilities',
                'recommendation': 'Use textContent or sanitize HTML input',
            })

        return issues

    def _check_sql_security(self, content: str) -> List[Dict[str, Any]]:
        """SQL-specific security checks."""
        issues = []

        # Check for SELECT *
        if re.search(r'SELECT\s+\*', content, re.IGNORECASE):
            issues.append({
                'type': 'security',
                'severity': 'low',
                'issue': 'select_star',
                'description': 'SELECT * can expose sensitive data',
                'recommendation': 'Explicitly specify columns needed',
            })

        return issues

    def get_summary(self, issues: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary of security issues."""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        for issue in issues:
            severity = issue.get('severity', 'low')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            'total_issues': len(issues),
            'critical': severity_counts['critical'],
            'high': severity_counts['high'],
            'medium': severity_counts['medium'],
            'low': severity_counts['low'],
            'has_critical': severity_counts['critical'] > 0,
        }
