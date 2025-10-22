"""
Code Quality Analyzer
Analyzes code complexity, maintainability, and quality metrics.
"""
import re
from typing import Dict, List, Any
from pathlib import Path
import ast


class QualityAnalyzer:
    """Analyzes code quality metrics."""

    def analyze_file(self, filename: str, content: str) -> Dict[str, Any]:
        """
        Analyze code quality for a file.

        Args:
            filename: Name of the file
            content: File content

        Returns:
            Dictionary of quality metrics and issues
        """
        file_ext = Path(filename).suffix.lower()

        metrics = {
            'filename': filename,
            'lines_of_code': len(content.split('\n')),
            'issues': [],
        }

        # Language-specific analysis
        if file_ext == '.py':
            metrics.update(self._analyze_python(content))
        elif file_ext in ['.js', '.ts', '.jsx', '.tsx']:
            metrics.update(self._analyze_javascript(content))

        # General code quality checks
        metrics['issues'].extend(self._check_general_quality(content, filename))

        return metrics

    def _analyze_python(self, content: str) -> Dict[str, Any]:
        """Analyze Python code quality."""
        issues = []
        metrics = {}

        try:
            tree = ast.parse(content)

            # Count functions and classes
            functions = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
            classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]

            metrics['functions'] = len(functions)
            metrics['classes'] = len(classes)

            # Check function complexity
            for func in functions:
                complexity = self._calculate_complexity(func)
                if complexity > 10:
                    issues.append({
                        'type': 'quality',
                        'severity': 'medium',
                        'issue': 'high_complexity',
                        'description': f'Function "{func.name}" has high complexity ({complexity})',
                        'line': func.lineno,
                        'recommendation': 'Consider breaking down into smaller functions',
                    })

                # Check function length
                if hasattr(func, 'end_lineno'):
                    length = func.end_lineno - func.lineno
                    if length > 50:
                        issues.append({
                            'type': 'quality',
                            'severity': 'low',
                            'issue': 'long_function',
                            'description': f'Function "{func.name}" is {length} lines long',
                            'line': func.lineno,
                            'recommendation': 'Consider splitting into smaller, focused functions',
                        })

            # Check for missing docstrings
            for node in functions + classes:
                if not ast.get_docstring(node):
                    node_type = 'Function' if isinstance(node, ast.FunctionDef) else 'Class'
                    issues.append({
                        'type': 'quality',
                        'severity': 'low',
                        'issue': 'missing_docstring',
                        'description': f'{node_type} "{node.name}" missing docstring',
                        'line': node.lineno,
                        'recommendation': 'Add docstring to document purpose and usage',
                    })

        except SyntaxError as e:
            issues.append({
                'type': 'quality',
                'severity': 'critical',
                'issue': 'syntax_error',
                'description': f'Syntax error: {str(e)}',
                'line': e.lineno if hasattr(e, 'lineno') else 0,
                'recommendation': 'Fix syntax error before proceeding',
            })

        metrics['issues'] = issues
        return metrics

    def _calculate_complexity(self, func_node: ast.FunctionDef) -> int:
        """Calculate cyclomatic complexity of a function."""
        complexity = 1  # Base complexity

        for node in ast.walk(func_node):
            # Increment for control flow statements
            if isinstance(node, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(node, ast.BoolOp):
                # And/Or operators add complexity
                complexity += len(node.values) - 1

        return complexity

    def _analyze_javascript(self, content: str) -> Dict[str, Any]:
        """Analyze JavaScript/TypeScript code quality."""
        issues = []
        metrics = {}

        # Count functions (basic regex matching)
        func_patterns = [
            r'function\s+\w+',  # function declarations
            r'const\s+\w+\s*=\s*\([^)]*\)\s*=>',  # arrow functions
            r'async\s+function',  # async functions
        ]

        func_count = sum(len(re.findall(pattern, content)) for pattern in func_patterns)
        metrics['functions'] = func_count

        # Check for console.log (should be removed in production)
        for match in re.finditer(r'console\.(log|debug|info)', content):
            line_num = content[:match.start()].count('\n') + 1
            issues.append({
                'type': 'quality',
                'severity': 'low',
                'issue': 'console_log',
                'description': 'Console.log statement found',
                'line': line_num,
                'recommendation': 'Remove debug statements before production',
            })

        # Check for var usage
        for match in re.finditer(r'\bvar\s+\w+', content):
            line_num = content[:match.start()].count('\n') + 1
            issues.append({
                'type': 'quality',
                'severity': 'low',
                'issue': 'var_usage',
                'description': 'Using "var" instead of "let" or "const"',
                'line': line_num,
                'recommendation': 'Use "let" or "const" for better scoping',
            })

        # Check for == instead of ===
        for match in re.finditer(r'[^=!<>]={2}[^=]', content):
            line_num = content[:match.start()].count('\n') + 1
            issues.append({
                'type': 'quality',
                'severity': 'low',
                'issue': 'loose_equality',
                'description': 'Using loose equality (==) instead of strict (===)',
                'line': line_num,
                'recommendation': 'Use === for strict equality checks',
            })

        metrics['issues'] = issues
        return metrics

    def _check_general_quality(self, content: str, filename: str) -> List[Dict[str, Any]]:
        """General code quality checks applicable to all languages."""
        issues = []
        lines = content.split('\n')

        # Check line length
        for line_num, line in enumerate(lines, 1):
            if len(line) > 120:
                issues.append({
                    'type': 'quality',
                    'severity': 'low',
                    'issue': 'long_line',
                    'description': f'Line {line_num} exceeds 120 characters ({len(line)})',
                    'line': line_num,
                    'recommendation': 'Break long lines for better readability',
                })

        # Check for TODO/FIXME comments
        for line_num, line in enumerate(lines, 1):
            if re.search(r'(TODO|FIXME|HACK|XXX):', line, re.IGNORECASE):
                issues.append({
                    'type': 'quality',
                    'severity': 'info',
                    'issue': 'todo_comment',
                    'description': 'TODO/FIXME comment found',
                    'line': line_num,
                    'code': line.strip(),
                    'recommendation': 'Consider creating a ticket for this work',
                })

        # Check for excessive comments (might indicate complex code)
        comment_ratio = self._calculate_comment_ratio(content, filename)
        if comment_ratio > 0.3:
            issues.append({
                'type': 'quality',
                'severity': 'info',
                'issue': 'high_comment_ratio',
                'description': f'High comment ratio ({comment_ratio:.1%})',
                'recommendation': 'Excessive comments might indicate complex code that needs refactoring',
            })

        # Check for magic numbers
        for line_num, line in enumerate(lines, 1):
            # Look for numeric literals (excluding 0, 1, -1, 100)
            matches = re.finditer(r'\b(\d+\.?\d*)\b', line)
            for match in matches:
                num = match.group(1)
                if num not in ['0', '1', '100', '0.0', '1.0'] and not line.strip().startswith('#'):
                    issues.append({
                        'type': 'quality',
                        'severity': 'low',
                        'issue': 'magic_number',
                        'description': f'Magic number {num} found',
                        'line': line_num,
                        'recommendation': 'Consider using named constants',
                    })
                    break  # Only report once per line

        # Check for very long files
        if len(lines) > 500:
            issues.append({
                'type': 'quality',
                'severity': 'medium',
                'issue': 'long_file',
                'description': f'File is very long ({len(lines)} lines)',
                'recommendation': 'Consider splitting into multiple modules',
            })

        return issues

    def _calculate_comment_ratio(self, content: str, filename: str) -> float:
        """Calculate ratio of comment lines to total lines."""
        lines = content.split('\n')
        file_ext = Path(filename).suffix.lower()

        comment_lines = 0
        code_lines = 0

        # Define comment patterns by language
        single_line_comment = '#' if file_ext in ['.py', '.sh'] else '//'

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            elif stripped.startswith(single_line_comment):
                comment_lines += 1
            else:
                code_lines += 1

        total = comment_lines + code_lines
        return comment_lines / total if total > 0 else 0

    def get_summary(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of code quality metrics."""
        issues = metrics.get('issues', [])

        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for issue in issues:
            severity = issue.get('severity', 'info')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            'total_issues': len(issues),
            'lines_of_code': metrics.get('lines_of_code', 0),
            'functions': metrics.get('functions', 0),
            'classes': metrics.get('classes', 0),
            'severity_breakdown': severity_counts,
        }
