"""
Tool-based Security Scanner
Integrates semgrep and bandit for comprehensive security scanning.
"""
import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional
import os
import sys


class ToolScanner:
    """Runs external security tools (semgrep, bandit) on code."""

    def __init__(self):
        """Initialize tool scanner."""
        # Get the directory where Python executables are located
        self.bin_dir = Path(sys.executable).parent

        self.semgrep_path = self._find_tool('semgrep')
        self.bandit_path = self._find_tool('bandit')

        self.semgrep_available = self.semgrep_path is not None
        self.bandit_available = self.bandit_path is not None

    def _find_tool(self, tool_name: str) -> Optional[str]:
        """Find a security tool in the current Python environment or system PATH."""
        # First, try to find in the same directory as the Python executable (venv)
        tool_path = self.bin_dir / tool_name
        if tool_path.exists() and os.access(tool_path, os.X_OK):
            return str(tool_path)

        # Try with .exe extension (Windows)
        tool_path_exe = self.bin_dir / f"{tool_name}.exe"
        if tool_path_exe.exists() and os.access(tool_path_exe, os.X_OK):
            return str(tool_path_exe)

        # Fall back to system PATH
        try:
            result = subprocess.run(
                ['which', tool_name],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return None

    def scan_file(self, filename: str, content: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Scan a file using available security tools.

        Args:
            filename: Name of the file
            content: File content

        Returns:
            Dictionary with 'bandit' and 'semgrep' keys containing issues
        """
        results = {
            'bandit': [],
            'semgrep': []
        }

        file_ext = Path(filename).suffix.lower()

        # Create temporary file for scanning
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix=file_ext,
            delete=False
        ) as tmp_file:
            tmp_file.write(content)
            tmp_path = tmp_file.name

        try:
            # Run bandit for Python files
            if file_ext == '.py' and self.bandit_available:
                results['bandit'] = self._run_bandit(tmp_path, filename)

            # Run semgrep for all supported files
            if self.semgrep_available:
                results['semgrep'] = self._run_semgrep(tmp_path, filename)

        finally:
            # Clean up temporary file
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

        return results

    def _run_bandit(self, filepath: str, original_filename: str) -> List[Dict[str, Any]]:
        """
        Run bandit security scanner.

        Args:
            filepath: Path to file to scan
            original_filename: Original filename for reporting

        Returns:
            List of security issues found by bandit
        """
        issues = []

        try:
            # Run bandit with JSON output
            result = subprocess.run(
                [self.bandit_path, '-f', 'json', filepath],
                capture_output=True,
                text=True,
                timeout=30
            )

            # Bandit returns non-zero exit code when issues are found
            if result.stdout:
                data = json.loads(result.stdout)

                for item in data.get('results', []):
                    issues.append({
                        'tool': 'bandit',
                        'type': 'security',
                        'severity': self._map_bandit_severity(item.get('issue_severity', 'LOW')),
                        'issue': item.get('test_id', 'Unknown'),
                        'description': item.get('issue_text', 'Security issue detected'),
                        'filename': original_filename,
                        'line': item.get('line_number'),
                        'code': item.get('code', '').strip(),
                        'confidence': item.get('issue_confidence', 'MEDIUM'),
                        'recommendation': self._get_bandit_recommendation(item),
                    })

        except subprocess.TimeoutExpired:
            pass
        except json.JSONDecodeError:
            pass
        except Exception as e:
            # Log error but don't fail the scan
            pass

        return issues

    def _run_semgrep(self, filepath: str, original_filename: str) -> List[Dict[str, Any]]:
        """
        Run semgrep security scanner.

        Args:
            filepath: Path to file to scan
            original_filename: Original filename for reporting

        Returns:
            List of security issues found by semgrep
        """
        issues = []

        # Get the directory where this script is located
        script_dir = Path(__file__).parent
        custom_rules = script_dir / '.semgrep-rules.yaml'

        # Use custom rules if they exist, otherwise fall back to auto
        config = str(custom_rules) if custom_rules.exists() else 'auto'

        try:
            # Run semgrep with security rules
            result = subprocess.run(
                [
                    self.semgrep_path,
                    f'--config={config}',
                    '--json',
                    '--quiet',
                    filepath
                ],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.stdout:
                data = json.loads(result.stdout)

                for item in data.get('results', []):
                    # Get severity from semgrep metadata
                    extra = item.get('extra', {})
                    severity = extra.get('severity', 'INFO').lower()

                    # Map semgrep severity to our standard
                    if severity == 'error':
                        severity = 'high'
                    elif severity == 'warning':
                        severity = 'medium'
                    elif severity == 'info':
                        severity = 'low'

                    issues.append({
                        'tool': 'semgrep',
                        'type': 'security',
                        'severity': severity,
                        'issue': item.get('check_id', 'Unknown'),
                        'description': extra.get('message', 'Security pattern detected'),
                        'filename': original_filename,
                        'line': item.get('start', {}).get('line'),
                        'code': extra.get('lines', '').strip(),
                        'recommendation': self._get_semgrep_recommendation(extra),
                    })

        except subprocess.TimeoutExpired:
            pass
        except json.JSONDecodeError:
            pass
        except Exception as e:
            # Log error but don't fail the scan
            pass

        return issues

    def _map_bandit_severity(self, severity: str) -> str:
        """Map bandit severity to standard severity levels."""
        severity = severity.upper()
        if severity == 'HIGH':
            return 'high'
        elif severity == 'MEDIUM':
            return 'medium'
        elif severity == 'LOW':
            return 'low'
        return 'medium'

    def _get_bandit_recommendation(self, item: Dict[str, Any]) -> str:
        """Extract or generate recommendation from bandit result."""
        # Try to get more info link
        more_info = item.get('more_info', '')
        if more_info:
            return f"See: {more_info}"

        # Generic recommendation based on test_id
        test_id = item.get('test_id', '')
        recommendations = {
            'B201': 'Avoid using flask app with debug=True in production',
            'B301': 'Avoid using pickle; use safer serialization like JSON',
            'B303': 'Use hashlib.sha256() instead of MD5 or SHA1',
            'B304': 'Use secrets module instead of insecure ciphers',
            'B308': 'Use safe_load() instead of load() when parsing YAML',
            'B311': 'Use secrets module for cryptographic randomness',
            'B501': 'Request with verify=False disables SSL verification',
            'B506': 'Use safe YAML loading methods',
            'B601': 'Potential shell injection; use subprocess with list args',
            'B602': 'Avoid shell=True in subprocess calls',
            'B608': 'Potential SQL injection; use parameterized queries',
        }

        return recommendations.get(test_id, 'Review security best practices for this pattern')

    def _get_semgrep_recommendation(self, extra: Dict[str, Any]) -> str:
        """Extract recommendation from semgrep metadata."""
        # Semgrep often includes references in metadata
        metadata = extra.get('metadata', {})

        # Try to get references
        references = metadata.get('references', [])
        if references:
            return f"See: {references[0]}"

        # Try to get CWE or OWASP info
        cwe = metadata.get('cwe', [])
        owasp = metadata.get('owasp', [])

        recommendations = []
        if cwe:
            recommendations.append(f"Related to CWE-{cwe[0]}")
        if owasp:
            recommendations.append(f"OWASP: {owasp[0]}")

        if recommendations:
            return '; '.join(recommendations)

        return 'Follow security best practices to address this finding'

    def get_summary(self, tool_results: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """
        Generate summary of tool scan results.

        Args:
            tool_results: Dictionary with tool names as keys

        Returns:
            Summary statistics
        """
        all_issues = []
        for tool_name, issues in tool_results.items():
            all_issues.extend(issues)

        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        for issue in all_issues:
            severity = issue.get('severity', 'low')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            'total_issues': len(all_issues),
            'by_tool': {
                tool: len(issues)
                for tool, issues in tool_results.items()
            },
            'critical': severity_counts['critical'],
            'high': severity_counts['high'],
            'medium': severity_counts['medium'],
            'low': severity_counts['low'],
            'has_critical': severity_counts['critical'] > 0,
            'has_high': severity_counts['high'] > 0,
        }

    def is_available(self) -> bool:
        """Check if any security tool is available."""
        return self.semgrep_available or self.bandit_available

    def get_available_tools(self) -> List[str]:
        """Get list of available tools."""
        tools = []
        if self.bandit_available:
            tools.append('bandit')
        if self.semgrep_available:
            tools.append('semgrep')
        return tools
