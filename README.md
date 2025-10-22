# Code Review Agent

AI-powered automated code review tool that analyzes pull requests for security vulnerabilities, code quality issues, and best practices violations.

## Features

- **Security Analysis**: Detects common vulnerabilities (SQL injection, XSS, hardcoded secrets, etc.)
- **Code Quality**: Analyzes complexity, maintainability, and code smells
- **AI-Powered Reviews**: Uses Claude to provide intelligent, context-aware feedback
- **Best Practices**: Checks for language-specific patterns and conventions
- **Actionable Feedback**: Provides specific suggestions with code examples
- **GitHub Integration**: Can be run as CLI or GitHub Action

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

Create a `.env` file with your API keys:

```bash
ANTHROPIC_API_KEY=your_anthropic_key_here
GITHUB_TOKEN=your_github_token_here
```

## Usage

### CLI Mode

```bash
# Review a pull request
python code_review_agent.py review owner/repo 123

# Review local changes
python code_review_agent.py review-local /path/to/repo

# Review specific files
python code_review_agent.py review-files file1.py file2.py
```

### GitHub Action

Add to `.github/workflows/code-review.yml`:

```yaml
name: AI Code Review
on: [pull_request]

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Code Review Agent
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          pip install -r requirements.txt
          python code_review_agent.py review ${{ github.repository }} ${{ github.event.pull_request.number }}
```

## What It Checks

### Security Issues
- SQL injection vulnerabilities
- Cross-site scripting (XSS)
- Command injection
- Hardcoded secrets/passwords
- Insecure randomness
- Path traversal vulnerabilities
- Insecure deserialization

### Code Quality
- Cyclomatic complexity
- Maintainability index
- Code duplication
- Function/class length
- Nested complexity
- Dead code

### Best Practices
- Error handling patterns
- Logging practices
- Resource management
- Type hints (Python)
- Documentation completeness
- Test coverage indicators

## Architecture

- `code_review_agent.py`: Main CLI interface
- `pr_analyzer.py`: GitHub PR fetcher and diff parser
- `security_scanner.py`: Security vulnerability detection
- `quality_analyzer.py`: Code quality metrics
- `ai_reviewer.py`: Claude AI integration for intelligent reviews
- `report_generator.py`: Formats and outputs review results
