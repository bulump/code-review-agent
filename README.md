# Code Review Agent

AI-powered automated code review tool that analyzes pull requests for security vulnerabilities, code quality issues, and best practices violations.

## Features

- **Multi-Tool Security Analysis**: Integrates industry-standard tools (Semgrep, Bandit) plus custom pattern matching
- **Comprehensive Coverage**: Detects SQL injection, XSS, hardcoded secrets, command injection, and more
- **Code Quality**: Analyzes complexity, maintainability, and code smells
- **AI-Powered Reviews**: Uses Claude to provide intelligent, context-aware feedback
- **Custom Security Rules**: Includes tailored Semgrep rules for Python and JavaScript/TypeScript
- **Best Practices**: Checks for language-specific patterns and conventions
- **Actionable Feedback**: Provides specific suggestions with code examples
- **GitHub Integration**: Can be run as CLI or GitHub Action

## Installation

### Option 1: Local Installation

```bash
pip install -r requirements.txt
```

### Option 2: Docker (Recommended)

No installation required! Just use Docker:

```bash
# Pull from Docker Hub (coming soon)
docker pull code-review-agent:latest

# Or build locally
docker build -t code-review-agent:latest .
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

### Docker Mode

```bash
# Review specific files (mount current directory)
docker run --rm \
  -v $(pwd):/workspace \
  -w /workspace \
  -e ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY}" \
  -e GITHUB_TOKEN="${GITHUB_TOKEN}" \
  code-review-agent:latest review-files file1.py file2.py

# Review a GitHub pull request
docker run --rm \
  -e ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY}" \
  -e GITHUB_TOKEN="${GITHUB_TOKEN}" \
  code-review-agent:latest review owner/repo 123

# Review local repository
docker run --rm \
  -v /path/to/your/repo:/workspace \
  -w /workspace \
  -e ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY}" \
  -e GITHUB_TOKEN="${GITHUB_TOKEN}" \
  code-review-agent:latest review-local .
```

**Docker Benefits:**
- ✅ No dependency installation required
- ✅ Consistent environment across all machines
- ✅ Isolated from your local system
- ✅ Easy CI/CD integration
- ✅ Works on any OS with Docker

### GitHub Action

#### Option 1: Using Docker (Faster, Cached)

Add to `.github/workflows/code-review.yml`:

```yaml
name: AI Code Review
on: [pull_request]

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Code Review Agent (Docker)
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/workspace \
            -w /workspace \
            -e ANTHROPIC_API_KEY \
            -e GITHUB_TOKEN \
            code-review-agent:latest review ${{ github.repository }} ${{ github.event.pull_request.number }}
```

#### Option 2: Traditional Installation

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

### Security Issues (via Semgrep, Bandit, and Custom Patterns)
- SQL injection vulnerabilities
- Cross-site scripting (XSS)
- Command injection and shell injection
- Hardcoded secrets/passwords/API keys
- Insecure randomness (use of `random` instead of `secrets`)
- Path traversal vulnerabilities
- Unsafe deserialization (pickle, YAML)
- Use of `eval()` and `exec()`
- Debug mode enabled in production
- Weak cryptographic algorithms

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

- `code_review_agent.py`: Main CLI interface with rich terminal output
- `pr_analyzer.py`: GitHub PR fetcher and diff parser
- `security_scanner.py`: Orchestrates security vulnerability detection
- `tool_scanner.py`: Integrates external security tools (Semgrep, Bandit)
- `quality_analyzer.py`: Code quality metrics and complexity analysis
- `ai_reviewer.py`: Claude AI integration for intelligent reviews
- `.semgrep-rules.yaml`: Custom Semgrep security rules for Python and JavaScript/TypeScript

## Security Tools Integration

### Semgrep
Custom rules detect:
- SQL injection patterns
- Command injection
- Hardcoded credentials
- Unsafe deserialization
- XSS vulnerabilities (JavaScript/TypeScript)

### Bandit
Python-specific security scanner detecting:
- CWE-categorized vulnerabilities
- Security best practice violations
- Confidence levels for each finding

### Pattern Matcher
Regex-based detection for:
- Quick pattern-based scanning
- Language-agnostic checks
- Custom vulnerability patterns
