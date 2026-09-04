# Code Review Agent

AI-powered automated code review tool that analyzes pull requests for security vulnerabilities, code quality issues, and best practices violations.

## Features

- **Multi-Tool Security Analysis**: Integrates industry-standard tools (Semgrep, Bandit) plus custom pattern matching
- **Comprehensive Coverage**: Detects SQL injection, XSS, hardcoded secrets, command injection, and more
- **Code Quality**: Analyzes complexity, maintainability, and code smells
- **AI-Powered Reviews**: Uses Claude to provide intelligent, context-aware feedback
- **AI Verification Layer**: Automatically verifies AI findings to eliminate false positives (30-50% reduction)
- **Project-Aware Context**: Loads project conventions from CLAUDE.md and REVIEW.md for tailored reviews
- **Custom Security Rules**: Includes tailored Semgrep rules for Python and JavaScript/TypeScript
- **Best Practices**: Checks for language-specific patterns and conventions
- **Actionable Feedback**: Provides specific suggestions with code examples
- **GitHub Integration**: Can be run as CLI or GitHub Action
- **Docker Support**: Fully containerized for easy deployment and consistent environments

## Installation

### Option 1: Local Installation

```bash
pip install -r requirements.txt
```

### Option 2: Docker (Recommended)

No installation required! Just use Docker:

```bash
# Pull from Docker Hub
docker pull bulump/code-review-agent:latest

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
  bulump/code-review-agent:latest review-files file1.py file2.py

# Review a GitHub pull request
docker run --rm \
  -e ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY}" \
  -e GITHUB_TOKEN="${GITHUB_TOKEN}" \
  bulump/code-review-agent:latest review owner/repo 123

# Review local repository
docker run --rm \
  -v /path/to/your/repo:/workspace \
  -w /workspace \
  -e ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY}" \
  -e GITHUB_TOKEN="${GITHUB_TOKEN}" \
  bulump/code-review-agent:latest review-local .
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
            bulump/code-review-agent:latest review ${{ github.repository }} ${{ github.event.pull_request.number }}
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

## Enhanced AI Features

### AI Verification Layer

The code review agent includes an intelligent verification layer that validates AI-generated findings to eliminate false positives:

- **Location Verification**: Confirms that file paths and line numbers actually exist
- **Claim Validation**: Verifies specific claims (e.g., "missing import" when import exists)
- **Deduplication**: Merges duplicate findings from multiple analysis tools
- **Statistics Tracking**: Reports verification metrics and drop rates

**Results:** In testing, verification reduces false positives by 30-50%, ensuring only accurate findings reach developers.

```python
# Verification is enabled by default
reviewer = AIReviewer(enable_verification=True)

# Check verification statistics
stats = reviewer.verifier.get_verification_stats()
print(f"Verified {stats['verified']}/{stats['total']} findings")
print(f"Drop rate: {stats['drop_rate']:.1%}")
```

### Project-Aware Context Loading

Reviews are tailored to your project by automatically loading conventions and rules:

- **CLAUDE.md**: Project architecture, development practices, conventions
- **REVIEW.md**: Review-specific rules, accepted tradeoffs (optional)
- **Language Rules**: `.claude/rules/*.md` for language-specific patterns (optional)

**Benefits:**
- AI respects your team's coding standards
- Reduces repeat feedback on accepted patterns
- Context-aware recommendations

**Example CLAUDE.md:**
```markdown
# Project Conventions

## Architecture
- Use dependency injection for all services
- Follow repository pattern for data access

## Security
- All API endpoints must have authentication
- Use parameterized queries for database access

## Code Style
- Max line length: 120 characters
- Use async/await for I/O operations
```

The AI reviewer automatically includes this context when generating reviews, making feedback more relevant to your project.

## Architecture

### Core Components

- `code_review_agent.py`: Main CLI interface with rich terminal output
- `pr_analyzer.py`: GitHub PR fetcher and diff parser
- `security_scanner.py`: Orchestrates security vulnerability detection
- `tool_scanner.py`: Integrates external security tools (Semgrep, Bandit)
- `quality_analyzer.py`: Code quality metrics and complexity analysis
- `ai_reviewer.py`: Claude AI integration for intelligent reviews
- `.semgrep-rules.yaml`: Custom Semgrep security rules for Python and JavaScript/TypeScript

### Enhanced AI Components (Phase 1)

- `finding_verifier.py`: Verifies AI findings to eliminate false positives
- `context_loader.py`: Loads project conventions (CLAUDE.md, REVIEW.md, rules)

### Data Flow

```
PR/Files → Security Scanner → Quality Analyzer → AI Reviewer → Output
              ↓                    ↓                 ↓
           Semgrep            Complexity        Verification
           Bandit             Metrics           Context Loading
           Patterns
```

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
