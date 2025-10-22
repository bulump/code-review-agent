# Code Review Agent - Quick Start

## Installation

```bash
cd ~/git/code-review-agent
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Basic Usage

### 1. Review Local Files (No API Key Required)

```bash
python code_review_agent.py review-files myfile.py
```

**What it checks:**
- Security vulnerabilities (SQL injection, XSS, hardcoded secrets)
- Code quality issues (complexity, long functions, missing docstrings)
- Best practices violations

### 2. Review Local Git Changes

```bash
python code_review_agent.py review-local /path/to/repo
```

Reviews all uncommitted changes in a local repository.

### 3. Review GitHub Pull Request

```bash
# Setup
cp .env.example .env
# Add your GITHUB_TOKEN and ANTHROPIC_API_KEY to .env

# Review PR
python code_review_agent.py review owner/repo 123
```

**Output:**
- Security analysis with severity levels
- Code quality metrics
- AI-powered review with specific recommendations
- Approval recommendation

## Configuration

### Environment Variables

```bash
# Required for PR reviews
GITHUB_TOKEN=ghp_your_github_token

# Required for AI-powered reviews
ANTHROPIC_API_KEY=sk-ant-your_key
```

### GitHub Token Permissions

Your GitHub token needs:
- `repo` (full control of private repositories)
- `read:org` (read org and team membership)

## What It Detects

### Security Issues (Critical/High/Medium/Low)

**Critical:**
- Hardcoded API keys/tokens
- SQL injection vulnerabilities
- Command injection vulnerabilities

**High:**
- Hardcoded passwords
- Path traversal vulnerabilities
- Unsafe deserialization
- Missing CSRF protection

**Medium:**
- Insecure random for security contexts
- Debug mode enabled
- Weak cryptographic algorithms
- innerHTML usage (XSS risk)

**Low:**
- SELECT * in SQL queries
- Other minor security concerns

### Code Quality Issues

**High:**
- Syntax errors
- Very long files (500+ lines)

**Medium:**
- High cyclomatic complexity (>10)
- Functions without proper error handling

**Low:**
- Long functions (50+ lines)
- Missing docstrings
- Long lines (>120 characters)
- Magic numbers
- console.log statements (JS/TS)
- Using `var` instead of `let`/`const` (JS/TS)
- Loose equality (==) instead of strict (===)

**Info:**
- TODO/FIXME comments
- High comment ratio

## Example Output

```
Security Analysis
╭─────────────── Security Issues (3 total) ───────────────╮
│ Critical: 1                                             │
│ High: 1                                                 │
│ Medium: 1                                               │
│ Low: 0                                                  │
╰─────────────────────────────────────────────────────────╯

Critical & High Severity Issues:

● hardcoded_api_key
  File: config.py
  Line: 12
  Hardcoded API key or token detected
  → Store secrets in environment variables or secret manager

● sql_injection
  File: database.py
  Line: 45
  Potential SQL injection vulnerability (string concatenation)
  → Use parameterized queries or prepared statements
```

## GitHub Action Integration

Add to `.github/workflows/code-review.yml`:

```yaml
name: AI Code Review
on: [pull_request]

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - run: pip install -r requirements.txt

      - name: Run Code Review
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          python code_review_agent.py review ${{ github.repository }} ${{ github.event.pull_request.number }}
```

## Common Use Cases

### Pre-commit Hook

```bash
# .git/hooks/pre-commit
#!/bin/bash
python code_review_agent.py review-local . --no-ai
if [ $? -ne 0 ]; then
    echo "Code review found issues. Fix them before committing."
    exit 1
fi
```

### CI/CD Pipeline

Integrate into your CI/CD to automatically review all PRs:

1. Add secrets to GitHub repository settings
2. Add workflow file (see above)
3. Reviews run automatically on every PR

### Local Development

Run before creating a PR:

```bash
# Review your changes
python code_review_agent.py review-local .

# Review specific files you changed
python code_review_agent.py review-files src/auth.py src/database.py
```

## Tips

1. **Start without AI**: Use `--no-ai` flag for faster feedback during development
2. **Save reviews**: Use `-o review.md` to save detailed reviews to a file
3. **Focus on critical**: Address critical and high severity issues first
4. **Iterative improvement**: Run after each fix to verify resolution

## Performance

- **Local file review**: < 1 second per file
- **PR review (10 files)**: 2-5 seconds (without AI)
- **AI-powered review**: +5-10 seconds (depends on file count and API)

## Troubleshooting

**Error: GITHUB_TOKEN must be set**
- For PR reviews, you need a GitHub token
- For local file reviews, no token is needed

**Error: ANTHROPIC_API_KEY must be set**
- Only needed when using `--ai` flag
- Can skip AI review with `--no-ai`

**Warning: urllib3 v2 only supports OpenSSL 1.1.1+**
- This is a warning, not an error
- Tool still works correctly
- Can be ignored safely

## Architecture

```
code_review_agent.py    # Main CLI
├── pr_analyzer.py      # GitHub PR fetcher
├── security_scanner.py # Security vulnerability detection
├── quality_analyzer.py # Code quality metrics
├── ai_reviewer.py      # Claude AI integration
└── report_generator.py # Output formatting
```

## Next Steps

1. Review the test_example.py file to see what gets detected
2. Try reviewing your own code
3. Set up GitHub Action for automated PR reviews
4. Customize security patterns for your needs
