# Code Review Agent

AI-powered automated code review tool that analyzes pull requests for security vulnerabilities, code quality issues, and best practices violations.

## Recent Updates

### Phase 3: Pre-existing Detection (September 2026)
- ✅ **Intelligent Classification**: Distinguishes newly introduced issues from pre-existing technical debt
- ✅ **Diff Analysis**: Parses git diffs and GitHub PR API to identify changed lines
- ✅ **Smart Filtering**: Focus reviews on new issues, track debt separately
- ✅ **Comprehensive Testing**: 5 automated tests, all passing

### Phase 2: Multi-Reviewer Architecture (September 2026)
- ✅ **Parallel Execution**: 5 specialized reviewers run concurrently (3-5x faster)
- ✅ **Specialized Focus**: Security, Quality, Architecture, Testing, and Narrative reviewers
- ✅ **AI-Powered Reviews**: 3 AI reviewers for architecture, testing, and PR coherence
- ✅ **Enhanced Findings**: Reviewer attribution, confidence levels, origin tracking
- ✅ **Comprehensive Testing**: 6 automated tests, all passing

### AWS Secret Detection (September 2026)
- ✅ **Multi-Layered AWS Detection**: Pattern + context-aware + proximity-based detection
- ✅ **Intelligent Verification**: Entropy analysis, test file filtering, comment exclusion
- ✅ **Minimal False Positives**: SHA-1 hashes and test fixtures automatically filtered
- ✅ **Comprehensive Coverage**: 6 automated tests, all passing

### Phase 1: Core Infrastructure (September 2026)
- ✅ **AI Verification Layer**: Reduces false positives by 30-50% through intelligent validation
- ✅ **Project-Aware Context**: Automatically loads CLAUDE.md, REVIEW.md, and language rules
- ✅ **Security Hardening**: Path traversal prevention, sensitive file filtering, API key sanitization
- ✅ **Comprehensive Testing**: 22 automated tests covering features and security enhancements

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

### API Keys

Create a `.env` file with your API keys:

```bash
ANTHROPIC_API_KEY=your_anthropic_key_here
GITHUB_TOKEN=your_github_token_here
```

### Project Context (Optional)

To enable project-aware reviews, create these files in your repository:

**`.claude/CLAUDE.md`** - Project conventions and architecture:
```markdown
# Project Conventions

## Architecture
- Follow MVC pattern
- Use dependency injection

## Security
- All endpoints require authentication
- Use parameterized queries for SQL
```

**`REVIEW.md`** (optional) - Review-specific rules:
```markdown
# Review Rules

## Accepted Tradeoffs
- Console.log allowed in development utilities
- TODO comments acceptable with ticket references
```

**`.claude/rules/python.md`** (optional) - Language-specific rules:
```markdown
# Python Rules

- Use type hints for all public functions
- Prefer pathlib over os.path
- Use context managers for file operations
```

The AI reviewer will automatically load and use these conventions when generating reviews.

### AI Model Configuration

The tool uses Claude Sonnet 4.5 by default. Model configuration is centralized in `ai_reviewer.py`:

```python
DEFAULT_MODEL = "claude-sonnet-4-5-20250929"
MAX_TOKENS_FULL_REVIEW = 4000
MAX_TOKENS_FILE_REVIEW = 2000
MAX_TOKENS_SUGGESTION = 1000
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
- **AWS Credentials Detection** (multi-layered with verification)
  - AWS Access Key IDs (AKIA*, ASIA*, AIDA*, etc.)
  - AWS Secret Access Keys (context-aware + proximity-based)
  - Entropy-based filtering to reduce false positives
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

### Security Features

The context loader and verification system include multiple security layers:

- **Path Traversal Prevention**: Uses `Path.resolve()` and `relative_to()` checks to prevent directory traversal attacks
- **Sensitive File Filtering**: Blocks access to `.env`, private keys, credentials, SSH keys, and other sensitive files
- **File Size Limits**: Enforces limits (100KB for CLAUDE.md, 50KB for REVIEW.md, 20KB for rules) to prevent resource exhaustion
- **API Key Sanitization**: Automatically redacts API keys from error messages and logs using regex patterns
- **Input Validation**: Only allows alphanumeric file type identifiers to prevent path injection
- **Fail-Secure Design**: Rejects paths on any validation error or exception

**Example protected files:**
```
.env, .env.local, .key, .pem, credentials, id_rsa, .ssh, .aws, .boto, .s3cfg, password.txt, token
```

All file access goes through the `_is_safe_path()` validator in `context_loader.py`.

### AWS Secret Detection

Comprehensive multi-layered detection system for AWS credentials with intelligent false positive filtering:

**Detection Strategies:**

1. **Pattern Detection** - Direct pattern matching for AWS Access Key IDs:
   - `AKIA*` - Long-term credentials
   - `ASIA*` - Temporary credentials (STS)
   - `AIDA*`, `AROA*`, `AIPA*`, `ANPA*`, `ANVA*`, `APKA*` - Other AWS identifiers

2. **Context-Aware Detection** - 40-character base64 strings flagged only when:
   - Variable name contains AWS-related keywords (`aws_secret`, `secret_access_key`, etc.)
   - Example: `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY..."`

3. **Proximity Detection** - 40-character strings flagged when:
   - Found within 5 lines of an AWS Access Key ID
   - Not a hash function call (excludes `sha1`, `digest`, `checksum`)
   - Higher confidence due to spatial correlation

**Verification Layer** - Filters false positives by:
- ❌ Excluding test files (`test_`, `*_test.py`, `/tests/`, `example`, `sample`, `demo`)
- ❌ Excluding documentation (`.md`, `.txt`, `/docs/`)
- ❌ Excluding comments (lines starting with `#`, `//`, `/*`)
- ❌ Shannon entropy check (< 4.0 bits/char = low entropy = likely test data)

**Example:**
```python
# ❌ DETECTED - High confidence
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# ❌ DETECTED - Context-aware
config = {
    'aws_secret': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
}

# ✅ NOT DETECTED - No AWS context
commit_sha1 = "356a192b7913b04c54574d18c28d46e6395428ab"  # SHA-1 hash

# ✅ FILTERED - Test file
# File: test_credentials.py
TEST_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # Excluded by verification
```

**Results:**
- High precision through multi-layered verification
- Minimal false positives (SHA-1 hashes, test fixtures filtered)
- High recall across different credential formats

**Recommendation:** Use IAM roles, instance profiles, or AWS Secrets Manager instead of hardcoded credentials.

## Testing

Run the test suite to validate functionality and security:

```bash
# Test Phase 1 features
python test_phase1.py

# Test verification layer
python test_security_fixes.py

# Test AWS secret detection
python test_aws_detection.py

# Test on real PR (self-review)
python test_real_pr.py
```

**Test Coverage:**
- ✅ Path traversal prevention (3 tests)
- ✅ Sensitive file filtering (3 tests)
- ✅ File size limits (1 test)
- ✅ API key sanitization (2 tests)
- ✅ Verification logic (5 tests)
- ✅ Context loading (2 tests)
- ✅ AWS secret detection (6 tests)
  - AWS Access Key ID pattern detection
  - Context-aware AWS Secret Key detection
  - Proximity-based detection (5-line window)
  - Verification filters test/example files
  - Entropy-based filtering
  - False positive prevention

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

## Development

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/yourusername/code-review-agent.git
cd code-review-agent

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your API keys
```

### Running Tests

```bash
# Activate virtual environment
source venv/bin/activate

# Run all Phase 1 tests
python test_phase1.py           # Feature tests (5 tests)
python test_security_fixes.py   # Security tests (6 tests)
python test_real_pr.py           # Integration test (self-review)

# Test on sample code
python code_review_agent.py review-files test_example.py
```

### Code Structure

```
code-review-agent/
├── code_review_agent.py      # CLI entry point
├── pr_analyzer.py             # GitHub/Git integration
├── security_scanner.py        # Security orchestration
├── tool_scanner.py            # Semgrep/Bandit integration
├── quality_analyzer.py        # Code quality metrics
├── ai_reviewer.py             # Claude AI integration
├── finding_verifier.py        # AI verification layer (Phase 1)
├── context_loader.py          # Project context loading (Phase 1)
├── .semgrep-rules.yaml        # Custom security rules
└── .claude/
    ├── CLAUDE.md              # Project documentation
    └── rules/                 # Language-specific rules
```

### Adding Custom Security Rules

Edit `.semgrep-rules.yaml` to add new Semgrep patterns:

```yaml
rules:
  - id: custom-vulnerability
    pattern: dangerous_function($ARG)
    message: Avoid using dangerous_function
    severity: ERROR
    languages: [python]
    metadata:
      cwe: "CWE-XXX"
      category: security
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests to ensure everything works
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Phase 1 Implementation Details

The Phase 1 enhancements added 1,603 lines of code across 7 files:

**New Modules:**
- `finding_verifier.py` (271 lines): Validates AI findings with location and claim verification
- `context_loader.py` (304 lines): Secure context loading with multi-layer security

**Enhanced Modules:**
- `ai_reviewer.py`: Added verification integration, context loading, API key sanitization

**Test Suite:**
- `test_phase1.py`: 5 feature tests
- `test_security_fixes.py`: 6 security tests
- `test_real_pr.py`: Real-world integration test

**Security Enhancements:**
- Path traversal prevention using `Path.relative_to()`
- Sensitive file filtering (`.env`, `.key`, credentials)
- File size limits (100KB/50KB/20KB)
- API key sanitization with regex redaction
- Input validation (alphanumeric-only file types)
- Complexity reduction (refactored high-complexity functions)

## License

MIT License - see LICENSE file for details

## Acknowledgments

- Built with [Anthropic Claude](https://www.anthropic.com/claude) for AI-powered reviews
- Security scanning powered by [Semgrep](https://semgrep.dev/) and [Bandit](https://github.com/PyCQA/bandit)
- Terminal UI using [Rich](https://github.com/Textualize/rich)
