#!/bin/bash
# Demo script to test the Code Review Agent

echo "=================================================="
echo "Code Review Agent Demo"
echo "=================================================="
echo ""
echo "Running security and quality analysis on test_example.py..."
echo ""

source venv/bin/activate
python code_review_agent.py review-files test_example.py

echo ""
echo "=================================================="
echo "Demo Complete!"
echo "=================================================="
echo ""
echo "The test file contains intentional security issues:"
echo "  - Hardcoded passwords and API keys"
echo "  - SQL injection vulnerability"
echo "  - Command injection vulnerability"
echo "  - Insecure random usage"
echo "  - High complexity functions"
echo "  - Missing docstrings"
echo "  - Magic numbers"
echo ""
