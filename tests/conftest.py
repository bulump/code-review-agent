"""
Pytest configuration for code-review-agent tests.
Adds parent directory to Python path so tests can import project modules.
"""
import sys
from pathlib import Path

# Add parent directory to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
