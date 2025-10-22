"""
Example file with intentional security and quality issues for testing.
"""
import os
import random

# Security Issue: Hardcoded password
password = "secretpassword123"
API_KEY = "sk_test_abc123def456ghi789"

def execute_query(user_input):
    """Execute SQL query - has SQL injection vulnerability."""
    # Security Issue: SQL injection
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    return query

def run_command(cmd):
    """Run system command - has command injection vulnerability."""
    # Security Issue: Command injection
    os.system("ls " + cmd)

def get_random_token():
    """Generate random token - uses insecure random."""
    # Security Issue: Insecure random for security
    return random.randint(1000, 9999)

# Quality Issue: Very long function
def process_data_with_many_branches(data, option1, option2, option3, option4):
    """Process data with complex logic."""
    # Quality Issue: High cyclomatic complexity
    if option1:
        if option2:
            if option3:
                if option4:
                    result = data * 4
                else:
                    result = data * 3
            else:
                if option4:
                    result = data * 2
                else:
                    result = data * 1
        else:
            if option3:
                if option4:
                    result = data + 4
                else:
                    result = data + 3
            else:
                if option4:
                    result = data + 2
                else:
                    result = data + 1
    else:
        result = data

    # Quality Issue: Magic numbers
    return result * 42

# Quality Issue: Missing docstring
def helper_function(x, y, z):
    return x + y + z

# Quality Issue: Long line
very_long_variable_name_that_makes_this_line_extremely_long = "This is a very long string that exceeds 120 characters and should be flagged"

# Quality Issue: Console log
print("Debug: This should be removed in production")

# TODO: Refactor this entire module
