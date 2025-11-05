# Use Python 3.11 slim image for smaller size
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies needed for security tools
# git: Required for GitPython
# gcc: Required for some Python packages compilation
RUN apt-get update && apt-get install -y \
    git \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (better layer caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY *.py .
COPY .semgrep-rules.yaml .
COPY .env.example .env.example

# Create a non-root user for security
RUN useradd -m -u 1000 reviewer && \
    chown -R reviewer:reviewer /app
USER reviewer

# Set Python to run in unbuffered mode (better for containers)
ENV PYTHONUNBUFFERED=1

# Default command - shows help
ENTRYPOINT ["python", "code_review_agent.py"]
CMD ["--help"]
