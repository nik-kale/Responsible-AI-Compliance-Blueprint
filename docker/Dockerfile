FROM python:3.11-slim

LABEL maintainer="Responsible AI Toolkit Team"
LABEL description="Responsible AI Compliance Blueprint - Self-audit toolkit for AI systems"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml /app/
COPY src/ /app/src/
COPY app/ /app/app/
COPY templates/ /app/templates/
COPY examples/ /app/examples/
COPY README.md /app/
COPY LICENSE /app/

# Install Python dependencies
RUN pip install --no-cache-dir -e . && \
    pip install --no-cache-dir streamlit

# Create workspace directory
RUN mkdir -p /workspace

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV MODE=cli

# Expose Streamlit port
EXPOSE 8501

# Copy entrypoint script
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/entrypoint.sh"]

# Default command
CMD ["--help"]
