FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY core/       ./core/
COPY collectors/ ./collectors/
COPY pipeline/   ./pipeline/
COPY analyst/    ./analyst/
COPY api/        ./api/
COPY frontend/   ./frontend/
COPY main.py     .

# Create data directory for SQLite
RUN mkdir -p /data

EXPOSE 8000

CMD ["python", "main.py"]
