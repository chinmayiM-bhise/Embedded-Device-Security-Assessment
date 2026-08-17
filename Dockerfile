FROM python:3.11-slim

# Install system dependencies for firmware extraction and analysis
RUN apt-get update && apt-get install -y --no-install-recommends \
    binwalk \
    yara \
    libmagic1 \
    squashfs-tools \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Create workspace directories
RUN mkdir -p uploads results cli_results

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/ || exit 1

# Launch FastAPI web application
CMD ["uvicorn", "iot_scanner.web.api:app", "--host", "0.0.0.0", "--port", "8000"]
