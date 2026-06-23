FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libmagic1 \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create uploads directory
RUN mkdir -p /app/uploads

# Expose port 5000 for Flask
EXPOSE 5000

# Default command runs the production server
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "run:app"]
