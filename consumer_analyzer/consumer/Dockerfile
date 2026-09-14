FROM python:3.11-slim

# Set work directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --index-url https://artifactory.eng.nimblestorage.com/artifactory/api/pypi/pypi/simple --no-cache-dir -r requirements.txt

# Copy code
COPY . .

# Set environment variables
ENV http_proxy=http://hpeproxy.its.hpecorp.net:443
ENV https_proxy=http://hpeproxy.its.hpecorp.net:443

# Default command
CMD ["python", "kafka_consumer.py"]