FROM python:3.11-slim

# Build from the PROJECT ROOT so ui/ and the shared modules app.py imports
# are inside the build context:
#   docker build -f proxy-server/Dockerfile -t pii-proxy .
#
# The layout under /app mirrors the repo, because app.py resolves
# ROOT = parents[1] to find config.py, ui/, consumer_analyzer/ and common/.
WORKDIR /app

COPY requirements.txt /app/requirements.txt
COPY proxy-server/requirements.txt /app/proxy-server/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt \
 && python -m spacy download en_core_web_sm

COPY config.py /app/config.py
COPY common/ /app/common/
COPY anonymizer/pb/ /app/anonymizer/pb/
COPY consumer_analyzer/ /app/consumer_analyzer/
COPY proxy-server/ /app/proxy-server/
COPY ui/ /app/ui/

# Same PYTHONPATH the README uses for local runs (needed for `common.*` and `pb.*`)
ENV PYTHONPATH=/app/anonymizer:/app/common:/app/consumer_analyzer/pii_analyser:/app/consumer_analyzer/consumer:/app/proxy-server

WORKDIR /app/proxy-server
EXPOSE 8080

CMD ["python", "app.py"]
