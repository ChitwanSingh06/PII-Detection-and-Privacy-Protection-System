import logging
import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env")

SQLITE_PATH = os.environ.get("SQLITE_PATH", str(PROJECT_ROOT / "data" / "pii.db"))
STORAGE_ROOT = os.environ.get("STORAGE_ROOT", str(PROJECT_ROOT / "data" / "storage"))
AN_SVC_URL = os.environ.get("AN_SVC_URL", "localhost:10666")
PII_SCORE_THRESHOLD = float(os.environ.get("PII_SCORE_THRESHOLD", "0.6"))
SPACY_MODEL = os.environ.get("SPACY_MODEL", "en_core_web_sm")

# --- Authentication (JWT) ---
# Set JWT_SECRET to a long random value, e.g.:
#   python -c "import secrets; print(secrets.token_urlsafe(48))"
# If it is missing, a random per-process secret is generated so the server still starts;
# tokens then stop working whenever the server restarts.
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM") or "HS256"
if JWT_ALGORITHM not in ("HS256", "HS384", "HS512"):
    raise ValueError("JWT_ALGORITHM must be one of HS256, HS384, HS512")
JWT_EXPIRE_MINUTES = int(os.environ.get("JWT_EXPIRE_MINUTES") or "60")
JWT_SECRET = os.environ.get("JWT_SECRET", "")
if not JWT_SECRET:
    JWT_SECRET = secrets.token_urlsafe(48)
    logging.getLogger(__name__).warning(
        "JWT_SECRET is not set; using a random temporary secret. "
        "Tokens will be invalid after a restart. Set JWT_SECRET in .env."
    )
elif len(JWT_SECRET) < 32:
    logging.getLogger(__name__).warning("JWT_SECRET is shorter than 32 characters; use a longer secret.")

# --- Kafka (queue of PII scan jobs: the proxy produces, consumer_analyzer/consumer/kafka_consumer.py consumes) ---
# KAFKA_ENABLED=0 keeps the original behaviour (the upload request scans the file itself, no broker needed).
KAFKA_ENABLED = (os.environ.get("KAFKA_ENABLED") or "1") == "1"
KAFKA_BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS") or "localhost:9092"
KAFKA_SCAN_TOPIC = os.environ.get("KAFKA_SCAN_TOPIC") or "pii-scan-jobs"
KAFKA_GROUP_ID = os.environ.get("KAFKA_GROUP_ID") or "pii-scan-workers"
