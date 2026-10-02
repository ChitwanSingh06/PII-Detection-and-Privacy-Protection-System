import os
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env")

SQLITE_PATH = os.environ.get("SQLITE_PATH", str(PROJECT_ROOT / "data" / "pii.db"))
STORAGE_ROOT = os.environ.get("STORAGE_ROOT", str(PROJECT_ROOT / "data" / "storage"))
AN_SVC_URL = os.environ.get("AN_SVC_URL", "localhost:10666")
PII_SCORE_THRESHOLD = float(os.environ.get("PII_SCORE_THRESHOLD", "0.6"))
SPACY_MODEL = os.environ.get("SPACY_MODEL", "en_core_web_sm")
DEFAULT_USER = os.environ.get("DEFAULT_USER", "admin")
