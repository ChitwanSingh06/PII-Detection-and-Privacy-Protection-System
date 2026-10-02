import os
import logging
import json
import sqlite3
import sys
from pathlib import Path
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import (  # noqa: E402
    SQLITE_PATH,
    STORAGE_ROOT,
    PII_SCORE_THRESHOLD,
    SPACY_MODEL,
)

load_dotenv()
logging.basicConfig(level=logging.INFO)


class LocalStorageHandler:
    def __init__(self):
        self.root = Path(os.getenv("STORAGE_ROOT", STORAGE_ROOT))

    def get_object_text(self, bucket_name, object_key):
        try:
            path = (self.root / bucket_name / object_key).resolve()
            if not str(path).startswith(str(self.root.resolve())):
                logging.error("Rejected path outside storage root")
                return None
            logging.info(f"Reading object {object_key} from bucket {bucket_name}")
            return path.read_text(encoding="utf-8")
        except Exception as e:
            logging.error(f"Error reading local object {object_key} from bucket {bucket_name}: {e}")
            return None


class PIIAnalyzer:
    _engine = None

    def __init__(self):
        if PIIAnalyzer._engine is None:
            logging.info("Initializing AnalyzerEngine")
            configuration = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": os.getenv("SPACY_MODEL", SPACY_MODEL)}],
            }
            provider = NlpEngineProvider(nlp_configuration=configuration)
            nlp_engine = provider.create_engine()
            PIIAnalyzer._engine = AnalyzerEngine(nlp_engine=nlp_engine)
        self.engine = PIIAnalyzer._engine

    def analyze(self, text):
        try:
            logging.info("Running PII analysis")
            score_threshold = float(os.getenv("PII_SCORE_THRESHOLD", str(PII_SCORE_THRESHOLD)))
            results = self.engine.analyze(text=text, entities=[], language="en")
            filtered = [
                {
                    "type": r.entity_type,
                    "start": r.start,
                    "end": r.end,
                    "score": r.score,
                }
                for r in results
                if r.score >= score_threshold
            ]
            logging.info(f"Filtered PII entities (score >= {score_threshold})")
            return filtered
        except Exception as e:
            logging.error(f"Error during PII analysis: {e}")
            return []


class SqlitePiiDB:
    def __init__(self):
        self.db_path = os.getenv("SQLITE_PATH", SQLITE_PATH)

    def store_pii_results(self, bucket_name, object_key, pii_entities):
        try:
            logging.info(f"Storing PII results for {object_key} in bucket {bucket_name}")
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO pii_objects (bucket_name, object_key, pii_entities)
                VALUES (?, ?, ?)
                ON CONFLICT(bucket_name, object_key)
                DO UPDATE SET pii_entities=excluded.pii_entities
                """,
                (bucket_name, object_key, json.dumps(pii_entities)),
            )
            conn.commit()
            cur.close()
            conn.close()
        except Exception as e:
            logging.error(f"SQLite error: {e}")


class PIIProcessor:
    def __init__(self):
        self.storage = LocalStorageHandler()
        self.analyzer = PIIAnalyzer()
        self.db = SqlitePiiDB()

    def process(self, bucket_name, object_key):
        text = self.storage.get_object_text(bucket_name, object_key)
        if text is None:
            logging.error(f"Skipping analysis; object not found: {bucket_name}/{object_key}")
            return
        pii_entities = self.analyzer.analyze(text)
        self.db.store_pii_results(bucket_name, object_key, pii_entities)
        logging.info(f"PII entities stored: {pii_entities}")


if __name__ == "__main__":
    load_dotenv()
    print("PII analyser is invoked automatically after local uploads.")
    print("To analyze an existing object: PIIProcessor().process(bucket, key)")
