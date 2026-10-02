import os
import logging
<<<<<<< HEAD
import boto3
import psycopg2
import json
import redis
import botocore
import time
from presidio_analyzer import AnalyzerEngine
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO)

class RedisHandler:
    def fetch_bucket_object_sorted(self):
        try:
            result = self.client.zpopmin(self.queue)
            logging.info(f"Fetched from Redis sorted set: {result}")
            if result:
                member, score = result[0]
            # Assuming member is in the format "object_key:bucket_name"
                obj, bucket = member.split(":", 1)
                logging.info(f"Popped: Bucket={bucket}, Object={obj}, Score={score}")
                return bucket, obj
            else:
                return None, None
        except Exception as e:
            logging.error(f"Error fetching from Redis: {e}")
    def __init__(self):
        try:
            self.host = os.getenv('REDIS_HOST')
            self.port = int(os.getenv('REDIS_PORT'))
            self.queue = os.getenv('REDIS_QUEUE')
            self.client = redis.Redis(host=self.host, port=self.port, decode_responses=True)
        except Exception as e:
            logging.error(f"Error initializing Redis client: {e}")
            


class S3Handler:
    def __init__(self):
        aws_access_key = os.getenv('AWS_ACCESS_KEY')
        aws_secret_key = os.getenv('AWS_SECRET_KEY')
        region_name = os.getenv('AWS_REGION', 'ind-south-1')
        endpoint_url = os.getenv('S3_ENDPOINT_URL')
        client_args = {
            'service_name': 's3',
            'aws_access_key_id': aws_access_key,
            'aws_secret_access_key': aws_secret_key,
            'region_name': region_name,
            'config': botocore.client.Config(connect_timeout=10, read_timeout=30)
        }
        if endpoint_url:
            client_args['endpoint_url'] = endpoint_url
        self.s3 = boto3.client(**client_args)

    def get_object_text(self, bucket_name, object_key):
        try:
            logging.info(f"Fetching object {object_key} from bucket {bucket_name}")
            obj = self.s3.get_object(Bucket=bucket_name, Key=object_key)
            return obj['Body'].read().decode('utf-8')
        except Exception as e:
            logging.error(f"Error fetching S3 object {object_key} from bucket {bucket_name}: {e}")
            return None

=======
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


>>>>>>> d7328bf (changed proj)
class PIIAnalyzer:
    _engine = None

    def __init__(self):
        if PIIAnalyzer._engine is None:
            logging.info("Initializing AnalyzerEngine")
<<<<<<< HEAD
            PIIAnalyzer._engine = AnalyzerEngine()
=======
            configuration = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": os.getenv("SPACY_MODEL", SPACY_MODEL)}],
            }
            provider = NlpEngineProvider(nlp_configuration=configuration)
            nlp_engine = provider.create_engine()
            PIIAnalyzer._engine = AnalyzerEngine(nlp_engine=nlp_engine)
>>>>>>> d7328bf (changed proj)
        self.engine = PIIAnalyzer._engine

    def analyze(self, text):
        try:
            logging.info("Running PII analysis")
<<<<<<< HEAD
            score_threshold = float(os.getenv('PII_SCORE_THRESHOLD', '0.6'))
            results = self.engine.analyze(text=text, entities=[], language='en')
=======
            score_threshold = float(os.getenv("PII_SCORE_THRESHOLD", str(PII_SCORE_THRESHOLD)))
            results = self.engine.analyze(text=text, entities=[], language="en")
>>>>>>> d7328bf (changed proj)
            filtered = [
                {
                    "type": r.entity_type,
                    "start": r.start,
                    "end": r.end,
                    "score": r.score,
                }
<<<<<<< HEAD
                for r in results if r.score >= score_threshold
=======
                for r in results
                if r.score >= score_threshold
>>>>>>> d7328bf (changed proj)
            ]
            logging.info(f"Filtered PII entities (score >= {score_threshold})")
            return filtered
        except Exception as e:
            logging.error(f"Error during PII analysis: {e}")
            return []

<<<<<<< HEAD
class PostgresDB:
    def __init__(self):
        self.db_params = {
            'dbname': os.getenv('PG_DBNAME'),
            'user': os.getenv('PG_USER'),
            'password': os.getenv('PG_PASSWORD'),
            'host': os.getenv('PG_HOST')
        }
=======

class SqlitePiiDB:
    def __init__(self):
        self.db_path = os.getenv("SQLITE_PATH", SQLITE_PATH)
>>>>>>> d7328bf (changed proj)

    def store_pii_results(self, bucket_name, object_key, pii_entities):
        try:
            logging.info(f"Storing PII results for {object_key} in bucket {bucket_name}")
<<<<<<< HEAD
            conn = psycopg2.connect(**self.db_params)
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO pii_objects (bucket_name, object_key, pii_entities) VALUES (%s, %s, %s)",
                (bucket_name, object_key, json.dumps(pii_entities))
=======
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
>>>>>>> d7328bf (changed proj)
            )
            conn.commit()
            cur.close()
            conn.close()
<<<<<<< HEAD
        except psycopg2.errors.UniqueViolation:
            logging.warning(f"Duplicate entry for {bucket_name}, {object_key}. Skipping insert.")
        except Exception as e:
            logging.error(f"Postgres error: {e}")
=======
        except Exception as e:
            logging.error(f"SQLite error: {e}")
>>>>>>> d7328bf (changed proj)


class PIIProcessor:
    def __init__(self):
<<<<<<< HEAD
        self.s3 = S3Handler()
        self.analyzer = PIIAnalyzer()
        self.db = PostgresDB()

    def process(self, bucket_name, object_key):
        text = self.s3.get_object_text(bucket_name, object_key)
=======
        self.storage = LocalStorageHandler()
        self.analyzer = PIIAnalyzer()
        self.db = SqlitePiiDB()

    def process(self, bucket_name, object_key):
        text = self.storage.get_object_text(bucket_name, object_key)
        if text is None:
            logging.error(f"Skipping analysis; object not found: {bucket_name}/{object_key}")
            return
>>>>>>> d7328bf (changed proj)
        pii_entities = self.analyzer.analyze(text)
        self.db.store_pii_results(bucket_name, object_key, pii_entities)
        logging.info(f"PII entities stored: {pii_entities}")


if __name__ == "__main__":
<<<<<<< HEAD
    from dotenv import load_dotenv
    load_dotenv()
    print("Starting PII analyser...")
    redis_handler = RedisHandler()
    processor = PIIProcessor()
    processed_count = 0
    while True:
        try:
            bucket_name, object_key = redis_handler.fetch_bucket_object_sorted()
            if bucket_name and object_key:
                processor.process(bucket_name, object_key)
                processed_count += 1
            time.sleep(5)
            logging.info(f"Processed {processed_count} objects from Redis sorted set queue.")
        except Exception as e:
            logging.error(f"Error processing {bucket_name}, {object_key}: {e}")


=======
    load_dotenv()
    print("PII analyser is invoked automatically after local uploads.")
    print("To analyze an existing object: PIIProcessor().process(bucket, key)")
>>>>>>> d7328bf (changed proj)
