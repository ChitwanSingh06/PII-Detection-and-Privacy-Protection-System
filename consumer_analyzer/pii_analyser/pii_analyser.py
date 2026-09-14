import os
import logging
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

class PIIAnalyzer:
    _engine = None

    def __init__(self):
        if PIIAnalyzer._engine is None:
            logging.info("Initializing AnalyzerEngine")
            PIIAnalyzer._engine = AnalyzerEngine()
        self.engine = PIIAnalyzer._engine

    def analyze(self, text):
        try:
            logging.info("Running PII analysis")
            score_threshold = float(os.getenv('PII_SCORE_THRESHOLD', '0.6'))
            results = self.engine.analyze(text=text, entities=[], language='en')
            filtered = [
                {
                    "type": r.entity_type,
                    "start": r.start,
                    "end": r.end,
                    "score": r.score,
                }
                for r in results if r.score >= score_threshold
            ]
            logging.info(f"Filtered PII entities (score >= {score_threshold})")
            return filtered
        except Exception as e:
            logging.error(f"Error during PII analysis: {e}")
            return []

class PostgresDB:
    def __init__(self):
        self.db_params = {
            'dbname': os.getenv('PG_DBNAME'),
            'user': os.getenv('PG_USER'),
            'password': os.getenv('PG_PASSWORD'),
            'host': os.getenv('PG_HOST')
        }

    def store_pii_results(self, bucket_name, object_key, pii_entities):
        try:
            logging.info(f"Storing PII results for {object_key} in bucket {bucket_name}")
            conn = psycopg2.connect(**self.db_params)
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO pii_objects (bucket_name, object_key, pii_entities) VALUES (%s, %s, %s)",
                (bucket_name, object_key, json.dumps(pii_entities))
            )
            conn.commit()
            cur.close()
            conn.close()
        except psycopg2.errors.UniqueViolation:
            logging.warning(f"Duplicate entry for {bucket_name}, {object_key}. Skipping insert.")
        except Exception as e:
            logging.error(f"Postgres error: {e}")


class PIIProcessor:
    def __init__(self):
        self.s3 = S3Handler()
        self.analyzer = PIIAnalyzer()
        self.db = PostgresDB()

    def process(self, bucket_name, object_key):
        text = self.s3.get_object_text(bucket_name, object_key)
        pii_entities = self.analyzer.analyze(text)
        self.db.store_pii_results(bucket_name, object_key, pii_entities)
        logging.info(f"PII entities stored: {pii_entities}")


if __name__ == "__main__":
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


