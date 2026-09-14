
import os
import json
import time
import redis
import logging
from confluent_kafka import Consumer
from dotenv import load_dotenv

load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)

class RedisHandler:
    def __init__(self, host, port, queue):
        self.client = redis.Redis(host=host, port=port, decode_responses=True)
        self.queue = queue

    def add_to_sorted_set(self, object_name, bucket_name):
        data = f"{object_name}:{bucket_name}"
        score = time.time()
        if self.client.zscore(self.queue, data) is None:
            if self.client.zadd(self.queue, {data: score}):
                logging.info(f"Stored in Redis: {object_name} -> {bucket_name}")
                return True
            else:
                logging.error(f"Failed to store in Redis: {object_name} -> {bucket_name}")
                return False
        else:
            logging.info(f"Skipped duplicate: {object_name} -> {bucket_name}")
            return True

class KafkaPIIConsumer:
    def __init__(self):
        # Kafka configuration
        self.bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "r1-kafka-broker-0-external.kafka.svc.cluster.local:9094")
        self.topic = os.getenv("KAFKA_TOPIC", "fastobject.di.s3.events")
        self.security_protocol = os.getenv("SECURITY_PROTOCOL", "SASL_PLAINTEXT")
        self.sasl_mechanism = os.getenv("SASL_MECHANISM", "PLAIN")
        self.sasl_username = os.getenv("KAFKA_USERNAME", "user1")
        self.sasl_password = os.getenv("KAFKA_PASSWORD", "ZGh7pFkVbV")
        self.auto_offset_reset = os.getenv("AUTO_OFFSET_RESET", "earliest")
        self.group_id = os.getenv("KAFKA_GROUP_ID", "PII-analyzer-kafka-consumer")

        # Redis configuration
        redis_host = os.getenv("REDIS_HOST", "redis.default.svc.cluster.local")
        redis_port = os.getenv("REDIS_PORT", 6379)
        redis_queue = os.getenv("REDIS_QUEUE", "kafka_notifications")
        logging.info(f"Connecting to Redis at {redis_host}:{redis_port}, queue: {redis_queue}")
        self.redis_handler = RedisHandler(redis_host, redis_port, redis_queue)

        # Kafka consumer setup
        self.consumer = Consumer({
            "bootstrap.servers": self.bootstrap_servers,
            "group.id": self.group_id,
            "auto.offset.reset": self.auto_offset_reset,
            "enable.auto.commit": False,
            "max.poll.interval.ms": 86400000,
            "security.protocol": self.security_protocol,
            "sasl.mechanism": self.sasl_mechanism,
            "sasl.username": self.sasl_username,
            "sasl.password": self.sasl_password
        })
        self.consumer.subscribe([self.topic])

    def process_message(self, event):
        try:
            records = event.get("Records", [])
            for record in records:
                event_name = record.get("eventName")
                if event_name == "ObjectCreated:Put":
                    bucket_name = record.get("s3", {}).get("bucket", {}).get("name")
                    object_name = record.get("s3", {}).get("object", {}).get("key")
                    if bucket_name and object_name:
                        return self.redis_handler.add_to_sorted_set(object_name, bucket_name)
                    else:
                        logging.warning("Missing bucket or object name in record.")
                        return False
                else:
                    logging.info(f"Ignored event: {event_name}")
            return True
        except Exception as e:
            logging.error(f"Error processing event: {e}")
            return False

    def run(self):
        while not self.consumer.assignment():
            logging.info("Waiting for partition assignment...")
            self.consumer.poll(timeout=1.0)

        logging.info(f"Listening for messages on topic '{self.topic}'...")
        while True:
            try:
                processed_successfully = False
                msg = self.consumer.poll(1.0)
                if msg is None:
                    continue
                if msg.error():
                    logging.error(f"Consumer error: {msg.error()}")
                    continue
                if msg.value() is None:
                    continue

                try:
                    current_offset = msg.offset()
                    logging.info(f"Current offset: {current_offset}")
                    payload = msg.value().decode("utf-8")
                    logging.info(f"Raw message: {payload}")
                    try:
                        event = json.loads(payload)
                    except Exception as e:
                        logging.error(f"JSON decode error: {e}")
                        continue

                    logging.info(f"Received event - {event}")

                    if self.process_message(event):
                        processed_successfully = True
                    else:
                        logging.error("Failed to process the event")

                    if processed_successfully:
                        self.consumer.commit(message=msg)
                        logging.info(f"Committed offset: {current_offset}")
                except Exception as e:
                    logging.error(f"Error processing message: {e}")

            except Exception as e:
                logging.error(f"Error processing message: {e}")

if __name__ == "__main__":
    consumer = KafkaPIIConsumer()
    consumer.run()