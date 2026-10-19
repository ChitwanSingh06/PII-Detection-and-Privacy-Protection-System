import asyncio
import json
import logging
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PII_ANALYSER_DIR = ROOT / "consumer_analyzer" / "pii_analyser"
for path in (str(ROOT), str(PII_ANALYSER_DIR)):
    if path not in sys.path:
        sys.path.insert(0, path)

from pii_analyser import PIIProcessor  # noqa: E402
from config import KAFKA_BOOTSTRAP_SERVERS, KAFKA_GROUP_ID, KAFKA_SCAN_TOPIC, SQLITE_PATH  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


class LocalUploadTrigger:
    """Replace S3 PUT / Kafka events with an in-process analysis trigger."""

    def __init__(self):
        self.processor = PIIProcessor()

    def on_put(self, bucket_name: str, object_key: str):
        """Analyze the object; returns the stored spans, or None if it could not be read."""
        logging.info(f"Local PUT trigger: analyzing {bucket_name}/{object_key}")
        return self.processor.process(bucket_name, object_key)


# --- Kafka worker: consumes the scan jobs the proxy queues (kafka_producer.py) -----------------------------
# Run:  python consumer_analyzer/consumer/kafka_consumer.py   (see README)
# Each job is scanned with the existing LocalUploadTrigger / PIIProcessor, so results land in the same
# pii_objects table and the same dashboard_events record the upload request used to write itself.
_loop = None


def _run(coro):
    global _loop
    if _loop is None:
        _loop = asyncio.new_event_loop()  # one loop for the worker's lifetime (shared async DB engine)
    return _loop.run_until_complete(coro)


def _dashboard():
    if str(ROOT / "proxy-server") not in sys.path:
        sys.path.insert(0, str(ROOT / "proxy-server"))
    import dashboard

    return dashboard


def _record_detection(job: dict, entities) -> None:
    """The 'detection' dashboard event (entity types and counts only). The job id makes a redelivered
    job count once."""
    record_event = _dashboard().record_event
    if entities is None:
        _run(record_event("detection", status="failed", bucket=job["bucket"], key=job["key"],
                          request_id=job["job_id"]))
    else:
        _run(record_event("detection", bucket=job["bucket"], key=job["key"], entity_count=len(entities),
                          details={"by_entity_type": dict(Counter(e["type"] for e in entities))},
                          request_id=job["job_id"]))


def handle_job(trigger, raw: bytes) -> None:
    """Scan one queued job. A malformed message is logged and skipped so it cannot block the queue."""
    try:
        job = json.loads(raw)
        if not all(isinstance(job[k], str) and job[k] for k in ("job_id", "bucket", "key")):
            raise ValueError("job fields must be non-empty strings")
    except (ValueError, KeyError, TypeError) as exc:
        logging.error(f"Skipping malformed scan job: {exc}")
        return
    try:
        entities = trigger.on_put(job["bucket"], job["key"])
    except Exception:  # noqa: BLE001 - one bad file must not stop the worker
        logging.exception(f"Scan failed for {job['bucket']}/{job['key']}")
        entities = None
    _record_detection(job, entities)


def _make_consumer():
    from kafka import KafkaConsumer
    from kafka.admin import KafkaAdminClient, NewTopic
    from kafka.errors import TopicAlreadyExistsError

    servers = KAFKA_BOOTSTRAP_SERVERS.split(",")
    try:  # make sure the topic exists before subscribing (the broker may also auto-create it)
        admin = KafkaAdminClient(bootstrap_servers=servers, bootstrap_timeout_ms=5000)
        try:
            admin.create_topics([NewTopic(KAFKA_SCAN_TOPIC, num_partitions=1, replication_factor=1)])
        except TopicAlreadyExistsError:
            pass
        finally:
            admin.close()
    except Exception as exc:  # noqa: BLE001
        logging.warning(f"Could not check/create topic {KAFKA_SCAN_TOPIC}: {exc}")
    return KafkaConsumer(
        KAFKA_SCAN_TOPIC,
        bootstrap_servers=servers,
        bootstrap_timeout_ms=10000,
        group_id=KAFKA_GROUP_ID,
        enable_auto_commit=False,  # a job is acknowledged only after its result is stored
        auto_offset_reset="earliest",  # jobs queued while the worker was down are still processed
    )


def run_worker(consumer=None, trigger=None) -> None:
    _dashboard().ensure_schema(SQLITE_PATH)  # the table is created if the proxy has never run
    trigger = trigger or LocalUploadTrigger()
    consumer = consumer or _make_consumer()
    logging.info(f"Kafka worker listening on {KAFKA_BOOTSTRAP_SERVERS}, topic {KAFKA_SCAN_TOPIC}")
    try:
        for message in consumer:
            handle_job(trigger, message.value)
            consumer.commit()  # at-least-once: committed after the result is stored
    except KeyboardInterrupt:
        logging.info("Kafka worker stopping")
    finally:
        consumer.close()


if __name__ == "__main__":
    try:
        run_worker()
    except Exception as exc:  # noqa: BLE001
        if type(exc).__name__ in ("KafkaTimeoutError", "KafkaConnectionError"):  # no broker reachable
            sys.exit(f"Cannot reach Kafka at {KAFKA_BOOTSTRAP_SERVERS}. Start it with: docker compose up -d")
        raise
