"""Kafka producer: queues one PII scan job per stored file. The scan itself runs in the worker
(kafka_consumer.py), which uses the existing PIIProcessor."""
import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import KAFKA_BOOTSTRAP_SERVERS, KAFKA_SCAN_TOPIC  # noqa: E402

log = logging.getLogger(__name__)


class ScanQueueError(Exception):
    """The scan job could not be queued (broker unreachable, no acknowledgement, ...)."""


class ScanJobProducer:
    def __init__(self, producer=None):
        self._producer = producer  # injectable for tests; created on first use otherwise

    def _client(self):
        if self._producer is None:
            from kafka import KafkaProducer  # imported here so the app starts without a broker

            self._producer = KafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS.split(","),
                acks="all",
                retries=3,
                bootstrap_timeout_ms=5000,  # without this an unreachable broker blocks the upload for 30 s
                max_block_ms=5000,
                request_timeout_ms=10000,
            )
        return self._producer

    def publish(self, bucket: str, key: str) -> str:
        """Queue a scan job and wait for the broker's acknowledgement. Returns the job id."""
        job = {
            "job_id": uuid.uuid4().hex,
            "bucket": bucket,
            "key": key,
            "queued_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            # Same file -> same partition, so repeated uploads of one file are scanned in upload order.
            self._client().send(
                KAFKA_SCAN_TOPIC,
                key=f"{bucket}/{key}".encode("utf-8"),
                value=json.dumps(job).encode("utf-8"),
            ).get(timeout=10)
        except Exception as exc:  # noqa: BLE001 - any client/broker failure means "not queued"
            self._producer = None  # rebuild the client on the next attempt
            log.error("Could not queue scan job for %s/%s: %s", bucket, key, exc)
            raise ScanQueueError(str(exc)) from exc
        log.info("Queued scan job %s for %s/%s", job["job_id"], bucket, key)
        return job["job_id"]
