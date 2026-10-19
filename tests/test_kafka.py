"""Kafka scan-job queue: the upload request queues a job, the worker scans it with the existing engine.

No broker is needed: the Kafka client objects are replaced by small fakes. The worker tests use the real
LocalUploadTrigger (spaCy/Presidio), the real SQLite tables and the real dashboard event writer.
"""
import json
import sqlite3
from types import SimpleNamespace

import pytest

import config

TEXT = b"Contact jane.doe@example.com about the invoice."


class FakeKafkaProducer:
    def __init__(self, fail=False):
        self.sent, self.fail = [], fail

    def send(self, topic, key=None, value=None):
        if self.fail:
            raise RuntimeError("broker down")
        self.sent.append((topic, key, value))
        return SimpleNamespace(get=lambda timeout=None: None)


def events(event_type="detection"):
    conn = sqlite3.connect(config.SQLITE_PATH)
    rows = conn.execute("SELECT bucket_name, object_key, status, entity_count, details, request_id "
                        "FROM dashboard_events WHERE event_type=? ORDER BY id", (event_type,)).fetchall()
    conn.close()
    return rows


def scanned(bucket, key):
    conn = sqlite3.connect(config.SQLITE_PATH)
    row = conn.execute("SELECT pii_entities FROM pii_objects WHERE bucket_name=? AND object_key=?", (bucket, key)).fetchone()
    conn.close()
    return None if row is None else json.loads(row[0])


@pytest.fixture
def queue(monkeypatch):
    """Switch the proxy to Kafka mode with a fake producer; returns the producer."""
    import app as proxy_app
    import kafka_producer

    fake = FakeKafkaProducer()
    monkeypatch.setattr(proxy_app, "KAFKA_ENABLED", True)
    monkeypatch.setattr(proxy_app, "_scan_producer", kafka_producer.ScanJobProducer(fake))
    return fake


# ------------------------------------------------------------------------------------------ producer
def test_publish_sends_one_json_job_to_the_scan_topic():
    import kafka_producer

    fake = FakeKafkaProducer()
    job_id = kafka_producer.ScanJobProducer(fake).publish("docs", "a/b.txt")
    (topic, key, value), = fake.sent
    job = json.loads(value)
    assert topic == config.KAFKA_SCAN_TOPIC and key == b"docs/a/b.txt"
    assert (job["job_id"], job["bucket"], job["key"]) == (job_id, "docs", "a/b.txt") and job["queued_at"]


def test_publish_failure_is_a_scan_queue_error():
    import kafka_producer

    with pytest.raises(kafka_producer.ScanQueueError):
        kafka_producer.ScanJobProducer(FakeKafkaProducer(fail=True)).publish("docs", "x.txt")


# ------------------------------------------------------------------------------------------ upload
def test_upload_queues_a_job_instead_of_scanning_in_the_request(client, admin_h, queue):
    r = client.put("/kq/queued.txt", content=TEXT, headers=admin_h)
    assert r.status_code == 200
    assert [json.loads(v)["key"] for _, _, v in queue.sent] == ["queued.txt"]
    assert scanned("kq", "queued.txt") is None  # not scanned yet: that is the worker's job
    assert [e for e in events() if e[1] == "queued.txt"] == []
    assert any(e[1] == "queued.txt" for e in events("upload"))  # the upload itself is still recorded
    client.delete("/kq/queued.txt", headers=admin_h)


def test_upload_when_the_queue_is_unavailable_is_a_503_and_a_failed_detection(client, admin_h, queue):
    queue.fail = True
    r = client.put("/kq/down.txt", content=TEXT, headers=admin_h)
    assert r.status_code == 503 and "could not be queued" in r.json()["detail"]
    (ev,) = [e for e in events() if e[1] == "down.txt"]
    assert ev[2] == "failed" and "queue_unavailable" in ev[4]
    acts = client.get("/api/dashboard/activity?limit=20", headers=admin_h).json()["data"]["items"]
    assert any(a["object_key"] == "down.txt" and a["summary"] == "Scan job could not be queued (Kafka unavailable)"
               for a in acts)
    client.delete("/kq/down.txt", headers=admin_h)


def test_kafka_disabled_keeps_the_original_in_request_scan(client, admin_h):
    import app as proxy_app

    assert proxy_app.KAFKA_ENABLED is False  # tests/conftest.py
    assert client.put("/kq/direct.txt", content=TEXT, headers=admin_h).status_code == 200
    assert scanned("kq", "direct.txt")  # scanned before the response, as before
    client.delete("/kq/direct.txt", headers=admin_h)


# ------------------------------------------------------------------------------------------ worker
def make_job(bucket, key, job_id="job-1"):
    return json.dumps({"job_id": job_id, "bucket": bucket, "key": key, "queued_at": "now"}).encode()


def put_file(client, admin_h, name):
    # stored through the API with the in-request scan off, then its scan row removed: only the worker may fill it
    assert client.put(f"/kq/{name}", content=TEXT, headers=admin_h).status_code == 200
    conn = sqlite3.connect(config.SQLITE_PATH)
    conn.execute("DELETE FROM pii_objects WHERE bucket_name='kq' AND object_key=?", (name,))
    conn.execute("DELETE FROM dashboard_events WHERE event_type='detection' AND object_key=?", (name,))
    conn.commit()
    conn.close()


def test_worker_scans_a_job_with_the_existing_engine_and_stores_the_result(client, admin_h):
    import kafka_consumer

    put_file(client, admin_h, "w1.txt")
    assert scanned("kq", "w1.txt") is None
    kafka_consumer.handle_job(kafka_consumer.LocalUploadTrigger(), make_job("kq", "w1.txt", "job-w1"))
    spans = scanned("kq", "w1.txt")
    assert any(s["type"] == "EMAIL_ADDRESS" for s in spans)
    (ev,) = [e for e in events() if e[1] == "w1.txt"]
    assert ev[2] == "ok" and ev[3] == len(spans) and json.loads(ev[4])["by_entity_type"]["EMAIL_ADDRESS"] == 1
    assert "jane.doe@example.com" not in json.dumps(ev)  # matched text is never recorded
    # the dashboard reads the worker's result like any other
    d = client.get("/api/dashboard/summary", headers=admin_h).json()["data"]
    assert d["scanned_objects"] >= 1
    client.delete("/kq/w1.txt", headers=admin_h)


def test_a_redelivered_job_is_counted_once(client, admin_h):
    import kafka_consumer

    put_file(client, admin_h, "w2.txt")
    trigger = kafka_consumer.LocalUploadTrigger()
    for _ in range(2):
        kafka_consumer.handle_job(trigger, make_job("kq", "w2.txt", "job-w2"))
    assert len([e for e in events() if e[1] == "w2.txt"]) == 1
    client.delete("/kq/w2.txt", headers=admin_h)


def test_job_for_a_missing_file_is_recorded_as_a_failed_detection(client):
    import kafka_consumer

    kafka_consumer.handle_job(kafka_consumer.LocalUploadTrigger(), make_job("kq", "never-stored.txt", "job-w3"))
    (ev,) = [e for e in events() if e[1] == "never-stored.txt"]
    assert ev[2] == "failed"


def test_worker_loop_commits_each_job_and_skips_malformed_messages(client):
    import kafka_consumer

    seen, commits = [], []

    class Trigger:
        def on_put(self, bucket, key):
            seen.append((bucket, key))
            return [{"type": "PERSON", "start": 0, "end": 4, "score": 0.9}]

    class Consumer:
        def __init__(self, values):
            self.values, self.closed = values, False

        def __iter__(self):
            return iter(SimpleNamespace(value=v) for v in self.values)

        def commit(self):
            commits.append(1)

        def close(self):
            self.closed = True

    consumer = Consumer([b"not json", json.dumps({"job_id": "x"}).encode(), make_job("kq", "loop.txt", "job-w4")])
    kafka_consumer.run_worker(consumer=consumer, trigger=Trigger())
    assert seen == [("kq", "loop.txt")]  # the two bad messages were skipped, not fatal
    assert len(commits) == 3 and consumer.closed  # all three acknowledged, so a bad one cannot block the queue
    assert [e[3] for e in events() if e[1] == "loop.txt"] == [1]


def test_scan_exception_does_not_stop_the_worker(client):
    import kafka_consumer

    class Boom:
        def on_put(self, bucket, key):
            raise RuntimeError("scan blew up")

    kafka_consumer.handle_job(Boom(), make_job("kq", "boom.txt", "job-w5"))
    (ev,) = [e for e in events() if e[1] == "boom.txt"]
    assert ev[2] == "failed"

def test_worker_does_not_report_success_when_the_result_could_not_be_stored(client, admin_h, monkeypatch):
    import kafka_consumer

    put_file(client, admin_h, "w6.txt")
    trigger = kafka_consumer.LocalUploadTrigger()
    monkeypatch.setattr(trigger.processor.db, "db_path", "/proc/nonexistent/ro.db")  # sqlite cannot open it
    kafka_consumer.handle_job(trigger, make_job("kq", "w6.txt", "job-w6"))
    (ev,) = [e for e in events() if e[1] == "w6.txt"]
    assert ev[2] == "failed" and scanned("kq", "w6.txt") is None  # no detection without a stored result
    client.delete("/kq/w6.txt", headers=admin_h)


def test_queued_scan_shows_up_in_dashboard_and_pii_detection_after_the_worker_runs(client, admin_h, queue):
    import kafka_consumer

    body = b"Pay with card 4111 1111 1111 1111 or mail a@b.org"
    assert client.put("/kq/flow.txt", content=body, headers=admin_h).status_code == 200
    assert scanned("kq", "flow.txt") is None  # queued only
    (_, _, value), = queue.sent  # consume exactly what the proxy published
    kafka_consumer.handle_job(kafka_consumer.LocalUploadTrigger(), value)
    assert any(s["type"] == "CREDIT_CARD" for s in scanned("kq", "flow.txt"))
    d = client.get("/api/admin/pii-detection?limit=20", headers=admin_h).json()["data"]
    assert "CREDIT_CARD" in json.dumps(d)
    acts = client.get("/api/dashboard/activity?limit=50", headers=admin_h).json()["data"]["items"]
    assert any(a["object_key"] == "flow.txt" and a["event_type"] == "detection" for a in acts)
    client.delete("/kq/flow.txt", headers=admin_h)
