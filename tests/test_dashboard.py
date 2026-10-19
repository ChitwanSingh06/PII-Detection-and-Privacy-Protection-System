"""Live Dashboard API: schemas, metric accuracy against the real SQLite/storage, empty DB, no PII leakage.

Real here: JWT auth, the proxy's PUT/GET/DELETE and /api/llm/chat code paths, SQLite (pii_objects, users,
policies, dashboard_events), the storage folder, and Presidio's anonymizer (via PIIAnonymizer, called the
way the gRPC handler calls it). Stubbed: the spaCy analyzer (fixed spans, so counts are deterministic),
the gRPC transport, and Ollama.
"""
import json
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import grpc
import pytest

import config

KNOWN = {  # value -> (entity type, score)
    "Priya Raman": ("PERSON", 0.85),
    "priya.raman@acme.in": ("EMAIL_ADDRESS", 1.0),
    "4532 8891 0023 7714": ("CREDIT_CARD", 1.0),
    "123-45-6789": ("US_SSN", 0.85),
    "10.24.8.17": ("IP_ADDRESS", 0.95),
    "+91 98765 43210": ("PHONE_NUMBER", 0.75),
}
RAW_PII = list(KNOWN)

OBJECTS = {
    "b1/a.txt": "Customer Priya Raman, priya.raman@acme.in, card 4532 8891 0023 7714",  # PERSON EMAIL CC
    "b1/b.txt": "Nothing sensitive in this one.",
    "b2/c.txt": "Mail priya.raman@acme.in, SSN 123-45-6789, from 10.24.8.17",  # EMAIL SSN IP
    "b2/d.txt": "Card on file: 4532 8891 0023 7714",  # CC
    "b2/e.txt": "Login from 10.24.8.17",  # IP
}


def spans(text):
    return [{"type": t, "start": text.index(v), "end": text.index(v) + len(v), "score": s}
            for v, (t, s) in KNOWN.items() if v in text]


def db():
    return sqlite3.connect(config.SQLITE_PATH)


@pytest.fixture
def env(client, monkeypatch):
    """Clean test DB tables/storage (temp dirs from conftest), fake analyzer, stubbed gRPC + Ollama."""
    import app as proxy_app
    from anonymizer.pii_anonymizer import PIIAnonymizer
    from pii_analyser import SqlitePiiDB

    conn = db()
    conn.execute("DELETE FROM pii_objects")
    conn.execute("DELETE FROM dashboard_events")
    conn.commit()
    conn.close()
    root = Path(config.STORAGE_ROOT)
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)

    real_db = SqlitePiiDB()

    class Analyzer:
        def analyze(self, text, raise_on_error=False):
            if state.analyzer_down:
                if raise_on_error:
                    raise RuntimeError("analyzer down")
                return []  # what the real analyzer does by default: errors look like "no PII"
            return spans(text)

    class Trigger:  # same contract as LocalUploadTrigger.on_put / PIIProcessor.process
        processor = SimpleNamespace(analyzer=Analyzer(), db=real_db)

        def on_put(self, bucket, key):
            try:
                text = (root / bucket / key).read_text(encoding="utf-8")
            except Exception:
                return None
            found = spans(text)
            real_db.store_pii_results(bucket, key, found)
            return found

    state = SimpleNamespace(grpc_down=False, analyzer_down=False, ollama=[])

    class Channel:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    class Stub:  # anonymizer/server/handler.py logic: spans from SQLite by bucket/key
        def __init__(self, channel):
            pass

        async def AnonymizeObject(self, request, timeout=None):
            if state.grpc_down:
                raise grpc.aio.AioRpcError(grpc.StatusCode.UNAVAILABLE, grpc.aio.Metadata(),
                                           grpc.aio.Metadata(), details="anonymizer down")
            c = db()
            row = c.execute("SELECT pii_entities FROM pii_objects WHERE bucket_name=? AND object_key=?",
                            (request.bucketName, request.objectKey)).fetchone()
            c.close()
            data = request.objectData.decode("utf-8")
            out = data if not row else PIIAnonymizer().anonymize_data(
                object_data=data, policy_map=request.policy_map, pii_metadata=json.loads(row[0]))
            return proxy_app.an_pb2.AnonymizeObjectResponse(updatedObjectData=out.encode(), objectLength=len(out))

    def fake_ollama(payload):
        state.ollama.append(payload)
        return {"model": "llama3.2", "message": {"role": "assistant", "content": "ok"}, "done": True}

    monkeypatch.setattr(proxy_app, "get_upload_trigger", lambda: Trigger())
    monkeypatch.setattr(proxy_app.grpc.aio, "insecure_channel", lambda url: Channel())
    monkeypatch.setattr(proxy_app.an_pb2_grpc, "PIIAnonymizerServiceStub", Stub)
    monkeypatch.setattr(proxy_app, "_call_ollama", fake_ollama)
    state.root = root
    return state


def seed(client, admin_h, env):
    for path, body in OBJECTS.items():
        assert client.put(f"/{path}", content=body.encode(), headers=admin_h).status_code == 200
    # binary upload: the analyzer cannot read it as text -> failed detection, stays unscanned
    assert client.put("/b2/bin.dat", content=b"\xff\xfe\x00\x81", headers=admin_h).status_code == 200
    # a file placed in storage without going through the proxy -> unscanned, no events
    (env.root / "b2" / "raw.txt").write_text("dropped in by hand")


def get(client, path, headers):
    return client.get(path, headers=headers).json()


ENDPOINTS = ["summary", "pii-types", "detection", "anonymization", "llm-prompts", "activity"]


# ---- auth + envelope ---------------------------------------------------------------------------
@pytest.mark.parametrize("ep", ENDPOINTS)
def test_requires_token(client, ep):
    assert client.get(f"/api/dashboard/{ep}").status_code == 401


@pytest.mark.parametrize("ep", ENDPOINTS)
def test_regular_user_can_read_and_envelope_is_consistent(client, user1_h, ep):
    r = client.get(f"/api/dashboard/{ep}", headers=user1_h)
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"generated_at", "data"}
    assert body["generated_at"].endswith("Z")


def test_schemas_exact_keys(client, admin_h, env):
    seed(client, admin_h, env)
    s = get(client, "/api/dashboard/summary", admin_h)["data"]
    assert set(s) == {"total_objects", "total_buckets", "total_size_bytes", "scanned_objects", "unscanned_objects",
                      "objects_with_pii", "objects_without_pii", "scan_coverage_pct", "orphaned_metadata_rows", "buckets"}
    assert set(s["buckets"][0]) == {"bucket", "objects", "scanned", "with_pii", "size_bytes"}
    p = get(client, "/api/dashboard/pii-types", admin_h)["data"]
    assert set(p) == {"total_entities", "objects_with_pii", "types"}
    assert set(p["types"][0]) == {"entity_type", "count", "objects", "avg_score", "min_score", "max_score"}
    d = get(client, "/api/dashboard/detection", admin_h)["data"]
    assert set(d) == {"window_days", "tz_offset_minutes", "objects_scanned", "objects_with_pii", "total_entities",
                      "detection_runs_total", "detection_failures_total", "tracking_since", "timeline", "protection"}
    assert set(d["timeline"][0]) == {"date", "detection_runs", "entities_detected", "failed_runs"}
    assert set(d["protection"]) == {"basis", "assigned_policies", "users_without_policy", "protected_objects",
                                    "partially_protected_objects", "unprotected_objects", "protected_pct",
                                    "partially_protected_pct", "unprotected_pct", "uncovered_entity_types"}
    a = get(client, "/api/dashboard/anonymization", admin_h)["data"]
    assert set(a) == {"window_days", "tz_offset_minutes", "requests_total", "anonymized_ok", "failed",
                      "served_original", "entities_anonymized", "by_operator", "by_entity_type", "by_source",
                      "tracking_since", "timeline"}
    lp = get(client, "/api/dashboard/llm-prompts", admin_h)["data"]
    assert set(lp) == {"window_days", "tz_offset_minutes", "prompts_total", "prompts_sent", "prompts_blocked",
                       "prompts_with_pii", "prompts_protected", "prompts_unchanged", "entities_detected",
                       "entities_protected", "by_entity_type", "by_operator", "tracking_since", "timeline"}
    assert set(lp["timeline"][0]) == {"date", "prompts", "with_pii", "blocked"}
    act = get(client, "/api/dashboard/activity", admin_h)["data"]
    assert set(act) == {"limit", "total_events", "items"}
    assert set(act["items"][0]) == {"id", "timestamp", "event_type", "source", "actor", "bucket", "object_key",
                                    "status", "entity_count", "summary"}


# ---- empty databases ---------------------------------------------------------------------------
def _assert_empty(client, h):
    s = get(client, "/api/dashboard/summary", h)["data"]
    assert s["total_objects"] == s["scanned_objects"] == s["objects_with_pii"] == 0
    assert s["scan_coverage_pct"] is None and s["buckets"] == []
    p = get(client, "/api/dashboard/pii-types", h)["data"]
    assert p == {"total_entities": 0, "objects_with_pii": 0, "types": []}
    d = get(client, "/api/dashboard/detection", h)["data"]
    assert len(d["timeline"]) == 14 and all(x["detection_runs"] == 0 for x in d["timeline"])
    assert d["tracking_since"] is None and d["protection"]["protected_pct"] is None
    a = get(client, "/api/dashboard/anonymization", h)["data"]
    assert a["requests_total"] == a["served_original"] == a["entities_anonymized"] == 0 and a["by_operator"] == []
    lp = get(client, "/api/dashboard/llm-prompts", h)["data"]
    assert lp["prompts_total"] == lp["prompts_sent"] == lp["prompts_blocked"] == lp["entities_detected"] == 0
    assert lp["by_entity_type"] == [] and lp["tracking_since"] is None and len(lp["timeline"]) == 14
    act = get(client, "/api/dashboard/activity", h)["data"]
    assert act["items"] == [] and act["total_events"] == 0


def test_empty_initialised_db(client, admin_h, env):
    _assert_empty(client, admin_h)


def test_never_initialised_db_has_no_tables(client, admin_h, monkeypatch, tmp_path):
    """A brand-new SQLite file with no tables at all and no storage folder must read as zeros, not 500."""
    import dashboard
    from sqlalchemy.ext.asyncio import create_async_engine

    fresh = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'fresh.db'}")
    monkeypatch.setattr(dashboard, "_engine", lambda: fresh)
    monkeypatch.setenv("STORAGE_ROOT", str(tmp_path / "no-such-storage"))
    _assert_empty(client, admin_h)


# ---- accuracy ----------------------------------------------------------------------------------
def test_object_and_pii_counts_match_storage_and_sqlite(client, admin_h, env):
    seed(client, admin_h, env)
    s = get(client, "/api/dashboard/summary", admin_h)["data"]
    assert (s["total_objects"], s["total_buckets"], s["scanned_objects"], s["unscanned_objects"]) == (7, 2, 5, 2)
    assert (s["objects_with_pii"], s["objects_without_pii"], s["scan_coverage_pct"]) == (4, 1, 71.4)
    expected_size = sum(len(b.encode()) for b in OBJECTS.values()) + 4 + len("dropped in by hand")
    assert s["total_size_bytes"] == expected_size
    assert {b["bucket"]: (b["objects"], b["scanned"], b["with_pii"]) for b in s["buckets"]} == {
        "b1": (2, 2, 1), "b2": (5, 3, 3)}

    p = get(client, "/api/dashboard/pii-types", admin_h)["data"]
    by = {t["entity_type"]: t for t in p["types"]}
    assert {k: (v["count"], v["objects"]) for k, v in by.items()} == {
        "PERSON": (1, 1), "EMAIL_ADDRESS": (2, 2), "CREDIT_CARD": (2, 2), "US_SSN": (1, 1), "IP_ADDRESS": (2, 2)}
    assert p["total_entities"] == 8 and p["objects_with_pii"] == 4
    assert by["PERSON"]["avg_score"] == 0.85 and by["IP_ADDRESS"]["max_score"] == 0.95
    assert [t["count"] for t in p["types"]] == sorted([t["count"] for t in p["types"]], reverse=True)


def test_detection_timeline_and_protection_coverage(client, admin_h, env):
    seed(client, admin_h, env)
    d = get(client, "/api/dashboard/detection?tz_offset_minutes=0", admin_h)["data"]
    assert d["detection_runs_total"] == 6 and d["detection_failures_total"] == 1  # 5 text + 1 binary
    today = d["timeline"][-1]
    assert today["date"] == datetime.now(timezone.utc).date().isoformat()
    assert (today["detection_runs"], today["entities_detected"], today["failed_runs"]) == (6, 8, 1)
    assert d["tracking_since"] is not None

    pr = d["protection"]
    # user1_policy covers PERSON/CC/EMAIL/PHONE/SSN/BANK; user2_policy the same minus PERSON; admin has none.
    assert pr["assigned_policies"] == ["user1_policy", "user2_policy"] and pr["users_without_policy"] == 1
    # a: PERSON not in user2 -> partial; c: IP uncovered -> partial; d: CC everywhere -> protected; e: IP -> none
    assert (pr["protected_objects"], pr["partially_protected_objects"], pr["unprotected_objects"]) == (1, 2, 1)
    assert (pr["protected_pct"], pr["partially_protected_pct"], pr["unprotected_pct"]) == (25.0, 50.0, 25.0)
    assert pr["uncovered_entity_types"] == [{"entity_type": "IP_ADDRESS", "count": 2}]


def test_anonymization_stats_follow_real_gets(client, admin_h, user1_h, env):
    from conftest import bearer
    user2_h = bearer(client, "user2", "User2@12345")
    seed(client, admin_h, env)

    r1 = client.get("/b1/a.txt", headers=user1_h).text
    assert "Priya Raman" not in r1 and "priya.raman@acme.in" not in r1  # sanity: really anonymized
    r2 = client.get("/b1/a.txt", headers=user2_h).text
    assert "Priya Raman" in r2 and "priya.raman@acme.in" not in r2  # user2 policy keeps names
    assert client.get("/b1/a.txt", headers=admin_h).text == OBJECTS["b1/a.txt"]  # admin: no policy
    env.grpc_down = True
    client.get("/b2/d.txt", headers=user1_h)

    a = get(client, "/api/dashboard/anonymization?tz_offset_minutes=0", admin_h)["data"]
    assert (a["requests_total"], a["anonymized_ok"], a["failed"], a["served_original"]) == (3, 2, 1, 1)
    # user1: PERSON replace + EMAIL replace + CC mask = 3; user2: EMAIL mask + CC mask = 2
    assert a["entities_anonymized"] == 5
    assert {x["name"]: x["count"] for x in a["by_operator"]} == {"mask": 3, "replace": 2}
    assert {x["name"]: x["count"] for x in a["by_entity_type"]} == {"PERSON": 1, "EMAIL_ADDRESS": 2, "CREDIT_CARD": 2}
    assert a["by_source"] == [{"name": "object", "count": 3}]
    assert a["timeline"][-1] == {"date": datetime.now(timezone.utc).date().isoformat(), "anonymized": 2, "failed": 1}


def test_llm_prompt_protection_is_counted(client, user1_h, env):
    body = {"provider": "ollama", "model": "llama3.2",
            "messages": [{"role": "user", "content": "Email Priya Raman at priya.raman@acme.in from 10.24.8.17"}]}
    assert client.post("/api/llm/chat", json=body, headers=user1_h).status_code == 200
    a = get(client, "/api/dashboard/anonymization", user1_h)["data"]
    # user1 policy: PERSON + EMAIL; IP has no rule (kept) -> not counted as anonymized
    assert a["entities_anonymized"] == 2 and a["by_source"] == [{"name": "llm_prompt", "count": 1}]
    assert "llama" not in json.dumps(a)
    item = get(client, "/api/dashboard/activity", user1_h)["data"]["items"][0]
    assert item["source"] == "llm_prompt" and item["bucket"] is None and item["entity_count"] == 2


def test_delete_updates_counts_and_activity(client, admin_h, env):
    seed(client, admin_h, env)
    assert client.delete("/b2/e.txt", headers=admin_h).status_code == 204
    s = get(client, "/api/dashboard/summary", admin_h)["data"]
    assert (s["total_objects"], s["scanned_objects"], s["objects_with_pii"]) == (6, 4, 3)
    pr = get(client, "/api/dashboard/detection", admin_h)["data"]["protection"]
    assert pr["unprotected_objects"] == 0
    act = get(client, "/api/dashboard/activity?limit=1", admin_h)["data"]
    assert act["items"][0]["event_type"] == "delete" and act["items"][0]["actor"] == "admin"


def test_orphaned_metadata_is_excluded(client, admin_h, env):
    seed(client, admin_h, env)
    (env.root / "b1" / "a.txt").unlink()  # file removed outside the proxy; its pii_objects row remains
    s = get(client, "/api/dashboard/summary", admin_h)["data"]
    assert s["orphaned_metadata_rows"] == 1 and s["total_objects"] == 6 and s["objects_with_pii"] == 3
    assert get(client, "/api/dashboard/pii-types", admin_h)["data"]["total_entities"] == 5


def test_activity_order_limit_and_summaries(client, admin_h, env):
    seed(client, admin_h, env)
    act = get(client, "/api/dashboard/activity?limit=4", admin_h)["data"]
    assert act["limit"] == 4 and len(act["items"]) == 4 and act["total_events"] == 12  # 6 uploads + 6 detections
    ids = [i["id"] for i in act["items"]]
    assert ids == sorted(ids, reverse=True)
    newest = act["items"][0]  # bin.dat detection
    assert (newest["event_type"], newest["status"], newest["object_key"]) == ("detection", "failed", "bin.dat")
    det_a = [i for i in get(client, "/api/dashboard/activity?limit=100", admin_h)["data"]["items"]
             if i["event_type"] == "detection" and i["object_key"] == "a.txt"][0]
    assert det_a["summary"] == "3 entities detected (CREDIT_CARD, EMAIL_ADDRESS, PERSON)"
    assert client.get("/api/dashboard/activity?limit=0", headers=admin_h).status_code == 422
    assert client.get("/api/dashboard/activity?limit=101", headers=admin_h).status_code == 422


def test_timezone_day_buckets(client, admin_h, env):
    """An event at 20:00 UTC yesterday falls on yesterday (UTC) but on today/IST-next-day for +330."""
    created = (datetime.now(timezone.utc) - timedelta(days=1)).replace(hour=20, minute=0, second=0, microsecond=0)
    conn = db()
    conn.execute("INSERT INTO dashboard_events (created_at, event_type, status, entity_count, details) "
                 "VALUES (?, 'detection', 'ok', 4, '{}')", (created.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),))
    conn.commit()
    conn.close()
    for tz in (0, 330):
        tl = get(client, f"/api/dashboard/detection?tz_offset_minutes={tz}", admin_h)["data"]["timeline"]
        day = (created + timedelta(minutes=tz)).date().isoformat()
        assert {x["date"]: x["entities_detected"] for x in tl}.get(day) == 4
        assert sum(x["entities_detected"] for x in tl) == 4
    assert client.get("/api/dashboard/detection?tz_offset_minutes=9999", headers=admin_h).status_code == 422


# ---- privacy -------------------------------------------------------------------------------------
def test_no_raw_pii_in_events_or_dashboard_responses(client, admin_h, user1_h, env):
    seed(client, admin_h, env)
    client.get("/b1/a.txt", headers=user1_h)
    client.post("/api/llm/chat", headers=user1_h, json={"provider": "ollama", "model": "llama3.2", "messages": [
        {"role": "user", "content": "Call +91 98765 43210 about 123-45-6789"}]})
    conn = db()
    dumped = json.dumps(conn.execute("SELECT * FROM dashboard_events").fetchall())
    conn.close()
    responses = json.dumps([get(client, f"/api/dashboard/{ep}?limit=100" if ep == "activity" else
                                f"/api/dashboard/{ep}", admin_h) for ep in ENDPOINTS])
    for value in RAW_PII:
        assert value not in dumped, value
        assert value not in responses, value


def test_metric_write_failure_never_breaks_upload(client, admin_h, env, monkeypatch):
    import dashboard

    def broken():
        raise RuntimeError("db locked")

    monkeypatch.setattr(dashboard, "_engine", broken)
    assert client.put("/b1/z.txt", content=b"Priya Raman", headers=admin_h).status_code == 200
    assert client.get("/b1/z.txt", headers=admin_h).status_code == 200


def test_existing_data_untouched_by_schema_init():
    """ensure_schema / init_db only ADD the table; pii_objects rows and old events survive re-runs."""
    import dashboard
    import init_db

    conn = db()
    conn.execute("INSERT OR REPLACE INTO pii_objects VALUES ('keep', 'me.txt', '[]')")
    conn.execute("INSERT INTO dashboard_events (created_at, event_type, status) VALUES "
                 "('2026-01-01T00:00:00.000000Z', 'upload', 'ok')")
    conn.commit()
    before = conn.execute("SELECT COUNT(*) FROM dashboard_events").fetchone()[0]
    conn.close()
    dashboard.ensure_schema(config.SQLITE_PATH)
    init_db.create_tables()
    conn = db()
    assert conn.execute("SELECT COUNT(*) FROM pii_objects WHERE bucket_name='keep'").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM dashboard_events").fetchone()[0] == before
    conn.close()


def test_overlapping_spans_counted_as_presidio_resolves_them(client, admin_h, user1_h, env, monkeypatch):
    """Spans seen in a live run: spaCy DATE_TIME (0.85, no policy rule) covers 'Card 4111-...' and CONTAINS the
    CREDIT_CARD (1.0, which user1's policy masks). Plain Presidio would drop the contained card span and return
    the card number UNMASKED; conflict resolution is policy-aware (a span without a rule cannot swallow one
    with a rule), so the card IS masked together with the PERSON.
    Detection stats report the stored spans as-is; anonymization stats report what was applied."""
    import app as proxy_app

    body = "Card 4111-1111-1111-1111 owned by Jane Doe"
    ents = [{"type": "CREDIT_CARD", "start": 5, "end": 24, "score": 1.0},
            {"type": "DATE_TIME", "start": 0, "end": 24, "score": 0.85},
            {"type": "PERSON", "start": 34, "end": 42, "score": 0.85}]

    class Trigger:
        def on_put(self, bucket, key):
            proxy_app.get_upload_trigger  # noqa: B018 - same contract as LocalUploadTrigger
            from pii_analyser import SqlitePiiDB
            SqlitePiiDB().store_pii_results(bucket, key, ents)
            return ents

    monkeypatch.setattr(proxy_app, "get_upload_trigger", lambda: Trigger())
    assert client.put("/b1/overlap.txt", content=body.encode(), headers=admin_h).status_code == 200
    p = get(client, "/api/dashboard/pii-types", admin_h)["data"]
    assert p["total_entities"] == 3
    assert {t["entity_type"] for t in p["types"]} == {"CREDIT_CARD", "DATE_TIME", "PERSON"}
    pr = get(client, "/api/dashboard/detection", admin_h)["data"]["protection"]
    assert pr["uncovered_entity_types"] == [{"entity_type": "DATE_TIME", "count": 1}]

    got = client.get("/b1/overlap.txt", headers=user1_h)
    assert "4111-1111-1111-1111" not in got.text  # the card is masked, not swallowed by DATE_TIME
    assert "Jane Doe" not in got.text
    a = get(client, "/api/dashboard/anonymization", admin_h)["data"]
    assert a["entities_anonymized"] == 2
    assert {x["name"]: x["count"] for x in a["by_entity_type"]} == {"PERSON": 1, "CREDIT_CARD": 1}
    assert {x["name"]: x["count"] for x in a["by_operator"]} == {"replace": 1, "mask": 1}


# ====================================================================================================
# Regression: LLM Playground activity must reach the dashboard metrics (from persisted events only),
# without being mixed into stored-object counts, without duplicates, and without raw PII.
# ====================================================================================================
P_PII = "Email Priya Raman at priya.raman@acme.in from 10.24.8.17"  # PERSON, EMAIL_ADDRESS, IP_ADDRESS
P_NONE = "What is the capital of France?"


def prompt(client, headers, content, *more):
    msgs = [{"role": "user", "content": c} for c in (content, *more)]
    return client.post("/api/llm/chat", json={"provider": "ollama", "model": "llama3.2", "messages": msgs},
                       headers=headers)


def llm_events():
    conn = db()
    rows = conn.execute("SELECT event_type, status, entity_count, details, request_id FROM dashboard_events "
                        "WHERE source='llm_prompt' ORDER BY id").fetchall()
    conn.close()
    return rows


def test_llm_prompts_reach_the_dashboard_from_persisted_events(client, user1_h, env):
    assert prompt(client, user1_h, P_PII).status_code == 200
    assert prompt(client, user1_h, P_NONE).status_code == 200

    lp = get(client, "/api/dashboard/llm-prompts?tz_offset_minutes=0", user1_h)["data"]
    assert (lp["prompts_total"], lp["prompts_sent"], lp["prompts_blocked"]) == (2, 2, 0)
    assert (lp["prompts_with_pii"], lp["prompts_protected"], lp["prompts_unchanged"]) == (1, 1, 1)
    # detection (3 entities found) is reported apart from anonymization (user1 has rules for 2 of them)
    assert (lp["entities_detected"], lp["entities_protected"]) == (3, 2)
    assert {x["name"]: x["count"] for x in lp["by_entity_type"]} == {"PERSON": 1, "EMAIL_ADDRESS": 1, "IP_ADDRESS": 1}
    assert {x["name"]: x["count"] for x in lp["by_operator"]} == {"replace": 2}
    assert lp["tracking_since"] is not None
    assert lp["timeline"][-1] == {"date": datetime.now(timezone.utc).date().isoformat(),
                                  "prompts": 2, "with_pii": 1, "blocked": 0}

    # the numbers come from SQLite, not from process memory: the persisted rows say the same thing
    rows = llm_events()
    assert len(rows) == 2 and sum(r[2] for r in rows) == lp["entities_protected"]
    # ... and the existing Anonymization section still agrees
    a = get(client, "/api/dashboard/anonymization", user1_h)["data"]
    assert a["by_source"] == [{"name": "llm_prompt", "count": 2}] and a["entities_anonymized"] == 2


def test_llm_prompt_counts_stay_separate_from_stored_object_counts(client, admin_h, user1_h, env):
    def object_side():
        return (get(client, "/api/dashboard/summary", admin_h)["data"],
                get(client, "/api/dashboard/pii-types", admin_h)["data"],
                get(client, "/api/dashboard/detection", admin_h)["data"])

    s0, p0, d0 = object_side()
    prompt(client, user1_h, P_PII)
    prompt(client, user1_h, P_PII)
    assert object_side() == (s0, p0, d0)  # prompts add nothing to objects, entities, detection runs or protection

    seed(client, admin_h, env)
    s1, p1, d1 = object_side()
    assert (s1["total_objects"], p1["total_entities"], d1["detection_runs_total"]) == (7, 8, 6)  # uploads only
    lp = get(client, "/api/dashboard/llm-prompts", admin_h)["data"]
    assert (lp["prompts_total"], lp["entities_detected"]) == (2, 6)  # uploads add nothing to prompt counts


def test_each_llm_request_records_exactly_one_event(client, user1_h, admin_h, env):
    prompt(client, user1_h, P_PII)
    prompt(client, admin_h, P_PII)
    prompt(client, user1_h, P_NONE, "ok", P_PII)  # a longer history is still ONE prompt
    rows = llm_events()
    assert len(rows) == 3 and all(r[0] == "anonymization" for r in rows)
    ids = [r[4] for r in rows]
    assert all(ids) and len(set(ids)) == 3
    conn = db()
    assert conn.execute("SELECT COUNT(*) FROM dashboard_events").fetchone()[0] == 3  # nothing else was written
    conn.close()
    assert get(client, "/api/dashboard/llm-prompts", admin_h)["data"]["prompts_total"] == 3
    assert get(client, "/api/dashboard/activity", admin_h)["data"]["total_events"] == 3


def test_record_event_is_idempotent_per_request_id(client, env):
    import asyncio
    import dashboard

    async def go():
        for _ in range(3):
            await dashboard.record_event("anonymization", source="llm_prompt", actor="u", entity_count=1,
                                         request_id="req-1")
        await dashboard.record_event("detection", request_id="req-1")  # other event type, same request: allowed
        await dashboard.record_event("upload", actor="u", bucket="b", key="k")  # no request id: unchanged behaviour
        await dashboard.record_event("upload", actor="u", bucket="b", key="k")

    asyncio.run(go())
    conn = db()
    got = conn.execute("SELECT event_type, COUNT(*) FROM dashboard_events GROUP BY event_type ORDER BY 1").fetchall()
    conn.close()
    assert got == [("anonymization", 1), ("detection", 1), ("upload", 2)]


def test_admin_prompt_is_not_counted_as_anonymized(client, admin_h, env):
    assert prompt(client, admin_h, P_PII).status_code == 200
    assert env.ollama[-1]["messages"][-1]["content"] == P_PII

    a = get(client, "/api/dashboard/anonymization", admin_h)["data"]
    assert (a["anonymized_ok"], a["failed"], a["entities_anonymized"]) == (0, 0, 0)
    assert a["served_original"] == 1 and a["by_operator"] == [] and a["by_entity_type"] == []

    lp = get(client, "/api/dashboard/llm-prompts", admin_h)["data"]
    assert (lp["prompts_total"], lp["prompts_with_pii"], lp["prompts_protected"], lp["prompts_unchanged"]) == (1, 1, 0, 1)
    assert (lp["entities_detected"], lp["entities_protected"]) == (3, 0)  # PII was detected, no rule was applied

    item = get(client, "/api/dashboard/activity", admin_h)["data"]["items"][0]
    assert item["status"] == "original" and item["entity_count"] == 0
    assert item["summary"] == ("No masking rules apply; prompt sent unchanged "
                               "(3 entities detected: EMAIL_ADDRESS, IP_ADDRESS, PERSON)")


def test_blocked_prompt_is_counted_as_blocked_and_never_sent(client, user1_h, env):
    env.analyzer_down = True
    r = prompt(client, user1_h, P_PII)
    assert r.status_code == 502 and "NOT sent" in r.json()["detail"]
    assert env.ollama == []

    lp = get(client, "/api/dashboard/llm-prompts", user1_h)["data"]
    assert (lp["prompts_total"], lp["prompts_sent"], lp["prompts_blocked"], lp["prompts_with_pii"]) == (1, 0, 1, 0)
    assert lp["timeline"][-1]["blocked"] == 1
    a = get(client, "/api/dashboard/anonymization", user1_h)["data"]
    assert (a["failed"], a["anonymized_ok"]) == (1, 0)
    item = get(client, "/api/dashboard/activity", user1_h)["data"]["items"][0]
    assert item["status"] == "failed" and item["summary"] == "PII detection failed; prompt was not sent"


def test_prompt_that_never_reached_the_model_is_not_counted_as_sent(client, user1_h, env, monkeypatch):
    import urllib.error
    import app as proxy_app

    def down(payload):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(proxy_app, "_call_ollama", down)
    assert prompt(client, user1_h, P_PII).status_code == 503
    assert get(client, "/api/dashboard/llm-prompts", user1_h)["data"]["prompts_total"] == 0
    assert llm_events() == []


def test_events_written_before_detection_was_tracked_are_still_counted(client, admin_h, env):
    conn = db()  # shape written by the previous version: applied counts only, no "detected", no request_id
    conn.execute("INSERT INTO dashboard_events (created_at, event_type, source, actor, status, entity_count, details) "
                 "VALUES (?, 'anonymization', 'llm_prompt', 'user1', 'ok', 2, ?)",
                 (datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                  json.dumps({"by_entity_type": {"PERSON": 1, "EMAIL_ADDRESS": 1}, "by_operator": {"replace": 2}})))
    conn.commit()
    conn.close()
    lp = get(client, "/api/dashboard/llm-prompts", admin_h)["data"]
    assert (lp["prompts_total"], lp["prompts_with_pii"], lp["prompts_protected"]) == (1, 1, 1)
    assert (lp["entities_detected"], lp["entities_protected"]) == (2, 2)


def test_request_id_column_is_added_to_an_existing_database_without_losing_rows(tmp_path):
    import dashboard

    path = str(tmp_path / "old.db")
    conn = sqlite3.connect(path)  # the table exactly as the previous version created it
    conn.execute("""CREATE TABLE dashboard_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, event_type TEXT NOT NULL,
        source TEXT NOT NULL DEFAULT 'object', actor TEXT, bucket_name TEXT, object_key TEXT,
        status TEXT NOT NULL, entity_count INTEGER NOT NULL DEFAULT 0, details TEXT)""")
    conn.execute("INSERT INTO dashboard_events (created_at, event_type, status, entity_count) "
                 "VALUES ('2026-01-01T00:00:00.000000Z', 'upload', 'ok', 0)")
    conn.commit()
    conn.close()

    dashboard.ensure_schema(path)
    dashboard.ensure_schema(path)  # idempotent

    conn = sqlite3.connect(path)
    assert "request_id" in {r[1] for r in conn.execute("PRAGMA table_info(dashboard_events)")}
    assert conn.execute("SELECT COUNT(*), MIN(request_id) FROM dashboard_events").fetchone() == (1, None)
    conn.execute("INSERT OR IGNORE INTO dashboard_events (created_at, event_type, status, request_id) "
                 "VALUES ('2026-01-02T00:00:00.000000Z', 'anonymization', 'ok', 'r1')")
    conn.execute("INSERT OR IGNORE INTO dashboard_events (created_at, event_type, status, request_id) "
                 "VALUES ('2026-01-02T00:00:01.000000Z', 'anonymization', 'ok', 'r1')")
    assert conn.execute("SELECT COUNT(*) FROM dashboard_events").fetchone()[0] == 2
    conn.close()


def test_no_raw_pii_in_llm_dashboard_events_or_responses(client, admin_h, user1_h, env):
    everything = "Priya Raman priya.raman@acme.in 4532 8891 0023 7714 123-45-6789 10.24.8.17 +91 98765 43210"
    assert prompt(client, admin_h, everything).status_code == 200   # passthrough: the model sees the original ...
    assert prompt(client, user1_h, everything).status_code == 200
    env.analyzer_down = True
    assert prompt(client, user1_h, everything).status_code == 502
    conn = db()
    dumped = json.dumps(conn.execute("SELECT * FROM dashboard_events").fetchall())
    conn.close()
    responses = json.dumps([get(client, f"/api/dashboard/{ep}?limit=100" if ep == "activity" else
                                f"/api/dashboard/{ep}", admin_h) for ep in ENDPOINTS])
    for value in RAW_PII:  # ... but the dashboard store and API never hold it
        assert value not in dumped, value
        assert value not in responses, value


def test_dashboard_ui_reads_the_llm_prompt_metrics():
    html = (Path(config.PROJECT_ROOT) / "ui" / "index.html").read_text(encoding="utf-8")
    assert "'llm-prompts'" in html and "/api/dashboard/" in html
    for field in ("prompts_total", "prompts_sent", "prompts_blocked", "prompts_with_pii", "prompts_protected",
                  "prompts_unchanged", "entities_detected", "entities_protected", "by_entity_type"):
        assert field in html, field
