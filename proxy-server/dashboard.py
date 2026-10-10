"""Live Dashboard API (read-only) + the minimal event persistence it needs.

Sources of truth (nothing here is mocked or estimated):
  * data/storage/<bucket>/<key>      -> which objects exist (same folder the proxy serves)
  * pii_objects                      -> detected spans per object (type, offsets, score; no text)
  * policies / users                 -> which entity types the assigned policies cover
  * dashboard_events (new, additive) -> timestamps for uploads, detection runs, anonymized GETs,
                                        LLM prompt protection, deletes. Counts and entity TYPES only;
                                        the detected values themselves are never written here.

Routes (any authenticated user; every response is {"generated_at": ..., "data": {...}}):
  GET /api/dashboard/summary        object counts
  GET /api/dashboard/pii-types      PII statistics by entity type
  GET /api/dashboard/detection      detection timeline + policy protection coverage
  GET /api/dashboard/anonymization  anonymization statistics
  GET /api/dashboard/llm-prompts    LLM Playground prompt statistics (kept apart from stored-object counts)
  GET /api/dashboard/activity       recent activity
"""
import asyncio
import json
import logging
import os
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, create_model
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from auth import AuthUser, get_current_user
from config import SQLITE_PATH, STORAGE_ROOT
from sqlite_db import SqliteModel

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

LLM_SCRATCH_BUCKET = "__llm_playground__"  # temporary span rows written by the LLM Playground; never counted
EVENT_TYPES = ("upload", "detection", "anonymization", "download", "delete")

# --------------------------------------------------------------------------------------------------
# Persistence (additive, backward compatible: CREATE ... IF NOT EXISTS, nothing is dropped or reset)
# --------------------------------------------------------------------------------------------------
SCHEMA_SQL = (
    """
    CREATE TABLE IF NOT EXISTS dashboard_events (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at   TEXT    NOT NULL,              -- UTC, ISO-8601 'YYYY-MM-DDTHH:MM:SS.ffffffZ'
        event_type   TEXT    NOT NULL,              -- upload | detection | anonymization | download | delete
        source       TEXT    NOT NULL DEFAULT 'object',  -- object | llm_prompt
        actor        TEXT,                          -- username from the verified JWT
        bucket_name  TEXT,
        object_key   TEXT,
        status       TEXT    NOT NULL,              -- ok | failed | original
        entity_count INTEGER NOT NULL DEFAULT 0,
        details      TEXT,                          -- JSON of counts by entity type / operator; never PII values
        request_id   TEXT                           -- server-generated per request; makes a write idempotent
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_dashboard_events_created ON dashboard_events (created_at)",
    "CREATE INDEX IF NOT EXISTS idx_dashboard_events_type ON dashboard_events (event_type, created_at)",
)
# Created AFTER the request_id column is guaranteed to exist (see ensure_schema). Partial, so the
# NULL request_id of every pre-existing / object event is unaffected.
REQUEST_ID_INDEX_SQL = (
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_dashboard_events_request "
    "ON dashboard_events (request_id, event_type) WHERE request_id IS NOT NULL"
)


def ensure_schema(sqlite_path: str = SQLITE_PATH) -> None:
    """Create the dashboard_events table if missing and add the request_id column to an older one.

    Additive only (no rows are touched or dropped), safe to call on every start.
    """
    Path(sqlite_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(sqlite_path)
    try:
        for stmt in SCHEMA_SQL:
            conn.execute(stmt)
        if "request_id" not in {row[1] for row in conn.execute("PRAGMA table_info(dashboard_events)")}:
            conn.execute("ALTER TABLE dashboard_events ADD COLUMN request_id TEXT")
        conn.execute(REQUEST_ID_INDEX_SQL)
        conn.commit()
    finally:
        conn.close()


def _engine():
    return SqliteModel.create_engine(SQLITE_PATH)  # the shared engine app.py uses


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


async def record_event(
    event_type: str,
    *,
    status: str = "ok",
    actor: Optional[str] = None,
    bucket: Optional[str] = None,
    key: Optional[str] = None,
    source: str = "object",
    entity_count: int = 0,
    details: Optional[dict] = None,
    request_id: Optional[str] = None,
) -> None:
    """Best effort: a metrics write must never break an upload, GET or LLM request.

    With a request_id the write is idempotent: the same (request_id, event_type) is stored once, so a
    retried / re-entered code path cannot double count. Events without one behave as before.
    `details` must hold counts and entity TYPES only, never detected values.
    """
    if bucket == LLM_SCRATCH_BUCKET:
        return
    try:
        async with _engine().connect() as conn:
            await conn.execute(
                text(
                    "INSERT OR IGNORE INTO dashboard_events (created_at, event_type, source, actor, bucket_name, "
                    "object_key, status, entity_count, details, request_id) "
                    "VALUES (:t, :e, :src, :a, :b, :k, :s, :n, :d, :r)"
                ),
                {
                    "t": _iso(_now()), "e": event_type, "src": source, "a": actor, "b": bucket, "k": key,
                    "s": status, "n": int(entity_count), "d": json.dumps(details or {}, sort_keys=True),
                    "r": request_id,
                },
            )
            await conn.commit()
    except Exception as exc:  # noqa: BLE001
        log.warning("dashboard: could not record %s event: %s", event_type, exc)


_keep_engine = None


def _applied_entity_types(content: str, entities: list[dict]) -> list[str]:
    """Entity types Presidio's AnonymizerEngine actually operates on for these spans.

    Presidio resolves overlaps itself (merges same-type overlaps, drops any span CONTAINED in another
    span regardless of score, merges whitespace-adjacent same-type spans), so counting raw spans would
    over-report. Running its public anonymize() with 'keep' for everything returns exactly the surviving
    items without changing any text; the real transformation stays in the anonymizer service.
    """
    global _keep_engine
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig, RecognizerResult

    if _keep_engine is None:
        _keep_engine = AnonymizerEngine()
    result = _keep_engine.anonymize(
        text=content,
        analyzer_results=[RecognizerResult(e["type"], e["start"], e["end"], e["score"]) for e in entities],
        operators={"DEFAULT": OperatorConfig("keep")},
    )
    return [item.entity_type for item in result.items]


def anonymization_breakdown(content: str, entities: list[dict], policy_rules: list[dict]) -> dict:
    """Entities a policy rule was applied to (after Presidio's conflict resolution), by type and operator."""
    rules = {r["entity_type"]: r["operator_name"] for r in policy_rules if r.get("entity_type")}
    try:
        hit = [t for t in _applied_entity_types(content, entities) if t in rules] if entities else []
    except Exception as exc:  # noqa: BLE001 - metrics must never break the request
        log.warning("dashboard: could not count anonymized entities: %s", exc)
        return {"entity_count": 0, "by_entity_type": {}, "by_operator": {}, "count_unavailable": True}
    return {
        "entity_count": len(hit),
        "by_entity_type": dict(Counter(hit)),
        "by_operator": dict(Counter(rules[t] for t in hit)),
    }


def prompt_breakdown(content: str, entities: list[dict], policy_rules: list[dict]) -> dict:
    """Counts for ONE LLM prompt, with detection kept apart from anonymization (types/counts only).

    `detected`  : every PII entity found (after Presidio's conflict resolution), whether or not a rule covers it.
    top level   : the subset a policy rule was actually applied to (same shape as anonymization_breakdown),
                  so the existing Anonymization section keeps reading the same keys.
    """
    rules = {r["entity_type"]: r["operator_name"] for r in policy_rules if r.get("entity_type")}
    try:
        surviving = _applied_entity_types(content, entities) if entities else []
        unavailable = False
    except Exception as exc:  # noqa: BLE001 - metrics must never break the request
        log.warning("dashboard: could not resolve overlapping entities for a prompt: %s", exc)
        surviving, unavailable = [e["type"] for e in entities], True  # raw span count is the best remaining figure
    hit = [t for t in surviving if t in rules]
    out = {
        "entity_count": len(hit),
        "by_entity_type": dict(Counter(hit)),
        "by_operator": dict(Counter(rules[t] for t in hit)),
        "detected": {"entity_count": len(surviving), "by_entity_type": dict(Counter(surviving))},
    }
    if unavailable:
        out["count_unavailable"] = True
    return out


async def load_object_entities(bucket: str, key: str) -> Optional[list[dict]]:
    rows = await _fetch(
        "SELECT pii_entities FROM pii_objects WHERE bucket_name=:b AND object_key=:k", {"b": bucket, "k": key}
    )
    if not rows or rows[0].pii_entities is None:
        return None
    return _parse_entities(rows[0].pii_entities)


# --------------------------------------------------------------------------------------------------
# Response schemas
# --------------------------------------------------------------------------------------------------
class BucketCounts(BaseModel):
    bucket: str
    objects: int
    scanned: int
    with_pii: int
    size_bytes: int


class SummaryData(BaseModel):
    total_objects: int
    total_buckets: int
    total_size_bytes: int
    scanned_objects: int
    unscanned_objects: int
    objects_with_pii: int
    objects_without_pii: int
    scan_coverage_pct: Optional[float]  # null when there are no objects
    orphaned_metadata_rows: int  # pii_objects rows whose file no longer exists (excluded from all stats)
    buckets: list[BucketCounts]


class PiiTypeStat(BaseModel):
    entity_type: str
    count: int
    objects: int
    avg_score: float
    min_score: float
    max_score: float


class PiiTypesData(BaseModel):
    total_entities: int
    objects_with_pii: int
    types: list[PiiTypeStat]


class DetectionDay(BaseModel):
    date: str
    detection_runs: int
    entities_detected: int
    failed_runs: int


class UncoveredType(BaseModel):
    entity_type: str
    count: int


class ProtectionData(BaseModel):
    basis: str
    assigned_policies: list[str]
    users_without_policy: int
    protected_objects: int
    partially_protected_objects: int
    unprotected_objects: int
    protected_pct: Optional[float]
    partially_protected_pct: Optional[float]
    unprotected_pct: Optional[float]
    uncovered_entity_types: list[UncoveredType]


class DetectionData(BaseModel):
    window_days: int
    tz_offset_minutes: int
    objects_scanned: int
    objects_with_pii: int
    total_entities: int
    detection_runs_total: int
    detection_failures_total: int
    tracking_since: Optional[str]
    timeline: list[DetectionDay]
    protection: ProtectionData


class NamedCount(BaseModel):
    name: str
    count: int


class AnonDay(BaseModel):
    date: str
    anonymized: int
    failed: int


class AnonymizationData(BaseModel):
    window_days: int
    tz_offset_minutes: int
    requests_total: int
    anonymized_ok: int
    failed: int
    served_original: int
    entities_anonymized: int
    by_operator: list[NamedCount]
    by_entity_type: list[NamedCount]
    by_source: list[NamedCount]
    tracking_since: Optional[str]
    timeline: list[AnonDay]


class LlmDay(BaseModel):
    date: str
    prompts: int
    with_pii: int
    blocked: int


class LlmPromptsData(BaseModel):
    """LLM Playground prompts. A different unit from stored objects: nothing here is added to object counts."""
    window_days: int
    tz_offset_minutes: int
    prompts_total: int        # every prompt request recorded (sent + blocked)
    prompts_sent: int         # reached the model
    prompts_blocked: int      # fail-closed: detection / anonymizer error, nothing reached the model
    prompts_with_pii: int     # sent prompts in which PII was detected
    prompts_protected: int    # sent prompts in which at least one policy rule changed the text
    prompts_unchanged: int    # sent prompts forwarded exactly as written (no rule applied)
    entities_detected: int
    entities_protected: int
    by_entity_type: list[NamedCount]   # detected, per PII type
    by_operator: list[NamedCount]      # applied, per operator
    tracking_since: Optional[str]
    timeline: list[LlmDay]


class ActivityItem(BaseModel):
    id: int
    timestamp: str
    event_type: str
    source: str
    actor: Optional[str]
    bucket: Optional[str]
    object_key: Optional[str]
    status: str
    entity_count: int
    summary: str


class ActivityData(BaseModel):
    limit: int
    total_events: int
    items: list[ActivityItem]


def _envelope(model):
    return create_model(f"{model.__name__[:-4]}Response", generated_at=(str, ...), data=(model, ...))


SummaryResponse = _envelope(SummaryData)
PiiTypesResponse = _envelope(PiiTypesData)
DetectionResponse = _envelope(DetectionData)
AnonymizationResponse = _envelope(AnonymizationData)
LlmPromptsResponse = _envelope(LlmPromptsData)
ActivityResponse = _envelope(ActivityData)


def _wrap(data: BaseModel) -> dict:
    return {"generated_at": _iso(_now()), "data": data}


# --------------------------------------------------------------------------------------------------
# Data access helpers
# --------------------------------------------------------------------------------------------------
async def _fetch(sql: str, params: Optional[dict] = None) -> list:
    """Run a read query; a missing table (fresh / never-initialised DB) reads as no rows."""
    try:
        async with _engine().connect() as conn:
            return (await conn.execute(text(sql), params or {})).fetchall()
    except OperationalError as exc:
        if "no such table" in str(exc):
            return []
        raise


def _parse_entities(raw) -> list[dict]:
    try:
        data = json.loads(raw) if isinstance(raw, str) else (raw or [])
    except (TypeError, ValueError):
        return []
    return [e for e in data if isinstance(e, dict) and "type" in e]


def _storage_root() -> Path:
    return Path(os.environ.get("STORAGE_ROOT", STORAGE_ROOT))


def _scan_storage() -> dict[tuple[str, str], int]:
    """{(bucket, key): size_bytes} for every stored object (same layout the proxy writes)."""
    root = _storage_root()
    out: dict[tuple[str, str], int] = {}
    if not root.is_dir():
        return out
    for bucket_dir in root.iterdir():
        if not bucket_dir.is_dir() or bucket_dir.name == LLM_SCRATCH_BUCKET:
            continue
        for f in bucket_dir.rglob("*"):
            if f.is_file():
                out[(bucket_dir.name, f.relative_to(bucket_dir).as_posix())] = f.stat().st_size
    return out


async def _current_objects() -> tuple[dict, dict, int]:
    """(stored objects, {(bucket,key): stored spans} for stored+scanned objects, orphaned row count).

    Spans are counted exactly as the analyzer stored them (overlapping spans included).
    """
    stored = await asyncio.to_thread(_scan_storage)
    rows = await _fetch("SELECT bucket_name, object_key, pii_entities FROM pii_objects")
    scanned, orphaned = {}, 0
    for r in rows:
        k = (r.bucket_name, r.object_key)
        if r.bucket_name == LLM_SCRATCH_BUCKET:
            continue
        if k in stored:
            scanned[k] = _parse_entities(r.pii_entities)
        else:
            orphaned += 1
    return stored, scanned, orphaned


def _pct(n: int, d: int) -> Optional[float]:
    return round(100.0 * n / d, 1) if d else None


def _days(window: int, tz_offset: int) -> tuple[list[str], str]:
    """Local-date labels for the window (oldest first) and the UTC ISO cutoff for the query."""
    local_now = _now() + timedelta(minutes=tz_offset)
    days = [(local_now - timedelta(days=i)).date().isoformat() for i in range(window - 1, -1, -1)]
    start_local = datetime.fromisoformat(days[0]).replace(tzinfo=timezone.utc)
    return days, _iso(start_local - timedelta(minutes=tz_offset))


def _local_day(created_at: str, tz_offset: int) -> str:
    dt = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    return (dt + timedelta(minutes=tz_offset)).date().isoformat()


async def _first_event(event_types: tuple[str, ...]) -> Optional[str]:
    marks = ",".join(f":e{i}" for i in range(len(event_types)))
    rows = await _fetch(
        f"SELECT MIN(created_at) AS first_at FROM dashboard_events WHERE event_type IN ({marks})",
        {f"e{i}": e for i, e in enumerate(event_types)},
    )
    return rows[0].first_at if rows and rows[0].first_at else None


async def _assigned_policies() -> tuple[dict[str, set], int]:
    """({policy_name: covered entity types} for policies assigned to >=1 user, users with no policy)."""
    users = await _fetch("SELECT user_name, policy_name FROM users")
    assigned = {u.policy_name for u in users if u.policy_name}
    no_policy = len({u.user_name for u in users} - {u.user_name for u in users if u.policy_name})
    rules = await _fetch("SELECT policy_name, policy FROM policies")
    covered: dict[str, set] = {name: set() for name in assigned}
    for r in rules:
        if r.policy_name in covered:
            try:
                rule = json.loads(r.policy) if isinstance(r.policy, str) else r.policy
                covered[r.policy_name].add(rule["entity_type"])
            except (TypeError, ValueError, KeyError):
                continue
    return covered, no_policy


TzOffset = Query(0, ge=-720, le=840, description="Client UTC offset in minutes (IST = 330) for day buckets")
Window = Query(14, ge=1, le=90, description="Number of days in the timeline")


# --------------------------------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------------------------------
@router.get("/summary", response_model=SummaryResponse)
async def summary(_: AuthUser = Depends(get_current_user)):
    stored, scanned, orphaned = await _current_objects()
    per_bucket: dict[str, dict] = defaultdict(lambda: {"objects": 0, "scanned": 0, "with_pii": 0, "size_bytes": 0})
    for (bucket, key), size in stored.items():
        b = per_bucket[bucket]
        b["objects"] += 1
        b["size_bytes"] += size
        if (bucket, key) in scanned:
            b["scanned"] += 1
            if scanned[(bucket, key)]:
                b["with_pii"] += 1
    with_pii = sum(1 for e in scanned.values() if e)
    return _wrap(SummaryData(
        total_objects=len(stored),
        total_buckets=len(per_bucket),
        total_size_bytes=sum(stored.values()),
        scanned_objects=len(scanned),
        unscanned_objects=len(stored) - len(scanned),
        objects_with_pii=with_pii,
        objects_without_pii=len(scanned) - with_pii,
        scan_coverage_pct=_pct(len(scanned), len(stored)),
        orphaned_metadata_rows=orphaned,
        buckets=[BucketCounts(bucket=k, **v) for k, v in sorted(per_bucket.items())],
    ))


@router.get("/pii-types", response_model=PiiTypesResponse)
async def pii_types(_: AuthUser = Depends(get_current_user)):
    _, scanned, _ = await _current_objects()
    scores: dict[str, list[float]] = defaultdict(list)
    objects: dict[str, int] = Counter()
    for entities in scanned.values():
        for e in entities:
            scores[e["type"]].append(float(e.get("score", 0.0)))
        for t in {e["type"] for e in entities}:
            objects[t] += 1
    types = [
        PiiTypeStat(
            entity_type=t, count=len(s), objects=objects[t],
            avg_score=round(sum(s) / len(s), 4), min_score=round(min(s), 4), max_score=round(max(s), 4),
        )
        for t, s in scores.items()
    ]
    types.sort(key=lambda x: (-x.count, x.entity_type))
    return _wrap(PiiTypesData(
        total_entities=sum(t.count for t in types),
        objects_with_pii=sum(1 for e in scanned.values() if e),
        types=types,
    ))


@router.get("/detection", response_model=DetectionResponse)
async def detection(
    _: AuthUser = Depends(get_current_user), days: int = Window, tz_offset_minutes: int = TzOffset
):
    _, scanned, _ = await _current_objects()
    labels, cutoff = _days(days, tz_offset_minutes)
    tl = {d: {"detection_runs": 0, "entities_detected": 0, "failed_runs": 0} for d in labels}
    for r in await _fetch(
        "SELECT created_at, status, entity_count FROM dashboard_events "
        "WHERE event_type='detection' AND created_at >= :c", {"c": cutoff},
    ):
        d = tl.get(_local_day(r.created_at, tz_offset_minutes))
        if d is None:
            continue
        d["detection_runs"] += 1
        if r.status == "ok":
            d["entities_detected"] += r.entity_count
        else:
            d["failed_runs"] += 1
    totals = await _fetch(
        "SELECT COUNT(*) AS n, SUM(CASE WHEN status != 'ok' THEN 1 ELSE 0 END) AS f "
        "FROM dashboard_events WHERE event_type='detection'"
    )

    # Protection: an object is protected when EVERY assigned policy has a rule for EVERY detected type,
    # unprotected when NO assigned policy covers ANY detected type, partially protected otherwise.
    covered, no_policy = await _assigned_policies()
    any_cov = set().union(*covered.values()) if covered else set()
    all_cov = set.intersection(*covered.values()) if covered else set()
    prot = part = unprot = 0
    uncovered: Counter = Counter()
    for entities in scanned.values():
        types = {e["type"] for e in entities}
        if not types:
            continue
        if types <= all_cov:
            prot += 1
        elif types & any_cov:
            part += 1
        else:
            unprot += 1
        for e in entities:
            if e["type"] not in any_cov:
                uncovered[e["type"]] += 1
    flagged = prot + part + unprot
    return _wrap(DetectionData(
        window_days=days,
        tz_offset_minutes=tz_offset_minutes,
        objects_scanned=len(scanned),
        objects_with_pii=flagged,
        total_entities=sum(len(e) for e in scanned.values()),
        detection_runs_total=(totals[0].n or 0) if totals else 0,
        detection_failures_total=(totals[0].f or 0) if totals else 0,
        tracking_since=await _first_event(("detection",)),
        timeline=[DetectionDay(date=d, **v) for d, v in tl.items()],
        protection=ProtectionData(
            basis="policies assigned to at least one user",
            assigned_policies=sorted(covered),
            users_without_policy=no_policy,
            protected_objects=prot,
            partially_protected_objects=part,
            unprotected_objects=unprot,
            protected_pct=_pct(prot, flagged),
            partially_protected_pct=_pct(part, flagged),
            unprotected_pct=_pct(unprot, flagged),
            uncovered_entity_types=[UncoveredType(entity_type=t, count=n) for t, n in uncovered.most_common()],
        ),
    ))


@router.get("/anonymization", response_model=AnonymizationResponse)
async def anonymization(
    _: AuthUser = Depends(get_current_user), days: int = Window, tz_offset_minutes: int = TzOffset
):
    rows = await _fetch(
        "SELECT created_at, event_type, source, status, entity_count, details FROM dashboard_events "
        "WHERE event_type IN ('anonymization', 'download')"
    )
    labels, cutoff = _days(days, tz_offset_minutes)
    tl = {d: {"anonymized": 0, "failed": 0} for d in labels}
    ok = failed = original = entities = 0
    by_op: Counter = Counter()
    by_type: Counter = Counter()
    by_source: Counter = Counter()
    for r in rows:
        if r.event_type == "download" or r.status == "original":
            original += 1  # no policy rule applies to this caller: the original was served / sent
            continue
        by_source[r.source] += 1
        if r.status == "ok":
            ok += 1
            entities += r.entity_count
            try:
                det = json.loads(r.details or "{}")
            except ValueError:
                det = {}
            by_op.update(det.get("by_operator", {}))
            by_type.update(det.get("by_entity_type", {}))
        else:
            failed += 1
        if r.created_at >= cutoff:
            d = tl.get(_local_day(r.created_at, tz_offset_minutes))
            if d is not None:
                d["anonymized" if r.status == "ok" else "failed"] += 1
    nc = lambda c: [NamedCount(name=k, count=v) for k, v in c.most_common()]  # noqa: E731
    return _wrap(AnonymizationData(
        window_days=days,
        tz_offset_minutes=tz_offset_minutes,
        requests_total=ok + failed,
        anonymized_ok=ok,
        failed=failed,
        served_original=original,
        entities_anonymized=entities,
        by_operator=nc(by_op),
        by_entity_type=nc(by_type),
        by_source=nc(by_source),
        tracking_since=await _first_event(("anonymization", "download")),
        timeline=[AnonDay(date=d, **v) for d, v in tl.items()],
    ))


def _int(v) -> int:
    try:
        return max(int(v), 0)
    except (TypeError, ValueError):
        return 0


@router.get("/llm-prompts", response_model=LlmPromptsResponse)
async def llm_prompts(
    _: AuthUser = Depends(get_current_user), days: int = Window, tz_offset_minutes: int = TzOffset
):
    """Prompt-level LLM Playground metrics, read from the persisted llm_prompt events (one per request)."""
    rows = await _fetch(
        "SELECT created_at, status, entity_count, details FROM dashboard_events "
        "WHERE event_type='anonymization' AND source='llm_prompt'"
    )
    labels, cutoff = _days(days, tz_offset_minutes)
    tl = {d: {"prompts": 0, "with_pii": 0, "blocked": 0} for d in labels}
    sent = blocked = with_pii = protected = detected_total = protected_total = 0
    by_type: Counter = Counter()
    by_op: Counter = Counter()
    for r in rows:
        try:
            det = json.loads(r.details or "{}")
        except ValueError:
            det = {}
        det = det if isinstance(det, dict) else {}
        failed = r.status == "failed"
        n_applied = 0 if failed else _int(r.entity_count)
        if failed:
            blocked += 1
            n_detected, types = 0, {}
        else:
            sent += 1
            found = det.get("detected")
            if isinstance(found, dict):
                n_detected, types = _int(found.get("entity_count")), found.get("by_entity_type") or {}
            else:  # event written before detection was tracked separately: anything anonymized was detected
                n_detected, types = n_applied, det.get("by_entity_type") or {}
            if n_applied:
                protected += 1
                by_op.update({k: _int(v) for k, v in (det.get("by_operator") or {}).items()})
            if n_detected:
                with_pii += 1
            detected_total += n_detected
            protected_total += n_applied
            by_type.update({k: _int(v) for k, v in types.items()})
        if r.created_at >= cutoff:
            d = tl.get(_local_day(r.created_at, tz_offset_minutes))
            if d is not None:
                d["prompts"] += 1
                d["blocked"] += 1 if failed else 0
                d["with_pii"] += 1 if (not failed and n_detected) else 0
    nc = lambda c: [NamedCount(name=k, count=v) for k, v in c.most_common() if v]  # noqa: E731
    return _wrap(LlmPromptsData(
        window_days=days,
        tz_offset_minutes=tz_offset_minutes,
        prompts_total=sent + blocked,
        prompts_sent=sent,
        prompts_blocked=blocked,
        prompts_with_pii=with_pii,
        prompts_protected=protected,
        prompts_unchanged=sent - protected,
        entities_detected=detected_total,
        entities_protected=protected_total,
        by_entity_type=nc(by_type),
        by_operator=nc(by_op),
        tracking_since=await _first_event_of_source("llm_prompt"),
        timeline=[LlmDay(date=d, **v) for d, v in tl.items()],
    ))


async def _first_event_of_source(source: str) -> Optional[str]:
    rows = await _fetch("SELECT MIN(created_at) AS first_at FROM dashboard_events WHERE source=:s", {"s": source})
    return rows[0].first_at if rows and rows[0].first_at else None


def _summary_text(event_type: str, status: str, n: int, details: dict) -> str:
    types = ", ".join(sorted(details.get("by_entity_type", {}))) if isinstance(details, dict) else ""
    types = f" ({types})" if types else ""
    if event_type == "upload":
        return f"{details.get('size_bytes', 0):,} bytes stored"
    if event_type == "detection":
        return "Analysis failed (object could not be read as UTF-8 text)" if status != "ok" else (
            f"{n} entit{'y' if n == 1 else 'ies'} detected{types}" if n else "No PII detected")
    if event_type == "anonymization":
        if status == "original":  # LLM prompt from a caller no policy rule applies to
            found = details.get("detected") if isinstance(details.get("detected"), dict) else {}
            k = found.get("entity_count", 0)
            seen = ", ".join(sorted(found.get("by_entity_type", {})))
            return "No masking rules apply; prompt sent unchanged" + (
                f" ({k} entit{'y' if k == 1 else 'ies'} detected: {seen})" if k else "")
        if status != "ok":
            if details.get("failure") == "detection":
                return "PII detection failed; prompt was not sent"
            return "Anonymizer unavailable; " + (
                "prompt was not sent" if details.get("source") == "llm_prompt" else "original returned")
        return f"{n} entit{'y' if n == 1 else 'ies'} anonymized{types}" if n else "Policy applied; nothing to change"
    if event_type == "download":
        return "No policy assigned; original returned"
    if event_type == "delete":
        return "Object and PII metadata removed"
    return event_type


@router.get("/activity", response_model=ActivityResponse)
async def activity(
    _: AuthUser = Depends(get_current_user), limit: int = Query(10, ge=1, le=100)
):
    rows = await _fetch(
        "SELECT id, created_at, event_type, source, actor, bucket_name, object_key, status, entity_count, details "
        "FROM dashboard_events ORDER BY id DESC LIMIT :n", {"n": limit},
    )
    total = await _fetch("SELECT COUNT(*) AS n FROM dashboard_events")
    items = []
    for r in rows:
        try:
            det = json.loads(r.details or "{}")
        except ValueError:
            det = {}
        det = {**det, "source": r.source} if isinstance(det, dict) else {"source": r.source}
        items.append(ActivityItem(
            id=r.id, timestamp=r.created_at, event_type=r.event_type, source=r.source, actor=r.actor,
            bucket=r.bucket_name, object_key=r.object_key, status=r.status, entity_count=r.entity_count,
            summary=_summary_text(r.event_type, r.status, r.entity_count, det),
        ))
    return _wrap(ActivityData(limit=limit, total_events=(total[0].n if total else 0), items=items))
