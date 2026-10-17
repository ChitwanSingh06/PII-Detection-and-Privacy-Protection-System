"""Admin-only APIs behind the PII Detection, Analytics and Audit Logs pages.

Every route depends on `require_admin` (JWT must say admin; anything else is 403 and the denied attempt is
written to the audit log). Nothing here is mocked or estimated, and nothing returns detected values:

  * pii_objects (spans: type / offsets / score)     -> detection statistics
  * dashboard_events (append-only activity record)   -> timelines, anonymization stats, the audit log itself
  * policies / users                                 -> protection coverage
  * data/storage                                     -> which objects currently exist

Routes (all GET, all admin only, envelope {"generated_at", "data"}):
  /api/admin/pii-detection      categories + live counts, per-type confidence, latest detection results
  /api/admin/analytics          distribution, detection-vs-protection timeline, risk, coverage per bucket, operators
  /api/admin/audit-logs         filtered + paged audit events
  /api/admin/audit-logs/export  the same filter as CSV (the export itself is audited)
"""
import csv
import io
import json
from collections import Counter, defaultdict
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from auth import AuthUser, require_admin
from dashboard import (
    EVENT_TYPES,
    TzOffset,
    Window,
    _assigned_policies,
    _current_objects,
    _days,
    _fetch,
    _iso,
    _local_day,
    _now,
    _pct,
    _summary_text,
    anonymization as dashboard_anonymization,
    record_event,
)
from pii_recognizers import SUPPORTED_CATEGORIES

router = APIRouter(prefix="/api/admin", tags=["admin"])

_CATALOG = {c["entity_type"]: c for c in SUPPORTED_CATEGORIES}

# Risk is DERIVED from what was actually detected in an object (the most sensitive type present decides).
CRITICAL_TYPES = {
    "CREDIT_CARD", "US_SSN", "IN_AADHAAR", "US_BANK_NUMBER", "US_PASSPORT", "US_ITIN", "US_DRIVER_LICENSE",
    "IBAN_CODE", "MEDICAL_LICENSE", "CRYPTO", "UK_NHS",
}
HIGH_TYPES = {"EMAIL_ADDRESS", "PHONE_NUMBER", "IN_ADDRESS", "US_ADDRESS"}
MEDIUM_TYPES = {"PERSON", "IN_PIN_CODE", "US_ZIP_CODE", "LOCATION", "IP_ADDRESS"}
RISK_LEVELS = ("Critical", "High", "Medium", "Low")


def risk_of(types: set) -> Optional[str]:
    if not types:
        return None
    if types & CRITICAL_TYPES:
        return "Critical"
    if types & HIGH_TYPES:
        return "High"
    if types & MEDIUM_TYPES:
        return "Medium"
    return "Low"


def _wrap(data: dict) -> dict:
    return {"generated_at": _iso(_now()), "data": data}


def _details(raw) -> dict:
    try:
        d = json.loads(raw) if isinstance(raw, str) else (raw or {})
    except (TypeError, ValueError):
        return {}
    return d if isinstance(d, dict) else {}


# ---------------------------------------------------------------------------------------------------
# PII Detection
# ---------------------------------------------------------------------------------------------------
@router.get("/pii-detection")
async def pii_detection(_: AuthUser = Depends(require_admin), limit: int = Query(20, ge=1, le=100)):
    stored, scanned, orphaned = await _current_objects()

    scores: dict[str, list] = defaultdict(list)
    objects: Counter = Counter()
    for entities in scanned.values():
        for e in entities:
            scores[e["type"]].append(float(e.get("score", 0.0)))
        for t in {e["type"] for e in entities}:
            objects[t] += 1

    def stat(t: str) -> dict:
        s = scores.get(t, [])
        return {
            "entity_type": t, "count": len(s), "objects": objects.get(t, 0),
            "avg_score": round(sum(s) / len(s), 4) if s else None,
            "min_score": round(min(s), 4) if s else None, "max_score": round(max(s), 4) if s else None,
        }

    categories = [{**c, **stat(c["entity_type"])} for c in SUPPORTED_CATEGORIES]
    other = [stat(t) for t in sorted(scores, key=lambda x: (-len(scores[x]), x)) if t not in _CATALOG]

    # Latest detection runs (from the persisted events), enriched with the stored spans' offsets/scores.
    rows = await _fetch(
        "SELECT id, created_at, bucket_name, object_key, status, entity_count, details FROM dashboard_events "
        "WHERE event_type='detection' AND source='object' ORDER BY id DESC LIMIT :n", {"n": limit},
    )
    latest = []
    for r in rows:
        spans = scanned.get((r.bucket_name, r.object_key))
        by_type = _details(r.details).get("by_entity_type", {})
        latest.append({
            "id": r.id, "timestamp": r.created_at, "bucket": r.bucket_name, "object_key": r.object_key,
            "status": r.status, "entity_count": r.entity_count, "by_entity_type": by_type,
            "object_exists": (r.bucket_name, r.object_key) in stored,
            # offsets + confidence only; the matched text is never returned
            "entities": [
                {"entity_type": e["type"], "start": e["start"], "end": e["end"], "score": round(float(e.get("score", 0)), 4),
                 "detector": _CATALOG.get(e["type"], {}).get("detector", "Recognizer")}
                for e in (spans or [])[:50]
            ] if spans is not None else [],
        })

    totals = await _fetch(
        "SELECT COUNT(*) AS n, SUM(CASE WHEN status != 'ok' THEN 1 ELSE 0 END) AS f FROM dashboard_events "
        "WHERE event_type='detection'")
    return _wrap({
        "objects_scanned": len(scanned),
        "objects_with_pii": sum(1 for e in scanned.values() if e),
        "total_entities": sum(len(e) for e in scanned.values()),
        "detection_runs_total": (totals[0].n or 0) if totals else 0,
        "detection_failures_total": (totals[0].f or 0) if totals else 0,
        "score_threshold_note": "Only detections at or above the configured confidence threshold are stored.",
        "categories": categories,
        "other_types": other,
        "latest_results": latest,
    })


# ---------------------------------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------------------------------
@router.get("/analytics")
async def analytics(
    _: AuthUser = Depends(require_admin), days: int = Window, tz_offset_minutes: int = TzOffset
):
    stored, scanned, orphaned = await _current_objects()

    # distribution (stored objects) + region split
    dist: Counter = Counter()
    region: Counter = Counter()
    for entities in scanned.values():
        for e in entities:
            dist[e["type"]] += 1
            region[_CATALOG.get(e["type"], {}).get("region", "Other")] += 1

    # risk per object, protection coverage per bucket
    covered, no_policy = await _assigned_policies()
    any_cov = set().union(*covered.values()) if covered else set()
    all_cov = set.intersection(*covered.values()) if covered else set()
    risk: Counter = Counter()
    per_bucket: dict[str, Counter] = defaultdict(Counter)
    for (bucket, _key), entities in scanned.items():
        types = {e["type"] for e in entities}
        lvl = risk_of(types)
        if lvl is None:
            continue
        risk[lvl] += 1
        b = per_bucket[bucket]
        b["with_pii"] += 1
        if types <= all_cov:
            b["protected"] += 1
        elif types & any_cov:
            b["partial"] += 1
        else:
            b["unprotected"] += 1
    coverage = [
        {"bucket": k, "objects_with_pii": v["with_pii"], "protected": v["protected"], "partial": v["partial"],
         "unprotected": v["unprotected"], "protected_pct": _pct(v["protected"], v["with_pii"])}
        for k, v in sorted(per_bucket.items())
    ]

    # detection vs protection timeline from the event record
    labels, cutoff = _days(days, tz_offset_minutes)
    tl = {d: {"detected": 0, "protected": 0, "failed": 0} for d in labels}
    for r in await _fetch(
        "SELECT created_at, event_type, status, entity_count FROM dashboard_events "
        "WHERE event_type IN ('detection','anonymization') AND created_at >= :c", {"c": cutoff},
    ):
        d = tl.get(_local_day(r.created_at, tz_offset_minutes))
        if d is None:
            continue
        if r.status == "failed":
            d["failed"] += 1
        elif r.status == "ok":
            d["detected" if r.event_type == "detection" else "protected"] += r.entity_count

    anon = (await dashboard_anonymization(None, days=days, tz_offset_minutes=tz_offset_minutes))["data"]
    return _wrap({
        "window_days": days,
        "tz_offset_minutes": tz_offset_minutes,
        "objects": {"stored": len(stored), "scanned": len(scanned), "with_pii": sum(risk.values())},
        "pii_distribution": [{"entity_type": t, "count": n} for t, n in dist.most_common()],
        "region_distribution": [{"region": t, "count": n} for t, n in region.most_common()],
        "risk_basis": "Most sensitive PII type present in each object (critical: ID/financial; high: contact/address; "
                      "medium: names/places/postal codes/IPs; low: other).",
        "risk_distribution": [{"level": lv, "objects": risk.get(lv, 0)} for lv in RISK_LEVELS],
        "protection_basis": "Protected = every detected type has a rule in every policy assigned to a user.",
        "assigned_policies": sorted(covered),
        "users_without_policy": no_policy,
        "coverage_by_bucket": coverage,
        "detection_vs_protection": [{"date": d, **v} for d, v in tl.items()],
        "anonymization": {
            "requests_total": anon.requests_total, "anonymized_ok": anon.anonymized_ok, "failed": anon.failed,
            "served_original": anon.served_original, "entities_anonymized": anon.entities_anonymized,
            "by_operator": [{"name": o.name, "count": o.count} for o in anon.by_operator],
            "by_entity_type": [{"name": o.name, "count": o.count} for o in anon.by_entity_type],
        },
    })


# ---------------------------------------------------------------------------------------------------
# Audit logs
# ---------------------------------------------------------------------------------------------------
def _filter_sql(event_type, actor, status, q):
    where, params = [], {}
    if event_type:
        where.append("event_type = :et")
        params["et"] = event_type
    if actor:
        where.append("actor = :ac")
        params["ac"] = actor
    if status:
        where.append("status = :st")
        params["st"] = status
    if q:  # matches bucket / object key / actor only (never event payloads)
        where.append("(object_key LIKE :q OR bucket_name LIKE :q OR actor LIKE :q)")
        params["q"] = f"%{q}%"
    return (" WHERE " + " AND ".join(where)) if where else "", params


def _item(r) -> dict:
    det = _details(r.details)
    return {
        "id": r.id, "timestamp": r.created_at, "event_type": r.event_type, "source": r.source, "actor": r.actor,
        "bucket": r.bucket_name, "object_key": r.object_key, "status": r.status, "entity_count": r.entity_count,
        "summary": _summary_text(r.event_type, r.status, r.entity_count, {**det, "source": r.source}),
        "details": det,
    }


_COLS = "id, created_at, event_type, source, actor, bucket_name, object_key, status, entity_count, details"


@router.get("/audit-logs")
async def audit_logs(
    _: AuthUser = Depends(require_admin),
    limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
    event_type: Optional[str] = Query(None, max_length=32), actor: Optional[str] = Query(None, max_length=64),
    status: Optional[str] = Query(None, max_length=16), q: Optional[str] = Query(None, max_length=100),
):
    where, params = _filter_sql(event_type, actor, status, q)
    rows = await _fetch(
        f"SELECT {_COLS} FROM dashboard_events{where} ORDER BY id DESC LIMIT :n OFFSET :o",
        {**params, "n": limit, "o": offset})
    total = await _fetch(f"SELECT COUNT(*) AS n FROM dashboard_events{where}", params)
    facets = await _fetch("SELECT event_type, COUNT(*) AS n FROM dashboard_events GROUP BY event_type")
    counts = {f.event_type: f.n for f in facets}
    return _wrap({
        "total": total[0].n if total else 0, "limit": limit, "offset": offset,
        "event_types": [{"event_type": t, "count": counts.get(t, 0)} for t in EVENT_TYPES if counts.get(t)] +
                       [{"event_type": t, "count": n} for t, n in sorted(counts.items()) if t not in EVENT_TYPES],
        "items": [_item(r) for r in rows],
    })


def _csv_cell(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s  # spreadsheet formula injection guard


@router.get("/audit-logs/export")
async def audit_logs_export(
    admin: AuthUser = Depends(require_admin),
    event_type: Optional[str] = Query(None, max_length=32), actor: Optional[str] = Query(None, max_length=64),
    status: Optional[str] = Query(None, max_length=16), q: Optional[str] = Query(None, max_length=100),
):
    where, params = _filter_sql(event_type, actor, status, q)
    rows = await _fetch(f"SELECT {_COLS} FROM dashboard_events{where} ORDER BY id DESC LIMIT 10000", params)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "timestamp_utc", "event_type", "status", "actor", "source", "bucket", "object_key",
                "entity_count", "summary"])
    for r in rows:
        i = _item(r)
        w.writerow([_csv_cell(i[k]) for k in ("id", "timestamp", "event_type", "status", "actor", "source", "bucket",
                                                "object_key", "entity_count", "summary")])
    await record_event("audit_export", actor=admin.username, details={"rows": len(rows)})
    return Response(content=buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="audit-logs.csv"'})
