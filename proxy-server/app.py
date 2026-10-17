import asyncio
import json
import os
import re
import sys
import urllib.error
import urllib.request
import uuid
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from google.protobuf.struct_pb2 import Struct
from pydantic import BaseModel, Field
from sqlalchemy import text
import grpc
import common.anonymizer.anonymizer_pb2 as an_pb2
import common.anonymizer.anonymizer_pb2_grpc as an_pb2_grpc

ROOT = Path(__file__).resolve().parents[1]
PROXY_DIR = Path(__file__).resolve().parent
CONSUMER_DIR = ROOT / "consumer_analyzer" / "consumer"
PII_ANALYSER_DIR = ROOT / "consumer_analyzer" / "pii_analyser"
COMMON_DIR = ROOT / "common"
for path in (str(ROOT), str(PROXY_DIR), str(CONSUMER_DIR), str(PII_ANALYSER_DIR), str(COMMON_DIR)):
    if path not in sys.path:
        sys.path.insert(0, path)

from config import AN_SVC_URL, SQLITE_PATH, STORAGE_ROOT  # noqa: E402
from sqlite_db import SqliteModel  # noqa: E402
from auth import AuthUser, get_current_user, require_role, router as auth_router  # noqa: E402
from policies import router as policies_router  # noqa: E402
<<<<<<< HEAD
from admin_api import router as admin_router  # noqa: E402
=======
>>>>>>> origin/main
from dashboard import (  # noqa: E402
    anonymization_breakdown,
    ensure_schema as ensure_dashboard_schema,
    load_object_entities,
    prompt_breakdown,
    record_event,
    router as dashboard_router,
)
from kafka_consumer import LocalUploadTrigger  # noqa: E402


class S3Object(BaseModel):
    bucketName: str = Field(..., description="Name of the bucket")
    objectKey: str = Field(..., description="Key of the object")
    objectData: bytes = Field(..., description="Data of the object")
    policy_map: list = Field(..., description="List of policies for anonymization")


app = FastAPI()

# Auth routes (POST /api/auth/login, GET /api/auth/me). Registered BEFORE the catch-all proxy route.
app.include_router(auth_router)
# Policy management (admin only): /api/policies*, /api/users*. Also before the catch-all.
app.include_router(policies_router)
# Live Dashboard (read-only metrics): /api/dashboard/*. Also before the catch-all.
app.include_router(dashboard_router)
<<<<<<< HEAD
# Admin-only pages' APIs (PII Detection, Analytics, Audit Logs): /api/admin/*. Also before the catch-all.
app.include_router(admin_router)
=======
>>>>>>> origin/main

# --- Frontend UI -------------------------------------------------------------
# Registered BEFORE the catch-all proxy route below so /ui/ is never treated as
# an S3 bucket path.
UI_DIR = ROOT / "ui"


@app.get("/ui", include_in_schema=False)
async def ui_redirect():
    return RedirectResponse(url="/ui/")


app.mount("/ui", StaticFiles(directory=str(UI_DIR), html=True), name="ui")
# -----------------------------------------------------------------------------
engine = SqliteModel.create_engine(SQLITE_PATH)
ensure_dashboard_schema(SQLITE_PATH)  # additive: CREATE TABLE IF NOT EXISTS dashboard_events
storage_root = Path(os.environ.get("STORAGE_ROOT", STORAGE_ROOT))
storage_root.mkdir(parents=True, exist_ok=True)
anonymizer_url = os.environ.get("AN_SVC_URL", AN_SVC_URL)
_upload_trigger: LocalUploadTrigger | None = None


def get_upload_trigger() -> LocalUploadTrigger:
    global _upload_trigger
    if _upload_trigger is None:
        _upload_trigger = LocalUploadTrigger()
    return _upload_trigger


def _safe_storage_path(bucket: str, key: str = "") -> Path:
    dest = (storage_root / bucket / key).resolve() if key else (storage_root / bucket).resolve()
    if not str(dest).startswith(str(storage_root.resolve())):
        raise ValueError("Invalid object path")
    return dest


def _split_bucket_key(path: str) -> tuple[str, str]:
    parts = path.split("/")
    return parts[0], "/".join(parts[1:])


def _policy_messages(policy_rows: list) -> list:
    messages = []
    for row in policy_rows:
        policy = row if isinstance(row, dict) else json.loads(row)
        params = Struct()
        operator_params = policy.get("operator_params") or {}
        if operator_params:
            params.update(operator_params)
        messages.append(
            an_pb2.Policy(
                entityType=policy["entity_type"],
                operatorName=policy["operator_name"],
                operatorParams=params,
            )
        )
    return messages


async def read_local_object(path: str) -> Response:
    bucket, key = _split_bucket_key(path)
    if not key:
        bucket_dir = _safe_storage_path(bucket)
        if not bucket_dir.exists():
            return Response(content=b"Bucket not found", status_code=404)
        objects = sorted(
            str(p.relative_to(bucket_dir))
            for p in bucket_dir.rglob("*")
            if p.is_file()
        )
        return Response(content=json.dumps(objects).encode("utf-8"), media_type="application/json")

    file_path = _safe_storage_path(bucket, key)
    if not file_path.is_file():
        return Response(content=b"Object not found", status_code=404)
    return Response(content=file_path.read_bytes(), status_code=200)


async def write_local_object(path: str, body: bytes) -> Response:
    bucket, key = _split_bucket_key(path)
    if not key:
        _safe_storage_path(bucket).mkdir(parents=True, exist_ok=True)
        return Response(status_code=200)
    file_path = _safe_storage_path(bucket, key)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_bytes(body)
    return Response(status_code=200)


async def delete_local_object(path: str) -> Response:
    bucket, key = _split_bucket_key(path)
    target = _safe_storage_path(bucket, key) if key else _safe_storage_path(bucket)
    if not target.exists():
        return Response(content=b"Not found", status_code=404)
    if target.is_file():
        target.unlink()
        async with engine.connect() as connection:
            await connection.execute(
                text("DELETE FROM pii_objects WHERE bucket_name=:bucket AND object_key=:key"),
                {"bucket": bucket, "key": key},
            )
            await connection.commit()
    return Response(status_code=204)


async def run_pii_analysis(bucket: str, key: str) -> None:
    entities = await asyncio.to_thread(get_upload_trigger().on_put, bucket, key)
    # Dashboard metric: entity types/counts only, never the detected values.
    if entities is None:
        await record_event("detection", status="failed", bucket=bucket, key=key)
    else:
        await record_event(
            "detection", bucket=bucket, key=key, entity_count=len(entities),
            details={"by_entity_type": dict(Counter(e["type"] for e in entities))},
        )


async def post_process_get_response(path: str, username: str, response: Response) -> Response:
    # `username` is the identity from the verified JWT (never a client-supplied header).
    access_key = username
    query = text(
        """
        SELECT p.policy FROM users u
        JOIN policies p ON u.policy_name = p.policy_name
        WHERE u.user_name = :access_key
        """
    )
    async with engine.connect() as connection:
        query_result = await connection.execute(query, {"access_key": access_key})
        rows = query_result.fetchall()
        if len(rows) == 0:
            print(f"No policy found for user {access_key}, skipping anonymization")
            bucket, key = _split_bucket_key(path)
            await record_event("download", status="original", actor=access_key, bucket=bucket, key=key)
            return response

        policy_map = []
        for row in rows:
            policy = row.policy
            policy_map.append(json.loads(policy) if isinstance(policy, str) else policy)
        print(f"Policy found for user {access_key}: {policy_map}, proceeding with anonymization")

        bucket, key = _split_bucket_key(path)
        async with grpc.aio.insecure_channel(anonymizer_url) as ch:
            stub = an_pb2_grpc.PIIAnonymizerServiceStub(ch)
            try:
                grpc_response = await stub.AnonymizeObject(
                    an_pb2.AnonymizeObjectRequest(
                        bucketName=bucket,
                        objectKey=key,
                        objectData=response.body,
                        policy_map=_policy_messages(policy_map),
                    )
                )
                updated = grpc_response.updatedObjectData

                headers = dict(response.headers)

                # Remove the old Content-Length because the anonymized
                # response has a different size.
                headers.pop("content-length", None)
                headers.pop("Content-Length", None)

                headers["objectLength"] = str(grpc_response.objectLength)

                spans = await load_object_entities(bucket, key) or []
                stats = await asyncio.to_thread(
                    anonymization_breakdown, response.body.decode("utf-8", "replace"), spans, policy_map
                )
                await record_event(
                    "anonymization", actor=access_key, bucket=bucket, key=key,
                    entity_count=stats["entity_count"], details=stats,
                )

                return Response(
                    content=updated,
                    status_code=response.status_code,
                    headers=headers
                )
            except grpc.aio.AioRpcError as e:
                error = {"code": e.code().name, "details": e.details()}
                print(f"gRPC error details: {error}")
                await record_event("anonymization", status="failed", actor=access_key, bucket=bucket, key=key)
                return response


# --- LLM Playground: PII Guard -> Ollama -------------------------------------
# Flow: raw prompt -> (1) PII DETECTION (existing PIIAnalyzer) -> (2) effective policy of the
# authenticated caller decides which detected types have a masking rule -> (3) ANONYMIZATION via the
# existing gRPC service, only if a rule applies -> prompt -> Ollama. Registered BEFORE the catch-all
# proxy route so POST /api/llm/chat is not treated as an S3 upload.
#
# Effective policy (see _resolve_effective_policy):
#   assigned     the caller has a policy: exactly its rules are applied, nothing else
#   passthrough  the caller is an admin WITHOUT a policy: no rule applies, the prompt is forwarded unchanged
#   default      a regular user WITHOUT a policy: fail-safe replace rules (below), never the raw text
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/chat")
OLLAMA_MODEL_PREFIX = "llama3.2"
LLM_SCRATCH_BUCKET = "__llm_playground__"  # only holds span offsets, never prompt text
# A user WITH a policy gets exactly that policy (types without a rule are kept, as in the S3 flow).
# A REGULAR user with NO policy would get the original text back from the S3 flow, which must never reach
# an LLM, so these types (the ones the seeded policies already cover, plus IP) are replaced instead.
# These defaults are never applied to an admin: an admin's effective policy is what the Policy Engine shows.
# Set LLM_STRICT_PII=1 to also replace every other detected type that has no rule (regular users only).
<<<<<<< HEAD
DEFAULT_PII_TYPES = {
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "US_SSN", "US_BANK_NUMBER", "IP_ADDRESS",
    # Indian + US categories (fail-safe for a regular user with no policy)
    "IN_AADHAAR", "IN_PIN_CODE", "IN_ADDRESS", "US_ADDRESS", "US_ZIP_CODE",
}
=======
DEFAULT_PII_TYPES = {"PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "US_SSN", "US_BANK_NUMBER", "IP_ADDRESS"}
>>>>>>> origin/main
LLM_STRICT_PII = os.environ.get("LLM_STRICT_PII", "0") == "1"


class LLMMessage(BaseModel):
    role: str
    content: str


class LLMChatRequest(BaseModel):
    provider: str
    model: str
    messages: list[LLMMessage]


async def _load_user_policy(user: str) -> list[dict]:
    # Same users/policies lookup that post_process_get_response uses for S3 GETs.
    query = text(
        "SELECT p.policy FROM users u JOIN policies p ON u.policy_name = p.policy_name "
        "WHERE u.user_name = :user"
    )
    async with engine.connect() as connection:
        rows = (await connection.execute(query, {"user": user})).fetchall()
    return [json.loads(r.policy) if isinstance(r.policy, str) else r.policy for r in rows]


async def _load_db_role(user: str) -> str | None:
    """The role stored for this user right now (None if the user is missing or the rows disagree)."""
    async with engine.connect() as connection:
        rows = (await connection.execute(
            text("SELECT role FROM users WHERE user_name = :user"), {"user": user})).fetchall()
    roles = {r.role for r in rows}
    return roles.pop() if len(roles) == 1 else None


@dataclass(frozen=True)
class EffectivePolicy:
    username: str
    mode: str               # "assigned" | "passthrough" | "default"
    rules: tuple            # the caller's OWN policy rules (empty unless mode == "assigned")
    is_admin: bool

    @property
    def can_mask(self) -> bool:
        return self.mode != "passthrough"


async def _resolve_effective_policy(user: AuthUser) -> EffectivePolicy:
    """What protection applies to THIS authenticated caller, decided once per request.

    The admin exemption needs the signed token AND the current users row to say admin, so a demoted
    admin's still-valid token (or a deleted account) is protected like any regular user.
    """
    rules = await _load_user_policy(user.username)
    is_admin = user.role == "admin" and await _load_db_role(user.username) == "admin"
    if rules:
        mode = "assigned"        # applies to admins too: an assigned policy is always honoured
    elif is_admin:
        mode = "passthrough"     # no masking rules apply to this admin
    else:
        mode = "default"
    return EffectivePolicy(user.username, mode, tuple(rules), is_admin)


class PromptBlocked(HTTPException):
    """Fail closed: the prompt must NOT reach the LLM. `failure` is a static code for the dashboard event."""

    def __init__(self, status_code: int, detail: str, failure: str):
        super().__init__(status_code=status_code, detail=detail)
        self.failure = failure


def _describe(content: str, entities: list[dict], rules: dict) -> list[dict]:
    # Display only: Presidio's anonymizer drops a lower-score detection that lies inside a
    # higher-score one (e.g. spaCy ORGANIZATION over an e-mail), so don't list those as findings.
    shown = [
        e for e in entities
        if not any(o is not e and o["score"] > e["score"] and o["start"] <= e["start"] and e["end"] <= o["end"]
                   for o in entities)
    ]
    out = []
    for e in sorted(shown, key=lambda x: x["start"]):
        rule = rules.get(e["type"])
        out.append({
            "entity_type": e["type"],
            # The matched text is NOT returned (no raw PII in API responses). The caller already has its own
            # prompt and highlights it with start/end; `length` is only a size hint.
            "length": e["end"] - e["start"],
            "start": e["start"],
            "end": e["end"],
            "score": e["score"],
            "operator_name": rule["operator_name"] if rule else "None",
            "operator_params": (rule.get("operator_params") or {}) if rule else {},
            "policy_source": rule["source"] if rule else "no rule (kept as-is)",
        })
    return out


# --- step 1: detection only (never changes text) ---------------------------------------------------
async def _detect_pii(content: str) -> list[dict]:
    analyzer = get_upload_trigger().processor.analyzer  # existing PIIAnalyzer
    # raise_on_error: "analysis failed" must never look like "no PII found".
    return await asyncio.to_thread(lambda: analyzer.analyze(content, raise_on_error=True))


# --- step 2: which detected types does the effective policy cover? ---------------------------------
def _applicable_rules(entities: list[dict], effective: EffectivePolicy) -> dict:
    if not effective.can_mask:
        return {}
    rules = {p["entity_type"]: {**p, "source": "user policy"} for p in effective.rules}
    if not effective.is_admin:
        for entity in entities:
            t = entity["type"]
            if t not in rules and (LLM_STRICT_PII or (effective.mode == "default" and t in DEFAULT_PII_TYPES)):
                rules[t] = {
                    "entity_type": t,
                    "operator_name": "replace",
                    "operator_params": {"new_value": f"<{t}>"},
                    "source": "default (user has no policy)" if effective.mode == "default" else "default (strict mode)",
                }
    return rules


# --- step 3: anonymization through the existing gRPC service ---------------------------------------
async def _anonymize(content: str, entities: list[dict], rules: dict) -> str:
    processor = get_upload_trigger().processor
    # The anonymizer service reads detected spans from SQLite by bucket/key, so store the spans
    # (offsets/types only, no text) under a throw-away key, then delete it.
    key = uuid.uuid4().hex
    try:
        await asyncio.to_thread(
            lambda: processor.db.store_pii_results(LLM_SCRATCH_BUCKET, key, entities, raise_on_error=True))
    except Exception as exc:  # noqa: BLE001
        # Without the spans the anonymizer would hand the ORIGINAL text back as if nothing were wrong.
        print(f"[llm] could not store detection spans: {type(exc).__name__}")
        raise PromptBlocked(
            502, "Could not record detected PII for the anonymizer. Prompt was NOT sent to the LLM.", "span_store")
    try:
        async with grpc.aio.insecure_channel(anonymizer_url) as ch:
            stub = an_pb2_grpc.PIIAnonymizerServiceStub(ch)
            grpc_response = await stub.AnonymizeObject(
                an_pb2.AnonymizeObjectRequest(
                    bucketName=LLM_SCRATCH_BUCKET,
                    objectKey=key,
                    objectData=content.encode("utf-8"),
                    policy_map=_policy_messages(list(rules.values())),
                ),
                timeout=30,
            )
    except grpc.aio.AioRpcError as e:
        raise PromptBlocked(
            502, f"Anonymizer service error ({e.code().name}). Prompt was NOT sent to the LLM.", "anonymizer")
    finally:
        async with engine.connect() as connection:
            await connection.execute(
                text("DELETE FROM pii_objects WHERE bucket_name=:b AND object_key=:k"),
                {"b": LLM_SCRATCH_BUCKET, "k": key},
            )
            await connection.commit()

    # Use the anonymizer's result exactly as returned. Identical text is a legitimate outcome (e.g. an
    # already-protected message from the chat history, or a rule whose output equals the input).
    protected = grpc_response.updatedObjectData.decode("utf-8")
    if protected == content:
        print("[llm] anonymizer returned the text unchanged; using it as-is")
    return protected


async def _protect_text(content: str, effective: EffectivePolicy) -> dict:
    """detect -> apply the effective policy -> anonymize only if a rule applies."""
    try:
        entities = await _detect_pii(content)
    except Exception as exc:  # noqa: BLE001
        if not effective.can_mask:
            # No masking rule applies to this caller, so there is nothing a failed detection could bypass.
            print(f"[llm] PII detection failed for {effective.username} ({type(exc).__name__}); no rules apply")
            return {"text": content, "entities": [], "spans": [], "rules": {}, "detection_failed": True}
        print(f"[llm] PII detection failed ({type(exc).__name__}); blocking the prompt")
        raise PromptBlocked(
            502, "PII detection failed. Prompt was NOT sent to the LLM.", "detection")
    if not entities:
        return {"text": content, "entities": [], "spans": [], "rules": {}}

    rules = _applicable_rules(entities, effective)
    described = _describe(content, entities, rules)
    if not any(e["type"] in rules for e in entities):  # nothing the policy touches: forwarded as written
        return {"text": content, "entities": described, "spans": entities, "rules": rules}

    protected = await _anonymize(content, entities, rules)
    return {"text": protected, "entities": described, "spans": entities, "rules": rules}


def _call_ollama(payload: dict) -> dict:
    req = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=300) as resp:
        return json.loads(resp.read())


@app.post("/api/llm/chat")
async def llm_chat(body: LLMChatRequest, current_user: AuthUser = Depends(get_current_user)):
    if body.provider != "ollama":
        raise HTTPException(status_code=400, detail="Only provider 'ollama' is served by this endpoint.")
    if not body.model.startswith(OLLAMA_MODEL_PREFIX):
        raise HTTPException(status_code=400, detail=f"Unsupported model '{body.model}'. Use 'llama3.2'.")
    if not body.messages or body.messages[-1].role != "user":
        raise HTTPException(status_code=400, detail="The last message must have role 'user'.")
    if any(m.role not in ("system", "user", "assistant") for m in body.messages):
        raise HTTPException(status_code=400, detail="Message role must be system, user or assistant.")

    user = current_user.username  # from the verified JWT
    request_id = uuid.uuid4().hex  # one dashboard event per request, however many code paths touch it
    effective = await _resolve_effective_policy(current_user)

    # Never trust the client: EVERY message (history included) is protected server-side.
    protected_messages, latest = [], None
    try:
        for m in body.messages:
            latest = await _protect_text(m.content, effective)
            protected_messages.append({"role": m.role, "content": latest["text"]})
    except PromptBlocked as e:
        await record_event(
            "anonymization", status="failed", actor=user, source="llm_prompt", request_id=request_id,
            details={"failure": e.failure, "policy_mode": effective.mode},
        )
        raise
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 - fail closed on anything unexpected
        print(f"[llm] unexpected error while protecting the prompt: {type(exc).__name__}")
        await record_event(
            "anonymization", status="failed", actor=user, source="llm_prompt", request_id=request_id,
            details={"failure": "internal", "policy_mode": effective.mode},
        )
        raise HTTPException(status_code=500, detail="Could not protect the prompt. Prompt was NOT sent to the LLM.")

    ollama_request = {"model": body.model, "messages": protected_messages, "stream": False}
    # Types and counts only: the prompt text (original or protected) is never written to the logs.
    print(f"[llm] user={user} mode={effective.mode} detected={[e['entity_type'] for e in latest['entities']]} -> Ollama {body.model}")
    try:
        result = await asyncio.to_thread(_call_ollama, ollama_request)
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")
        raise HTTPException(status_code=502, detail=f"Ollama returned HTTP {e.code}: {detail} (try: ollama pull {body.model})")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise HTTPException(status_code=503, detail=f"Cannot reach Ollama at {OLLAMA_URL} ({e}). Is 'ollama serve' running?")

    # Dashboard metric: one event for the newest prompt only (history was counted when it was sent), written
    # once the prompt has actually been forwarded. Detection (`detected`) and anonymization (top level) are
    # recorded separately; entity types/counts only, never values.
    stats = await asyncio.to_thread(
        prompt_breakdown, body.messages[-1].content, latest.get("spans", []), list(latest.get("rules", {}).values())
    )
    stats["policy_mode"] = effective.mode
    if latest.get("detection_failed"):
        stats["detection_failed"] = True
    await record_event(
        "anonymization",
        status="ok" if effective.can_mask else "original",  # "original": no masking rule applies, sent as written
        actor=user, source="llm_prompt", entity_count=stats["entity_count"], details=stats, request_id=request_id,
    )

    return {
        "model": result.get("model", body.model),
        "message": result.get("message", {"role": "assistant", "content": ""}),  # Ollama-native shape
        "done": result.get("done", True),
        "pii_guard": {
            "provider": "ollama",
            "model_used": result.get("model", body.model),
            "ollama_url": OLLAMA_URL,
            "policy_user": user,
            "policy_found": bool(effective.rules),
            "policy_mode": effective.mode,  # assigned | passthrough | default
            "masking_applied": stats["entity_count"] > 0,
            "entities": latest["entities"],
            "protected_prompt": latest["text"],
            "ollama_request": ollama_request,  # exactly what was sent to Ollama
        },
    }
# -----------------------------------------------------------------------------


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def proxy_handler(
    request: Request,
    path: str,
    tagging: str | None = None,
    current_user: AuthUser = Depends(get_current_user),  # every object route needs a valid JWT
):
    if request.method in ("PUT", "POST", "DELETE") and path:
        if current_user.role != "admin":
            await record_event(
                "access_denied", status="failed", actor=current_user.username,
                details={"method": request.method, "route": "/{bucket}/{key}", "required_role": "admin"},
            )
        require_role(current_user, "admin")  # RBAC: only admins may write or delete objects

    if request.method in ("PUT", "POST") and path:
        body = await request.body()
        resp = await write_local_object(path, body)
        bucket, key = _split_bucket_key(path)
        if key:
            await record_event(
                "upload", actor=current_user.username, bucket=bucket, key=key, details={"size_bytes": len(body)}
            )
            await run_pii_analysis(bucket, key)
        return resp

    if request.method == "DELETE" and path:
        resp = await delete_local_object(path)
        bucket, key = _split_bucket_key(path)
        if resp.status_code == 204 and key:
            await record_event("delete", actor=current_user.username, bucket=bucket, key=key)
        return resp

    if request.method == "GET" and re.match(r"^[^/]+/.+", path) and tagging is None:
        resp = await read_local_object(path)
        if resp.status_code == 200:
            return await post_process_get_response(path, current_user.username, resp)
        return resp

    if request.method == "GET":
        return await read_local_object(path)

    if request.method == "HEAD":
        bucket, key = _split_bucket_key(path)
        target = _safe_storage_path(bucket, key) if key else _safe_storage_path(bucket)
        return Response(status_code=200 if target.exists() else 404)

    return Response(status_code=405)


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8080, reload=False)
