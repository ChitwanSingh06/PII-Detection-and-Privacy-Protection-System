"""LLM Playground: JWT user -> their SQLite policy -> anonymizer -> protected prompt -> Ollama.

Real here: JWT auth, the users/policies tables, the proxy's /api/llm/chat code, the policy -> gRPC message
conversion, and Presidio's anonymizer (via the project's PIIAnonymizer, called the same way the gRPC handler
calls it). Stubbed: the analyzer (fixed spans, so results don't depend on the spaCy model), the gRPC
transport, and Ollama (a recorder, so we can inspect exactly what it would receive).
"""
import json
import sqlite3
from types import SimpleNamespace

import grpc
import pytest

import config

PROMPT = "Draft a reply to Priya Raman (priya.raman@acme.in, +91 98765 43210) about the failed payment on card 4532 8891 0023 7714."
PII = ["Priya Raman", "priya.raman@acme.in", "+91 98765 43210", "4532 8891 0023 7714"]
KNOWN = {"Priya Raman": "PERSON", "priya.raman@acme.in": "EMAIL_ADDRESS", "+91 98765 43210": "PHONE_NUMBER",
         "4532 8891 0023 7714": "CREDIT_CARD", "123-45-6789": "US_SSN"}

# What each seeded policy (or the no-policy default) must produce for PROMPT.
USER1_OUT = "Draft a reply to PERSON (<EMAIL>, PHONE_NUMBER) about the failed payment on card **********0023 7714."
USER2_OUT = "Draft a reply to Priya Raman (*******************, <PHONE>) about the failed payment on card **********0023 7714."
NO_POLICY_OUT = "Draft a reply to <PERSON> (<EMAIL_ADDRESS>, <PHONE_NUMBER>) about the failed payment on card <CREDIT_CARD>."


@pytest.fixture(autouse=True)
def restore_db():
    conn = sqlite3.connect(config.SQLITE_PATH)
    users = conn.execute("SELECT user_name, policy_name, password_hash, role FROM users").fetchall()
    policies = conn.execute("SELECT policy_name, policy FROM policies").fetchall()
    conn.close()
    yield
    conn = sqlite3.connect(config.SQLITE_PATH)
    conn.execute("DELETE FROM users")
    conn.execute("DELETE FROM policies")
    conn.executemany("INSERT INTO users (user_name, policy_name, password_hash, role) VALUES (?,?,?,?)", users)
    conn.executemany("INSERT INTO policies (policy_name, policy) VALUES (?,?)", policies)
    conn.commit()
    conn.close()


@pytest.fixture
def env(monkeypatch):
    import app as proxy_app
    from anonymizer.pii_anonymizer import PIIAnonymizer

    store, ollama, anonymizer_calls = {}, [], []

    class Analyzer:
        def analyze(self, text):
            return [{"type": t, "start": text.index(v), "end": text.index(v) + len(v), "score": 0.9}
                    for v, t in KNOWN.items() if v in text]

    class SpanDB:  # the proxy stores spans here; the anonymizer reads them back by bucket/key
        def store_pii_results(self, bucket, key, entities):
            store[(bucket, key)] = entities

    class Channel:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    class Stub:
        def __init__(self, channel):
            pass

        async def AnonymizeObject(self, request, timeout=None):
            # Same logic as anonymizer/server/handler.py, minus the SQLite read.
            anonymizer_calls.append({r.entityType: r.operatorName for r in request.policy_map})
            data = request.objectData.decode("utf-8")
            spans = store.get((request.bucketName, request.objectKey))
            out = data if spans is None else PIIAnonymizer().anonymize_data(
                object_data=data, policy_map=request.policy_map, pii_metadata=spans)
            return proxy_app.an_pb2.AnonymizeObjectResponse(updatedObjectData=out.encode("utf-8"), objectLength=len(out))

    def fake_ollama(payload):
        ollama.append(payload)
        return {"model": "llama3.2", "message": {"role": "assistant", "content": "LLM-REPLY"}, "done": True}

    processor = SimpleNamespace(analyzer=Analyzer(), db=SpanDB())
    monkeypatch.setattr(proxy_app, "get_upload_trigger", lambda: SimpleNamespace(processor=processor))
    monkeypatch.setattr(proxy_app.grpc.aio, "insecure_channel", lambda url: Channel())
    monkeypatch.setattr(proxy_app.an_pb2_grpc, "PIIAnonymizerServiceStub", Stub)
    monkeypatch.setattr(proxy_app, "_call_ollama", fake_ollama)
    return SimpleNamespace(ollama=ollama, anonymizer_calls=anonymizer_calls, store=store)


def chat(client, headers, *contents, roles=None):
    roles = roles or ["user"] * len(contents)
    body = {"provider": "ollama", "model": "llama3.2",
            "messages": [{"role": r, "content": c} for r, c in zip(roles, contents)]}
    return client.post("/api/llm/chat", json=body, headers=headers)


def sent_to_ollama(env):
    return env.ollama[-1]["messages"][-1]["content"]


# ---- user1: own policy, protected content is what Ollama gets -------------------
def test_user1_prompt_is_protected_by_user1_policy_and_only_that_reaches_ollama(client, user1_h, env):
    r = chat(client, user1_h, PROMPT)
    assert r.status_code == 200
    body, guard = r.json(), r.json()["pii_guard"]

    assert len(env.ollama) == 1
    assert sent_to_ollama(env) == USER1_OUT
    assert env.ollama[0]["model"] == "llama3.2" and env.ollama[0]["stream"] is False
    assert env.anonymizer_calls[-1] == {  # exactly user1_policy's rules went to the anonymizer
        "PERSON": "replace", "CREDIT_CARD": "mask", "EMAIL_ADDRESS": "replace",
        "PHONE_NUMBER": "replace", "US_SSN": "redact", "US_BANK_NUMBER": "mask"}

    # the original PII is nowhere in the outbound request
    outbound = json.dumps(env.ollama[0])
    assert not any(p in outbound for p in PII)

    # what the UI shows == what was sent
    assert guard["policy_user"] == "user1" and guard["policy_found"] is True
    assert guard["protected_prompt"] == sent_to_ollama(env)
    assert guard["ollama_request"] == env.ollama[0]
    assert body["message"]["content"] == "LLM-REPLY"  # the model's actual reply is returned


def test_admin_has_no_policy_and_gets_the_existing_default_behaviour(client, admin_h, env):
    r = chat(client, admin_h, PROMPT)
    assert r.status_code == 200
    assert sent_to_ollama(env) == NO_POLICY_OUT
    assert r.json()["pii_guard"]["policy_user"] == "admin" and r.json()["pii_guard"]["policy_found"] is False
    assert not any(p in json.dumps(env.ollama[0]) for p in PII)


def test_admin_and_user1_use_their_own_policies(client, admin_h, user1_h, env):
    chat(client, admin_h, PROMPT)
    chat(client, user1_h, PROMPT)
    assert env.ollama[0]["messages"][-1]["content"] == NO_POLICY_OUT
    assert env.ollama[1]["messages"][-1]["content"] == USER1_OUT
    assert NO_POLICY_OUT != USER1_OUT


def test_user2_uses_user2_policy(client, env):
    from conftest import bearer
    chat(client, bearer(client, "user2", "User2@12345"), PROMPT)
    assert sent_to_ollama(env) == USER2_OUT


# ---- policy changes apply to the very next LLM request --------------------------
def test_reassigning_policy_changes_next_request(client, admin_h, user1_h, env):
    chat(client, user1_h, PROMPT)
    assert sent_to_ollama(env) == USER1_OUT
    assert client.put("/api/users/user1/policy", headers=admin_h, json={"policy_name": "user2_policy"}).status_code == 200
    chat(client, user1_h, PROMPT)
    assert sent_to_ollama(env) == USER2_OUT
    client.put("/api/users/user1/policy", headers=admin_h, json={"policy_name": None})
    chat(client, user1_h, PROMPT)
    assert sent_to_ollama(env) == NO_POLICY_OUT


def test_editing_policy_changes_next_request(client, admin_h, user1_h, env):
    chat(client, user1_h, PROMPT)
    rules = [{"entity_type": "EMAIL_ADDRESS", "operator_name": "redact"},
             {"entity_type": "PERSON", "operator_name": "hash", "operator_params": {"hash_type": "sha256"}}]
    assert client.put("/api/policies/user1_policy", headers=admin_h, json={"rules": rules}).status_code == 200
    chat(client, user1_h, PROMPT)
    out = sent_to_ollama(env)
    assert "priya.raman@acme.in" not in out and "Priya Raman" not in out  # email redacted, name hashed
    assert "(, +91 98765 43210)" in out                                    # no phone/card rule now: kept as-is
    assert env.anonymizer_calls[-1] == {"EMAIL_ADDRESS": "redact", "PERSON": "hash"}


# ---- the anonymizer's result is used as-is --------------------------------------
def test_unchanged_anonymizer_result_is_not_an_error(client, admin_h, user1_h, env):
    rules = [{"entity_type": "PERSON", "operator_name": "replace", "operator_params": {"new_value": "Priya Raman"}}]
    client.post("/api/policies", headers=admin_h, json={"policy_name": "noop_policy", "rules": rules})
    client.put("/api/users/user1/policy", headers=admin_h, json={"policy_name": "noop_policy"})
    r = chat(client, user1_h, "Please call Priya Raman.")
    assert r.status_code == 200
    assert sent_to_ollama(env) == "Please call Priya Raman."  # result used as returned, not rejected
    assert r.json()["pii_guard"]["protected_prompt"] == "Please call Priya Raman."


def test_already_protected_history_does_not_break_a_follow_up(client, user1_h, env):
    # The UI re-sends earlier (already protected) turns; they must pass through, and the new one is protected.
    r = chat(client, user1_h, USER1_OUT, "LLM-REPLY", PROMPT, roles=["user", "assistant", "user"])
    assert r.status_code == 200
    assert [m["content"] for m in env.ollama[0]["messages"]] == [USER1_OUT, "LLM-REPLY", USER1_OUT]


def test_every_message_is_protected_not_just_the_last(client, user1_h, env):
    r = chat(client, user1_h, "Email priya.raman@acme.in", "ok", "Call +91 98765 43210", roles=["user", "assistant", "user"])
    assert r.status_code == 200
    assert not any(p in json.dumps(env.ollama[0]) for p in PII)
    assert [m["content"] for m in env.ollama[0]["messages"]] == ["Email <EMAIL>", "ok", "Call PHONE_NUMBER"]


def test_text_without_pii_is_sent_unchanged(client, user1_h, env):
    chat(client, user1_h, "What is the capital of France?")
    assert sent_to_ollama(env) == "What is the capital of France?"
    assert env.anonymizer_calls == []


# ---- fail closed ----------------------------------------------------------------
def test_anonymizer_failure_blocks_the_request(client, user1_h, env, monkeypatch):
    import app as proxy_app

    class Down:
        def __init__(self, channel):
            pass

        async def AnonymizeObject(self, request, timeout=None):
            raise grpc.aio.AioRpcError(grpc.StatusCode.UNAVAILABLE, grpc.aio.Metadata(), grpc.aio.Metadata())

    monkeypatch.setattr(proxy_app.an_pb2_grpc, "PIIAnonymizerServiceStub", Down)
    r = chat(client, user1_h, PROMPT)
    assert r.status_code == 502 and "NOT sent" in r.json()["detail"]
    assert env.ollama == []  # nothing reached Ollama


# ---- authentication -------------------------------------------------------------
def test_missing_or_invalid_jwt_is_401_and_nothing_reaches_ollama(client, env):
    assert chat(client, {}, PROMPT).status_code == 401
    assert chat(client, {"Authorization": "Bearer not.a.jwt"}, PROMPT).status_code == 401
    assert chat(client, {"X-User": "admin"}, PROMPT).status_code == 401
    assert env.ollama == []


def test_expired_jwt_is_401(client, env):
    from datetime import datetime, timedelta, timezone
    import jwt
    now = datetime.now(timezone.utc)
    t = jwt.encode({"sub": "user1", "role": "user", "iat": now, "exp": now - timedelta(minutes=1)},
                   config.JWT_SECRET, algorithm="HS256")
    assert chat(client, {"Authorization": f"Bearer {t}"}, PROMPT).status_code == 401
    assert env.ollama == []


def test_x_user_cannot_change_whose_policy_is_used(client, user1_h, env):
    r = chat(client, {**user1_h, "X-User": "admin"}, PROMPT)
    assert r.json()["pii_guard"]["policy_user"] == "user1"
    assert sent_to_ollama(env) == USER1_OUT


def test_only_ollama_llama32_is_accepted(client, user1_h, env):
    bad_provider = {"provider": "openai", "model": "llama3.2", "messages": [{"role": "user", "content": "hi"}]}
    bad_model = {"provider": "ollama", "model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}
    assert client.post("/api/llm/chat", json=bad_provider, headers=user1_h).status_code == 400
    assert client.post("/api/llm/chat", json=bad_model, headers=user1_h).status_code == 400
    assert env.ollama == []
