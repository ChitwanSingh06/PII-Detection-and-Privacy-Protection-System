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
    flags = SimpleNamespace(analyzer_down=False, span_store_down=False)

    class Analyzer:
        def analyze(self, text, raise_on_error=False):
            if flags.analyzer_down:
                if raise_on_error:
                    raise RuntimeError("analyzer down")
                return []  # the real analyzer's default: an error looks exactly like "no PII found"
            return [{"type": t, "start": text.index(v), "end": text.index(v) + len(v), "score": 0.9}
                    for v, t in KNOWN.items() if v in text]

    class SpanDB:  # the proxy stores spans here; the anonymizer reads them back by bucket/key
        def store_pii_results(self, bucket, key, entities, raise_on_error=False):
            if flags.span_store_down:
                if raise_on_error:
                    raise OSError("database is locked")
                return  # the real writer's default: log and carry on
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
    return SimpleNamespace(ollama=ollama, anonymizer_calls=anonymizer_calls, store=store, flags=flags)


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


def test_admin_with_no_applicable_rules_sends_the_original_prompt_unchanged(client, admin_h, env):
    r = chat(client, admin_h, PROMPT)
    assert r.status_code == 200
    assert sent_to_ollama(env) == PROMPT                      # byte-for-byte, nothing masked
    assert env.anonymizer_calls == []                         # the anonymizer was never involved
    guard = r.json()["pii_guard"]
    assert guard["policy_user"] == "admin" and guard["policy_found"] is False
    assert guard["policy_mode"] == "passthrough" and guard["masking_applied"] is False
    assert guard["protected_prompt"] == PROMPT and guard["ollama_request"] == env.ollama[0]
    # detection is separate from anonymization: the findings are still reported, with no rule behind them
    assert {e["entity_type"] for e in guard["entities"]} == {"PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD"}
    assert {e["operator_name"] for e in guard["entities"]} == {"None"}


def test_admin_and_user1_use_their_own_policies(client, admin_h, user1_h, env):
    chat(client, admin_h, PROMPT)
    chat(client, user1_h, PROMPT)
    assert env.ollama[0]["messages"][-1]["content"] == PROMPT      # admin: no rules apply
    assert env.ollama[1]["messages"][-1]["content"] == USER1_OUT   # user1: exactly user1_policy
    assert PROMPT != USER1_OUT


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


# ====================================================================================================
# Regression: an admin whose effective policy has no applicable masking rules must be sent UNCHANGED,
# regular users keep exactly their own protection, and errors never silently bypass an applicable policy.
# ====================================================================================================
def set_policy(client, admin_h, user, policy):
    r = client.put(f"/api/users/{user}/policy", headers=admin_h, json={"policy_name": policy})
    assert r.status_code == 200, r.text


def test_admin_prompt_is_not_masked_for_any_message_in_the_conversation(client, admin_h, env):
    r = chat(client, admin_h, "Email priya.raman@acme.in", "ok", PROMPT, roles=["user", "assistant", "user"])
    assert r.status_code == 200
    assert [m["content"] for m in env.ollama[0]["messages"]] == ["Email priya.raman@acme.in", "ok", PROMPT]
    assert env.anonymizer_calls == [] and env.store == {}  # no span was even staged for the anonymizer


def test_admin_with_an_assigned_policy_gets_exactly_that_policy(client, admin_h, env):
    set_policy(client, admin_h, "admin", "user2_policy")
    r = chat(client, admin_h, PROMPT)
    assert sent_to_ollama(env) == USER2_OUT  # user2_policy keeps names: PERSON stays, no default is added
    assert env.anonymizer_calls[-1] == {"CREDIT_CARD": "mask", "EMAIL_ADDRESS": "mask", "PHONE_NUMBER": "replace",
                                        "US_SSN": "redact", "US_BANK_NUMBER": "mask"}
    guard = r.json()["pii_guard"]
    assert guard["policy_mode"] == "assigned" and guard["policy_found"] is True and guard["masking_applied"] is True

    set_policy(client, admin_h, "admin", None)  # unassigned again -> the very next prompt is unchanged
    chat(client, admin_h, PROMPT)
    assert sent_to_ollama(env) == PROMPT


def test_admin_policy_with_no_matching_rule_leaves_the_prompt_untouched(client, admin_h, env):
    rules = [{"entity_type": "US_SSN", "operator_name": "redact"}]
    client.post("/api/policies", headers=admin_h, json={"policy_name": "ssn_only", "rules": rules})
    set_policy(client, admin_h, "admin", "ssn_only")
    chat(client, admin_h, PROMPT)  # no SSN in the prompt: no rule applies, nothing is added on top
    assert sent_to_ollama(env) == PROMPT and env.anonymizer_calls == []


def test_regular_user_without_a_policy_still_gets_the_fail_safe_defaults(client, admin_h, user1_h, env):
    set_policy(client, admin_h, "user1", None)
    r = chat(client, user1_h, PROMPT)
    assert sent_to_ollama(env) == NO_POLICY_OUT
    guard = r.json()["pii_guard"]
    assert guard["policy_mode"] == "default" and guard["policy_found"] is False and guard["masking_applied"] is True
    assert {e["policy_source"] for e in guard["entities"]} == {"default (user has no policy)"}
    assert not any(p in json.dumps(env.ollama[0]) for p in PII)


def test_admin_passthrough_does_not_change_what_regular_users_receive(client, admin_h, user1_h, env):
    from conftest import bearer
    user2_h = bearer(client, "user2", "User2@12345")
    chat(client, admin_h, PROMPT)
    chat(client, user1_h, PROMPT)
    chat(client, user2_h, PROMPT)
    chat(client, admin_h, PROMPT)
    assert [o["messages"][-1]["content"] for o in env.ollama] == [PROMPT, USER1_OUT, USER2_OUT, PROMPT]


def test_demoted_admin_with_a_still_valid_token_is_protected_like_a_regular_user(client, admin_h, env):
    conn = sqlite3.connect(config.SQLITE_PATH)  # restore_db puts the row back after the test
    conn.execute("UPDATE users SET role='user' WHERE user_name='admin'")
    conn.commit()
    conn.close()
    r = chat(client, admin_h, PROMPT)  # the token still says role=admin
    assert r.status_code == 200
    assert sent_to_ollama(env) == NO_POLICY_OUT and r.json()["pii_guard"]["policy_mode"] == "default"


def test_strict_mode_never_adds_defaults_for_an_admin(client, admin_h, user1_h, env, monkeypatch):
    import app as proxy_app
    monkeypatch.setattr(proxy_app, "LLM_STRICT_PII", True)
    monkeypatch.setitem(KNOWN, "https://example.com/x", "URL")  # a type neither seeded policy has a rule for
    chat(client, admin_h, "Visit https://example.com/x " + PROMPT)
    assert sent_to_ollama(env) == "Visit https://example.com/x " + PROMPT and env.anonymizer_calls == []
    chat(client, user1_h, "Visit https://example.com/x")  # a regular user keeps the opt-in strict behaviour
    assert sent_to_ollama(env) == "Visit <URL>"


def test_detection_is_separate_from_anonymization(client, admin_h, user1_h, env):
    import app as proxy_app
    from auth import AuthUser
    import asyncio

    entities = [{"type": "PERSON", "start": 0, "end": 5, "score": 0.9}, {"type": "URL", "start": 6, "end": 9, "score": 0.9}]
    admin = asyncio.run(proxy_app._resolve_effective_policy(AuthUser("admin", "admin")))
    assert admin.mode == "passthrough" and proxy_app._applicable_rules(entities, admin) == {}
    user = asyncio.run(proxy_app._resolve_effective_policy(AuthUser("user1", "user")))
    assert user.mode == "assigned" and set(proxy_app._applicable_rules(entities, user)) == {r["entity_type"] for r in user.rules}
    # detection itself never touches the anonymizer
    assert asyncio.run(proxy_app._detect_pii(PROMPT))
    assert env.anonymizer_calls == [] and env.store == {}


# ---- errors never silently bypass an applicable policy -----------------------------------------------
@pytest.mark.parametrize("who, assign", [("user1", None), ("user2", None), ("user1", "user2_policy")])
def test_detection_failure_blocks_prompts_for_users_with_a_policy(client, admin_h, env, who, assign):
    from conftest import bearer
    pw = {"user1": "User1@12345", "user2": "User2@12345"}[who]
    if assign:
        set_policy(client, admin_h, who, assign)
    env.flags.analyzer_down = True
    r = chat(client, bearer(client, who, pw), PROMPT)
    assert r.status_code == 502 and "NOT sent" in r.json()["detail"]
    assert env.ollama == [] and env.anonymizer_calls == []
    assert "Priya" not in r.text and "priya.raman" not in r.text  # the error never echoes the prompt


def test_detection_failure_also_blocks_a_regular_user_who_only_has_the_default(client, admin_h, user1_h, env):
    set_policy(client, admin_h, "user1", None)
    env.flags.analyzer_down = True
    assert chat(client, user1_h, PROMPT).status_code == 502 and env.ollama == []


def test_detection_failure_blocks_an_admin_who_has_an_assigned_policy(client, admin_h, env):
    set_policy(client, admin_h, "admin", "user1_policy")
    env.flags.analyzer_down = True
    assert chat(client, admin_h, PROMPT).status_code == 502 and env.ollama == []


def test_detection_failure_for_a_passthrough_admin_has_nothing_to_bypass(client, admin_h, env):
    env.flags.analyzer_down = True
    r = chat(client, admin_h, PROMPT)  # no rule applies to this admin, so the original is forwarded as promised
    assert r.status_code == 200 and sent_to_ollama(env) == PROMPT and r.json()["pii_guard"]["entities"] == []


def test_failure_to_stage_spans_blocks_instead_of_forwarding_the_original(client, user1_h, env):
    # without the staged spans the anonymizer service answers with the ORIGINAL text; that must not pass as protected
    env.flags.span_store_down = True
    r = chat(client, user1_h, PROMPT)
    assert r.status_code == 502 and "NOT sent" in r.json()["detail"]
    assert env.ollama == [] and env.anonymizer_calls == []


def test_a_prompt_with_nothing_for_the_policy_to_mask_is_forwarded_as_written(client, user1_h, env):
    chat(client, user1_h, "Server at 10.24.8.17 is down")  # user1_policy has no IP_ADDRESS rule
    assert sent_to_ollama(env) == "Server at 10.24.8.17 is down" and env.anonymizer_calls == []


# ---- the real analyzer / writer: errors can be surfaced, default behaviour is unchanged ----------------
def test_analyzer_and_writer_default_behaviour_is_unchanged_but_can_raise(tmp_path):
    from pii_analyser import PIIAnalyzer, SqlitePiiDB

    class Broken:
        def analyze(self, **kwargs):
            raise RuntimeError("model not loaded")

    analyzer = object.__new__(PIIAnalyzer)  # skip loading spaCy
    analyzer.engine = Broken()
    assert analyzer.analyze("Priya Raman") == []  # upload path: unchanged
    with pytest.raises(RuntimeError):
        analyzer.analyze("Priya Raman", raise_on_error=True)

    writer = SqlitePiiDB()
    writer.db_path = str(tmp_path)  # a directory: sqlite cannot open it
    assert writer.store_pii_results("b", "k", []) is None  # unchanged: logged, not raised
    with pytest.raises(Exception):
        writer.store_pii_results("b", "k", [], raise_on_error=True)
