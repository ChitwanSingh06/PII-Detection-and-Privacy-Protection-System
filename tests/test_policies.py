import sqlite3

import pytest

import config
from conftest import bearer

RULE_EMAIL = {"entity_type": "EMAIL_ADDRESS", "operator_name": "replace", "operator_params": {"new_value": "<EMAIL>"}}
RULE_SSN = {"entity_type": "US_SSN", "operator_name": "redact"}
RULE_CARD = {"entity_type": "CREDIT_CARD", "operator_name": "mask",
             "operator_params": {"masking_char": "#", "chars_to_mask": 12, "from_end": False}}


@pytest.fixture(autouse=True)
def restore_db():
    """Tests here change policies/users in the shared test DB; put them back afterwards."""
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


def create(client, admin_h, name="p_test", rules=None):
    return client.post("/api/policies", headers=admin_h, json={"policy_name": name, "rules": [RULE_EMAIL, RULE_SSN] if rules is None else rules})


# ---- Listing / reading -------------------------------------------------------
def test_list_policies(client, admin_h):
    r = client.get("/api/policies", headers=admin_h)
    assert r.status_code == 200
    by_name = {p["policy_name"]: p for p in r.json()}
    assert set(by_name) == {"user1_policy", "user2_policy"}
    assert len(by_name["user1_policy"]["rules"]) == 6 and len(by_name["user2_policy"]["rules"]) == 5
    assert by_name["user1_policy"]["assigned_users"] == ["user1"]
    assert by_name["user1_policy"]["rules"][0] == {
        "entity_type": "PERSON", "operator_name": "replace", "operator_params": {"new_value": "PERSON"}}


def test_get_policy(client, admin_h):
    r = client.get("/api/policies/user2_policy", headers=admin_h)
    assert r.status_code == 200 and r.json()["policy_name"] == "user2_policy"
    assert [x["entity_type"] for x in r.json()["rules"]][0] == "CREDIT_CARD"


def test_get_nonexistent_policy_404(client, admin_h):
    assert client.get("/api/policies/nope", headers=admin_h).status_code == 404


# ---- Create ------------------------------------------------------------------
def test_create_policy(client, admin_h):
    r = create(client, admin_h, rules=[RULE_EMAIL, RULE_SSN, RULE_CARD])
    assert r.status_code == 201
    body = r.json()
    assert body["policy_name"] == "p_test" and body["assigned_users"] == []
    assert body["rules"][1] == {"entity_type": "US_SSN", "operator_name": "redact", "operator_params": {}}
    assert client.get("/api/policies/p_test", headers=admin_h).json() == body
    assert "p_test" in [p["policy_name"] for p in client.get("/api/policies", headers=admin_h).json()]


def test_create_normalises_mask_params(client, admin_h):
    rule = {"entity_type": "PHONE_NUMBER", "operator_name": "mask", "operator_params": {"chars_to_mask": 4}}
    r = create(client, admin_h, rules=[rule])
    assert r.json()["rules"][0]["operator_params"] == {"masking_char": "*", "chars_to_mask": 4, "from_end": False}


def test_create_duplicate_name_409(client, admin_h):
    assert create(client, admin_h).status_code == 201
    assert create(client, admin_h).status_code == 409
    assert create(client, admin_h, name="user1_policy").status_code == 409


@pytest.mark.parametrize("rules", [
    [],                                                                                     # no rules
    [{"entity_type": "EMAIL_ADDRESS", "operator_name": "encrypt"}],                         # unsupported operator
    [{"entity_type": "email", "operator_name": "redact"}],                                  # bad entity name
    [{"entity_type": "EMAIL_ADDRESS", "operator_name": "mask", "operator_params": {}}],     # mask needs chars_to_mask
    [{"entity_type": "EMAIL_ADDRESS", "operator_name": "mask", "operator_params": {"chars_to_mask": -1}}],
    [{"entity_type": "EMAIL_ADDRESS", "operator_name": "mask", "operator_params": {"chars_to_mask": 3, "masking_char": "ab"}}],
    [{"entity_type": "EMAIL_ADDRESS", "operator_name": "redact", "operator_params": {"x": 1}}],
    [{"entity_type": "EMAIL_ADDRESS", "operator_name": "hash", "operator_params": {"hash_type": "md5"}}],
    [{"entity_type": "EMAIL_ADDRESS", "operator_name": "replace", "operator_params": {"new_value": 5}}],
    [RULE_EMAIL, {**RULE_EMAIL, "operator_name": "redact", "operator_params": {}}],         # same entity twice
])
def test_create_invalid_rules_422(client, admin_h, rules):
    assert create(client, admin_h, rules=rules).status_code == 422
    assert client.get("/api/policies/p_test", headers=admin_h).status_code == 404  # nothing was stored


@pytest.mark.parametrize("name", ["", "bad name", "../x", "a/b", "x" * 65, "-lead"])
def test_create_invalid_name_422(client, admin_h, name):
    assert create(client, admin_h, name=name).status_code == 422


def test_create_missing_fields_422(client, admin_h):
    assert client.post("/api/policies", headers=admin_h, json={"policy_name": "x"}).status_code == 422


# ---- Update ------------------------------------------------------------------
def test_update_replaces_rules(client, admin_h):
    create(client, admin_h)
    r = client.put("/api/policies/p_test", headers=admin_h, json={"rules": [RULE_CARD]})
    assert r.status_code == 200
    assert [x["entity_type"] for x in r.json()["rules"]] == ["CREDIT_CARD"]
    assert [x["entity_type"] for x in client.get("/api/policies/p_test", headers=admin_h).json()["rules"]] == ["CREDIT_CARD"]


def test_update_nonexistent_404_and_invalid_422(client, admin_h):
    assert client.put("/api/policies/nope", headers=admin_h, json={"rules": [RULE_EMAIL]}).status_code == 404
    create(client, admin_h)
    assert client.put("/api/policies/p_test", headers=admin_h, json={"rules": []}).status_code == 422
    assert len(client.get("/api/policies/p_test", headers=admin_h).json()["rules"]) == 2  # unchanged


def test_update_keeps_assignment(client, admin_h):
    client.put("/api/users/user2/policy", headers=admin_h, json={"policy_name": "user2_policy"})
    client.put("/api/policies/user2_policy", headers=admin_h, json={"rules": [RULE_SSN]})
    assert client.get("/api/policies/user2_policy", headers=admin_h).json()["assigned_users"] == ["user2"]


# ---- Delete ------------------------------------------------------------------
def test_delete_policy(client, admin_h):
    create(client, admin_h)
    assert client.delete("/api/policies/p_test", headers=admin_h).status_code == 204
    assert client.get("/api/policies/p_test", headers=admin_h).status_code == 404
    assert client.delete("/api/policies/p_test", headers=admin_h).status_code == 404


def test_delete_nonexistent_404(client, admin_h):
    assert client.delete("/api/policies/nope", headers=admin_h).status_code == 404


def test_delete_assigned_policy_409(client, admin_h):
    r = client.delete("/api/policies/user1_policy", headers=admin_h)
    assert r.status_code == 409 and "user1" in r.json()["detail"]
    assert len(client.get("/api/policies/user1_policy", headers=admin_h).json()["rules"]) == 6


# ---- Assignment --------------------------------------------------------------
def users(client, admin_h):
    return {u["user_name"]: u for u in client.get("/api/users", headers=admin_h).json()}


def test_list_users_has_no_password_hash(client, admin_h):
    r = client.get("/api/users", headers=admin_h)
    assert r.status_code == 200 and "password_hash" not in r.text
    u = users(client, admin_h)
    assert u["user1"]["policy_name"] == "user1_policy" and u["admin"]["policy_name"] is None and u["admin"]["role"] == "admin"


def test_assign_and_change_policy(client, admin_h):
    create(client, admin_h)
    r = client.put("/api/users/user1/policy", headers=admin_h, json={"policy_name": "p_test"})
    assert r.status_code == 200 and r.json() == {"user_name": "user1", "policy_name": "p_test"}
    assert users(client, admin_h)["user1"]["policy_name"] == "p_test"
    assert client.get("/api/policies/p_test", headers=admin_h).json()["assigned_users"] == ["user1"]
    assert client.get("/api/policies/user1_policy", headers=admin_h).json()["assigned_users"] == []
    # still exactly one users row, and login credentials/role are untouched
    conn = sqlite3.connect(config.SQLITE_PATH)
    assert conn.execute("SELECT COUNT(*) FROM users WHERE user_name='user1'").fetchone()[0] == 1
    conn.close()
    assert client.post("/api/auth/login", json={"username": "user1", "password": "User1@12345"}).json()["user"]["role"] == "user"


def test_unassign_policy(client, admin_h):
    assert client.put("/api/users/user1/policy", headers=admin_h, json={"policy_name": None}).status_code == 200
    assert users(client, admin_h)["user1"]["policy_name"] is None
    assert client.delete("/api/policies/user1_policy", headers=admin_h).status_code == 204  # now unused


def test_assign_nonexistent_policy_404(client, admin_h):
    r = client.put("/api/users/user1/policy", headers=admin_h, json={"policy_name": "nope"})
    assert r.status_code == 404
    assert users(client, admin_h)["user1"]["policy_name"] == "user1_policy"  # unchanged


def test_assign_nonexistent_user_404(client, admin_h):
    assert client.put("/api/users/ghost/policy", headers=admin_h, json={"policy_name": "user1_policy"}).status_code == 404


def test_assign_bad_body_422(client, admin_h):
    assert client.put("/api/users/user1/policy", headers=admin_h, json={"policy": "x"}).status_code == 422


# ---- Authorization -----------------------------------------------------------
CALLS = [
    ("GET", "/api/policies", None),
    ("GET", "/api/policies/user1_policy", None),
    ("POST", "/api/policies", {"policy_name": "evil", "rules": [RULE_EMAIL]}),
    ("PUT", "/api/policies/user1_policy", {"rules": [RULE_EMAIL]}),
    ("DELETE", "/api/policies/user2_policy", None),
    ("GET", "/api/users", None),
    ("PUT", "/api/users/user1/policy", {"policy_name": None}),
]


@pytest.mark.parametrize("method,path,body", CALLS)
def test_no_token_401(client, method, path, body):
    assert client.request(method, path, json=body).status_code == 401


@pytest.mark.parametrize("method,path,body", CALLS)
def test_normal_user_403(client, user1_h, method, path, body):
    assert client.request(method, path, json=body, headers=user1_h).status_code == 403
    # x-user must not help either
    assert client.request(method, path, json=body, headers={**user1_h, "X-User": "admin"}).status_code == 403


def test_normal_user_changes_nothing(client, admin_h, user1_h):
    for method, path, body in CALLS:
        client.request(method, path, json=body, headers=user1_h)
    assert len(client.get("/api/policies/user1_policy", headers=admin_h).json()["rules"]) == 6
    assert "evil" not in [p["policy_name"] for p in client.get("/api/policies", headers=admin_h).json()]
    assert users(client, admin_h)["user1"]["policy_name"] == "user1_policy"


# ---- Effect on the existing user -> policy -> anonymizer flow ------------------
@pytest.fixture
def fake_anonymizer(monkeypatch):
    """Stand-in for the gRPC anonymizer that records the policy_map the proxy sends to it."""
    import app as proxy_app

    sent = []

    class Channel:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    class Stub:
        def __init__(self, channel):
            pass

        async def AnonymizeObject(self, request):
            sent.append({r.entityType: r.operatorName for r in request.policy_map})
            return proxy_app.an_pb2.AnonymizeObjectResponse(updatedObjectData=b"ANONYMIZED", objectLength=10)

    async def no_analysis(bucket, key):
        return None

    monkeypatch.setattr(proxy_app.grpc.aio, "insecure_channel", lambda url: Channel())
    monkeypatch.setattr(proxy_app.an_pb2_grpc, "PIIAnonymizerServiceStub", Stub)
    monkeypatch.setattr(proxy_app, "run_pii_analysis", no_analysis)
    return sent


def test_policy_changes_apply_to_next_get(client, admin_h, user1_h, fake_anonymizer):
    client.put("/pol-bucket/doc.txt", headers=admin_h, content=b"original")
    get = lambda h: client.get("/pol-bucket/doc.txt", headers=h)

    assert get(user1_h).content == b"ANONYMIZED"
    assert len(fake_anonymizer[-1]) == 6 and fake_anonymizer[-1]["PERSON"] == "replace"

    # edit the rules of the assigned policy -> very next GET uses them
    client.put("/api/policies/user1_policy", headers=admin_h, json={"rules": [RULE_SSN]})
    get(user1_h)
    assert fake_anonymizer[-1] == {"US_SSN": "redact"}

    # switch the user to another policy -> very next GET uses that one
    client.put("/api/users/user1/policy", headers=admin_h, json={"policy_name": "user2_policy"})
    get(user1_h)
    assert fake_anonymizer[-1]["CREDIT_CARD"] == "mask" and "US_SSN" in fake_anonymizer[-1] and "PERSON" not in fake_anonymizer[-1]

    # unassign -> no policy -> original bytes, anonymizer not called
    calls = len(fake_anonymizer)
    client.put("/api/users/user1/policy", headers=admin_h, json={"policy_name": None})
    assert get(user1_h).content == b"original" and len(fake_anonymizer) == calls


def test_new_policy_assigned_to_user_is_used(client, admin_h, user1_h, fake_anonymizer):
    client.put("/pol-bucket/doc2.txt", headers=admin_h, content=b"original")
    create(client, admin_h, rules=[RULE_CARD])
    client.put("/api/users/user1/policy", headers=admin_h, json={"policy_name": "p_test"})
    assert client.get("/pol-bucket/doc2.txt", headers=user1_h).content == b"ANONYMIZED"
    assert fake_anonymizer[-1] == {"CREDIT_CARD": "mask"}
    # the saved mask params reach the anonymizer message intact
    import app as proxy_app
    assert proxy_app._policy_messages([{"entity_type": "CREDIT_CARD", "operator_name": "mask",
                                        "operator_params": RULE_CARD["operator_params"]}])[0].operatorParams["chars_to_mask"] == 12


def test_llm_uses_edited_policy(client, admin_h, user1_h, monkeypatch):
    import app as proxy_app

    seen = []

    async def fake_protect(content, policy):
        seen.append([r["entity_type"] for r in policy.rules])  # EffectivePolicy: the caller's own rules
        return {"text": content, "entities": []}

    monkeypatch.setattr(proxy_app, "_protect_text", fake_protect)
    monkeypatch.setattr(proxy_app, "_call_ollama", lambda payload: {"model": "llama3.2", "message": {"role": "assistant", "content": "ok"}})
    body = {"provider": "ollama", "model": "llama3.2", "messages": [{"role": "user", "content": "hi"}]}
    client.post("/api/llm/chat", json=body, headers=user1_h)
    client.put("/api/policies/user1_policy", headers=admin_h, json={"rules": [RULE_SSN]})
    client.post("/api/llm/chat", json=body, headers=user1_h)
    assert seen[0][0] == "PERSON" and seen[1] == ["US_SSN"]
