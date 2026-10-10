import sqlite3
from datetime import datetime, timedelta, timezone

import jwt
import pytest

import config
import init_db
from security import hash_password, verify_password
from conftest import login


def _token(claims, secret=None, alg="HS256"):
    return jwt.encode(claims, secret or config.JWT_SECRET, algorithm=alg)


def _claims(sub="user1", role="user", delta=timedelta(minutes=5)):
    now = datetime.now(timezone.utc)
    return {"sub": sub, "role": role, "iat": now, "exp": now + delta}


# ---- Login -------------------------------------------------------------------
def test_login_success_returns_jwt_with_claims(client):
    r = login(client, "user1", "User1@12345")
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer" and body["expires_in"] == 3600
    assert body["user"] == {"username": "user1", "role": "user"}
    claims = jwt.decode(body["access_token"], config.JWT_SECRET, algorithms=["HS256"])
    assert claims["sub"] == "user1" and claims["role"] == "user"
    assert claims["exp"] > claims["iat"]


def test_login_admin_role(client):
    assert login(client, "admin", "Admin@12345").json()["user"]["role"] == "admin"


@pytest.mark.parametrize("user,pw", [("user1", "wrong"), ("nobody", "User1@12345"), ("user1", "user1@12345")])
def test_login_invalid_credentials_401_generic(client, user, pw):
    r = login(client, user, pw)
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid username or password"  # same message: no user enumeration


def test_login_missing_fields_422(client):
    assert client.post("/api/auth/login", json={"username": "user1"}).status_code == 422


def test_passwords_are_hashed_in_db():
    conn = sqlite3.connect(config.SQLITE_PATH)
    rows = conn.execute("SELECT user_name, password_hash FROM users").fetchall()
    conn.close()
    assert len(rows) == 3
    for name, h in rows:
        assert h.startswith("pbkdf2_sha256$")
        assert all(pw not in h for _, _, _, pw in init_db.DEMO_USERS)


def test_hash_is_salted_and_verifies():
    a, b = hash_password("s3cret!"), hash_password("s3cret!")
    assert a != b
    assert verify_password("s3cret!", a) and not verify_password("S3cret!", a)
    assert not verify_password("x", "garbage") and not verify_password("x", None)


# ---- JWT validation ----------------------------------------------------------
def test_no_token_401(client):
    r = client.get("/api/auth/me")
    assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"


def test_valid_token_identity(client, user1_h):
    assert client.get("/api/auth/me", headers=user1_h).json() == {"username": "user1", "role": "user"}


def test_malformed_token_401(client):
    assert client.get("/api/auth/me", headers={"Authorization": "Bearer not.a.jwt"}).status_code == 401


def test_non_bearer_scheme_401(client):
    assert client.get("/api/auth/me", headers={"Authorization": "Basic dXNlcjE6cGFzcw=="}).status_code == 401


def test_expired_token_401(client):
    t = _token(_claims(delta=timedelta(minutes=-1)))
    r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {t}"})
    assert r.status_code == 401 and "expired" in r.json()["detail"].lower()


def test_wrong_signature_401(client):
    t = _token(_claims(), secret="a-different-secret-that-is-long-enough-1234")
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {t}"}).status_code == 401


def test_alg_none_token_401(client):
    t = jwt.encode(_claims(), key=None, algorithm="none")
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {t}"}).status_code == 401


def test_token_without_exp_401(client):
    t = _token({"sub": "user1", "role": "user"})
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {t}"}).status_code == 401


def test_token_with_unknown_role_401(client):
    t = _token(_claims(role="superuser"))
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {t}"}).status_code == 401


# ---- RBAC --------------------------------------------------------------------
def test_user_cannot_upload_403(client, user1_h):
    r = client.put("/rbac-bucket/a.txt", content=b"hello", headers=user1_h)
    assert r.status_code == 403


def test_user_cannot_delete_403(client, user1_h):
    assert client.delete("/rbac-bucket/a.txt", headers=user1_h).status_code == 403


def test_admin_can_upload_and_delete(client, admin_h, monkeypatch):
    import app as proxy_app

    async def no_analysis(bucket, key):  # skip loading spaCy/Presidio in unit tests
        return None

    monkeypatch.setattr(proxy_app, "run_pii_analysis", no_analysis)
    assert client.put("/rbac-bucket/b.txt", content=b"hello", headers=admin_h).status_code == 200
    assert client.delete("/rbac-bucket/b.txt", headers=admin_h).status_code == 204


def test_object_routes_require_token(client):
    assert client.get("/rbac-bucket/b.txt").status_code == 401
    assert client.put("/rbac-bucket/b.txt", content=b"x").status_code == 401
    assert client.delete("/rbac-bucket/b.txt").status_code == 401


def test_admin_gets_original_user_gets_policy(client, admin_h, user1_h, monkeypatch):
    import app as proxy_app

    async def no_analysis(bucket, key):
        return None

    seen = []

    async def spy(path, username, response):
        seen.append(username)
        return response

    monkeypatch.setattr(proxy_app, "run_pii_analysis", no_analysis)
    monkeypatch.setattr(proxy_app, "post_process_get_response", spy)
    client.put("/rbac-bucket/c.txt", content=b"hello", headers=admin_h)
    assert client.get("/rbac-bucket/c.txt", headers=user1_h).status_code == 200
    assert client.get("/rbac-bucket/c.txt", headers=admin_h).status_code == 200
    assert seen == ["user1", "admin"]


# ---- X-User impersonation ----------------------------------------------------
def test_x_user_header_alone_is_rejected(client):
    assert client.get("/demo-bucket/sample.txt", headers={"X-User": "admin"}).status_code == 401
    assert client.get("/api/auth/me", headers={"X-User": "admin"}).status_code == 401


def test_x_user_cannot_override_token_identity(client, user1_h):
    r = client.get("/api/auth/me", headers={**user1_h, "X-User": "admin"})
    assert r.json() == {"username": "user1", "role": "user"}


def test_x_user_cannot_escalate_privileges(client, user1_h):
    r = client.put("/rbac-bucket/d.txt", content=b"x", headers={**user1_h, "X-User": "admin"})
    assert r.status_code == 403


def test_policy_lookup_uses_jwt_user_not_x_user(client, user1_h, admin_h, monkeypatch):
    import app as proxy_app

    async def no_analysis(bucket, key):
        return None

    seen = []

    async def spy(path, username, response):
        seen.append(username)
        return response

    monkeypatch.setattr(proxy_app, "run_pii_analysis", no_analysis)
    monkeypatch.setattr(proxy_app, "post_process_get_response", spy)
    client.put("/rbac-bucket/e.txt", content=b"hi", headers=admin_h)
    client.get("/rbac-bucket/e.txt", headers={**user1_h, "X-User": "admin"})
    assert seen == ["user1"]


# ---- LLM endpoint ------------------------------------------------------------
def test_llm_requires_token(client):
    body = {"provider": "ollama", "model": "llama3.2", "messages": [{"role": "user", "content": "hi"}]}
    assert client.post("/api/llm/chat", json=body).status_code == 401
    assert client.post("/api/llm/chat", json=body, headers={"X-User": "admin"}).status_code == 401


def test_llm_uses_jwt_identity_not_x_user(client, user1_h, monkeypatch):
    import app as proxy_app

    loaded = []

    async def fake_load(user):
        loaded.append(user)
        return []

    async def fake_protect(content, policy):
        return {"text": content, "entities": []}

    monkeypatch.setattr(proxy_app, "_load_user_policy", fake_load)
    monkeypatch.setattr(proxy_app, "_protect_text", fake_protect)
    monkeypatch.setattr(proxy_app, "_call_ollama", lambda payload: {"model": "llama3.2", "message": {"role": "assistant", "content": "ok"}, "done": True})
    body = {"provider": "ollama", "model": "llama3.2", "messages": [{"role": "user", "content": "hi"}]}
    r = client.post("/api/llm/chat", json=body, headers={**user1_h, "X-User": "admin"})
    assert r.status_code == 200
    assert loaded == ["user1"] and r.json()["pii_guard"]["policy_user"] == "user1"
