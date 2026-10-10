import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Isolated DB/storage + a fixed secret. Must be set BEFORE config/app are imported.
_TMP = tempfile.mkdtemp(prefix="pii_auth_tests_")
os.environ["SQLITE_PATH"] = os.path.join(_TMP, "test.db")
os.environ["STORAGE_ROOT"] = os.path.join(_TMP, "storage")
os.environ["JWT_SECRET"] = "test-secret-key-that-is-at-least-32-characters-long"
os.environ["JWT_EXPIRE_MINUTES"] = "60"

for p in ("anonymizer", "common", "consumer_analyzer/pii_analyser", "consumer_analyzer/consumer", "proxy-server", "database", "."):
    full = str(ROOT / p)
    if full not in sys.path:
        sys.path.insert(0, full)

import pytest  # noqa: E402

import init_db  # noqa: E402


@pytest.fixture(scope="session")
def client():
    from fastapi.testclient import TestClient

    init_db.create_tables()
    import app as proxy_app

    with TestClient(proxy_app.app) as c:
        yield c


def login(client, username, password):
    return client.post("/api/auth/login", json={"username": username, "password": password})


def bearer(client, username, password):
    r = login(client, username, password)
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="session")
def admin_h(client):
    return bearer(client, "admin", "Admin@12345")


@pytest.fixture(scope="session")
def user1_h(client):
    return bearer(client, "user1", "User1@12345")
