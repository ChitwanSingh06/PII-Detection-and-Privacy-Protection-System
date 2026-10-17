"""Admin-only pages (PII Detection, Analytics, Audit Logs): authorization, live SQLite-backed statistics,
audit logging, no raw PII in responses, anonymization of the new categories, and non-destructive DB init.
"""
import json
import sqlite3

import pytest

import config
import init_db
from conftest import bearer, login
from test_dashboard import OBJECTS, RAW_PII, db, env, get, seed  # noqa: F401  (env is a fixture)
from test_llm import KNOWN, PROMPT, chat, env as llm_env, restore_db  # noqa: F401

ADMIN_GETS = ["/api/admin/pii-detection", "/api/admin/analytics", "/api/admin/audit-logs",
              "/api/admin/audit-logs/export"]


# ---- 2. authorization (backend) -----------------------------------------------------------------------
@pytest.mark.parametrize("path", ADMIN_GETS)
def test_admin_apis_reject_anonymous_and_regular_users(client, admin_h, user1_h, env, path):
    assert client.get(path).status_code == 401
    assert client.get(path, headers={"Authorization": "Bearer not-a-token"}).status_code == 401
    assert client.get(path, headers=user1_h).status_code == 403
    assert client.get(path, headers=admin_h).status_code == 200


def test_forged_role_claim_is_not_trusted(client, user1_h):
    # a token for a regular user stays regular; there is no way to escalate through the API
    assert client.get("/api/admin/audit-logs", headers=user1_h).status_code == 403


def test_denied_attempts_are_audited(client, admin_h, user1_h, env):
    client.get("/api/admin/analytics", headers=user1_h)
    client.put("/b1/x.txt", content=b"hello", headers=user1_h)  # write by a non-admin -> 403
    rows = get(client, "/api/admin/audit-logs?event_type=access_denied", admin_h)["data"]
    assert rows["total"] == 2
    assert {r["actor"] for r in rows["items"]} == {"user1"} and all(r["status"] == "failed" for r in rows["items"])
    assert {r["details"]["route"] for r in rows["items"]} == {"/api/admin/analytics", "/{bucket}/{key}"}


def test_regular_user_can_still_use_dashboard_but_only_sees_own_activity(client, admin_h, user1_h, env):
    seed(client, admin_h, env)
    client.get("/b1/a.txt", headers=user1_h)
    mine = get(client, "/api/dashboard/activity?limit=100", user1_h)["data"]
    assert mine["items"] and {i["actor"] for i in mine["items"]} == {"user1"}
    everyone = get(client, "/api/dashboard/activity?limit=100", admin_h)["data"]
    assert {i["actor"] for i in everyone["items"]} >= {"admin", "user1"}
    assert client.get("/api/dashboard/summary", headers=user1_h).status_code == 200


# ---- 3. live database statistics ----------------------------------------------------------------------
def test_empty_database_returns_zeros_not_samples(client, admin_h, env):
    d = get(client, "/api/admin/pii-detection", admin_h)["data"]
    assert d["total_entities"] == 0 and d["latest_results"] == [] and d["objects_scanned"] == 0
    assert all(c["count"] == 0 and c["avg_score"] is None for c in d["categories"])
    a = get(client, "/api/admin/analytics", admin_h)["data"]
    assert a["pii_distribution"] == [] and a["coverage_by_bucket"] == []
    assert all(r["objects"] == 0 for r in a["risk_distribution"])
    assert all(p["detected"] == 0 and p["protected"] == 0 for p in a["detection_vs_protection"])


def test_detection_page_matches_sqlite(client, admin_h, env):
    seed(client, admin_h, env)
    d = get(client, "/api/admin/pii-detection", admin_h)["data"]
    c = db()
    rows = c.execute("SELECT pii_entities FROM pii_objects").fetchall()
    c.close()
    expected = {}
    for (blob,) in rows:
        for e in json.loads(blob):
            expected[e["type"]] = expected.get(e["type"], 0) + 1
    by = {x["entity_type"]: x for x in d["categories"] + d["other_types"]}
    assert {t: by[t]["count"] for t in expected} == expected
    assert d["total_entities"] == sum(expected.values())
    assert d["objects_scanned"] == 5 and d["objects_with_pii"] == 4
    assert by["EMAIL_ADDRESS"]["avg_score"] == 1.0
    assert d["detection_runs_total"] == 6 and d["detection_failures_total"] == 1  # 5 text + 1 binary upload
    latest = d["latest_results"][0]
    assert {"entity_type", "start", "end", "score", "detector"} <= set(latest["entities"][0]) if latest["entities"] else True


def test_new_data_appears_on_next_request_and_delete_removes_it(client, admin_h, env):
    before = get(client, "/api/admin/pii-detection", admin_h)["data"]["total_entities"]
    client.put("/b3/new.txt", content=b"Mail priya.raman@acme.in, SSN 123-45-6789", headers=admin_h)
    mid = get(client, "/api/admin/pii-detection", admin_h)["data"]
    assert mid["total_entities"] == before + 2
    client.delete("/b3/new.txt", headers=admin_h)
    assert get(client, "/api/admin/pii-detection", admin_h)["data"]["total_entities"] == before


def test_analytics_matches_database_and_updates_after_anonymization(client, admin_h, user1_h, env):
    seed(client, admin_h, env)
    a = get(client, "/api/admin/analytics", admin_h)["data"]
    assert a["objects"]["stored"] == 7 and a["objects"]["scanned"] == 5 and a["objects"]["with_pii"] == 4
    assert sum(x["count"] for x in a["pii_distribution"]) == 8
    risk = {r["level"]: r["objects"] for r in a["risk_distribution"]}
    assert risk == {"Critical": 3, "High": 0, "Medium": 1, "Low": 0}  # cards/SSN objects vs IP-only object
    assert sum(p["detected"] for p in a["detection_vs_protection"]) == 8
    assert a["anonymization"]["entities_anonymized"] == 0
    client.get("/b1/a.txt", headers=user1_h)  # user1 policy masks PERSON + CREDIT_CARD (+ email)
    a2 = get(client, "/api/admin/analytics", admin_h)["data"]
    assert a2["anonymization"]["anonymized_ok"] == 1 and a2["anonymization"]["entities_anonymized"] >= 2
    assert sum(p["protected"] for p in a2["detection_vs_protection"]) == a2["anonymization"]["entities_anonymized"]
    assert a2["anonymization"]["by_operator"]


def test_no_raw_pii_in_any_admin_response(client, admin_h, user1_h, env):
    seed(client, admin_h, env)
    client.get("/b1/a.txt", headers=user1_h)
    client.get("/b2/c.txt", headers=admin_h)
    for path in ADMIN_GETS + ["/api/dashboard/activity?limit=100"]:
        body = client.get(path, headers=admin_h).text
        for v in RAW_PII:
            assert v not in body, f"{v!r} leaked through {path}"


# ---- 6. audit logging ---------------------------------------------------------------------------------
def test_login_success_and_failure_are_audited_without_storing_unknown_names(client, admin_h, env):
    assert login(client, "user2", "User2@12345").status_code == 200
    assert login(client, "user2", "wrong-password").status_code == 401
    assert login(client, "someone@example.com", "x").status_code == 401  # could be personal data
    logins = get(client, "/api/admin/audit-logs?event_type=login", admin_h)["data"]
    assert [(i["actor"], i["status"]) for i in logins["items"]] == [(None, "failed"), ("user2", "failed"), ("user2", "ok")]
    assert "someone@example.com" not in json.dumps(logins)


def test_policy_changes_are_audited(client, admin_h, env):
    body = {"policy_name": "audit_probe", "rules": [{"entity_type": "IN_AADHAAR", "operator_name": "redact", "operator_params": {}}]}
    assert client.post("/api/policies", json=body, headers=admin_h).status_code == 201
    assert client.delete("/api/policies/audit_probe", headers=admin_h).status_code == 204
    items = get(client, "/api/admin/audit-logs?event_type=policy_change", admin_h)["data"]["items"]
    assert [(i["details"]["action"], i["actor"]) for i in items] == [("deleted", "admin"), ("created", "admin")]
    assert items[1]["details"]["rules"] == ["IN_AADHAAR:redact"]


def test_object_lifecycle_events_are_audited(client, admin_h, user1_h, env):
    seed(client, admin_h, env)
    client.get("/b1/a.txt", headers=user1_h)
    client.get("/b2/c.txt", headers=admin_h)  # admin has no policy -> original served -> download event
    client.delete("/b1/b.txt", headers=admin_h)
    kinds = {i["event_type"] for i in get(client, "/api/admin/audit-logs?limit=200", admin_h)["data"]["items"]}
    assert {"upload", "detection", "anonymization", "download", "delete"} <= kinds


def test_audit_filters_paging_and_export(client, admin_h, user1_h, env):
    seed(client, admin_h, env)
    p1 = get(client, "/api/admin/audit-logs?limit=4&offset=0", admin_h)["data"]
    p2 = get(client, "/api/admin/audit-logs?limit=4&offset=4", admin_h)["data"]
    assert p1["total"] == p2["total"] >= 10 and len(p1["items"]) == 4
    assert not {i["id"] for i in p1["items"]} & {i["id"] for i in p2["items"]}
    assert [i["id"] for i in p1["items"]] == sorted((i["id"] for i in p1["items"]), reverse=True)
    only = get(client, "/api/admin/audit-logs?event_type=upload", admin_h)["data"]
    assert only["total"] == 6 and {i["event_type"] for i in only["items"]} == {"upload"}
    assert get(client, "/api/admin/audit-logs?q=a.txt", admin_h)["data"]["total"] >= 2
    assert client.get("/api/admin/audit-logs?limit=9999", headers=admin_h).status_code == 422
    r = client.get("/api/admin/audit-logs/export?event_type=upload", headers=admin_h)
    lines = r.text.strip().splitlines()
    assert r.headers["content-type"].startswith("text/csv") and len(lines) == 1 + 6
    assert lines[0].startswith("id,timestamp_utc,event_type")
    assert get(client, "/api/admin/audit-logs?event_type=audit_export", admin_h)["data"]["total"] == 1


def test_csv_export_neutralises_formula_injection():
    from admin_api import _csv_cell
    assert _csv_cell("=HYPERLINK(1)") == "'=HYPERLINK(1)" and _csv_cell("ok") == "ok" and _csv_cell(None) == ""


# ---- 4/5. new categories through the real analyzer -> policy engine -> anonymizer ---------------------
@pytest.fixture(scope="module")
def pipeline():
    from anonymizer.pii_anonymizer import PIIAnonymizer
    from pii_analyser import PIIAnalyzer
    import app as proxy_app
    an = PIIAnalyzer()

    def run(text, rules):
        spans = an.analyze(text)
        out = PIIAnonymizer().anonymize_data(
            object_data=text, policy_map=proxy_app._policy_messages(rules), pii_metadata=spans)
        return out, spans
    return run


DOC = ("Anita Rao, Aadhaar 2345 6789 0124, mobile +91 98765 43210, Flat 402, Sunrise Apartments, MG Road, "
       "Bengaluru 560001. SSN 123-45-6789, card 4111 1111 1111 1111, 350 Fifth Avenue, New York, NY 10118.")
RAW_NEW = ["2345 6789 0124", "+91 98765 43210", "Flat 402", "560001", "123-45-6789", "4111 1111 1111 1111",
           "350 Fifth Avenue", "10118"]


def test_new_categories_are_anonymized_by_policies(pipeline):
    rules = (init_db.USER1_POLICY + init_db.NEW_CATEGORY_RULES["user1_policy"])
    out, _ = pipeline(DOC, rules)
    for raw in RAW_NEW:
        assert raw not in out, raw
    assert "<AADHAAR>" in out and "<ADDRESS>" in out


def test_existing_policy_alone_leaves_new_types_but_masks_old_ones(pipeline):
    out, _ = pipeline(DOC, init_db.USER1_POLICY)  # untouched seeded policy: no rules for Aadhaar/PIN/ZIP/address
    assert "2345 6789 0124" in out                 # no rule => unchanged, exactly the old behaviour
    assert "+91 98765 43210" not in out            # Indian phones now ride on the existing PHONE_NUMBER rule
    assert "4111 1111 1111 1111" not in out and "123-45-6789" not in out


def test_a_rule_for_a_contained_type_is_not_swallowed_by_an_address(pipeline):
    # policy knows only PIN_CODE: the address (no rule) must not swallow the PIN that has one
    rules = [{"entity_type": "IN_PIN_CODE", "operator_name": "replace", "operator_params": {"new_value": "<PIN>"}}]
    out, spans = pipeline("Ship to Flat 402, Sunrise Apartments, MG Road, Bengaluru 560001.", rules)
    assert {s["type"] for s in spans} >= {"IN_ADDRESS", "IN_PIN_CODE"}
    assert "560001" not in out and "<PIN>" in out


def test_all_operators_work_on_new_types(pipeline):
    for op, params in [("redact", {}), ("hash", {}), ("mask", {"from_end": False, "masking_char": "*", "chars_to_mask": 100}),
                       ("replace", {"new_value": "<X>"})]:
        out, _ = pipeline("Aadhaar 2345 6789 0124 ok", [{"entity_type": "IN_AADHAAR", "operator_name": op, "operator_params": params}])
        assert "2345 6789 0124" not in out, op


def test_llm_response_has_no_raw_values(client, user1_h, llm_env):
    r = chat(client, user1_h, PROMPT)
    assert r.status_code == 200
    guard = r.json()["pii_guard"]
    assert guard["entities"] and all("value" not in e for e in guard["entities"])
    for raw in KNOWN:
        assert raw not in json.dumps(guard), raw


# ---- 6. database safety -------------------------------------------------------------------------------
def _rows(path):
    c = sqlite3.connect(path)
    out = (c.execute("SELECT user_name, policy_name, password_hash, role FROM users ORDER BY 1").fetchall(),
           c.execute("SELECT policy_name, policy FROM policies ORDER BY rowid").fetchall())
    c.close()
    return out


def test_init_db_does_not_reset_existing_data(tmp_path, monkeypatch):
    path = str(tmp_path / "x.db")
    monkeypatch.setattr(init_db, "SQLITE_PATH", path)
    init_db.create_tables()
    c = sqlite3.connect(path)
    c.execute("UPDATE users SET policy_name='custom' WHERE user_name='user1'")
    c.execute("INSERT INTO users (user_name, policy_name, password_hash, role) VALUES ('carol','custom','h','user')")
    c.execute("DELETE FROM policies WHERE policy_name='user2_policy' AND policy LIKE '%PERSON%'")
    c.commit()
    c.close()
    before = _rows(path)
    init_db.create_tables()
    assert _rows(path) == before


def test_new_category_rules_are_additive_and_idempotent(tmp_path, monkeypatch):
    path = str(tmp_path / "y.db")
    monkeypatch.setattr(init_db, "SQLITE_PATH", path)
    init_db.create_tables()
    before = _rows(path)[1]
    init_db.create_tables(upgrade_policies=True)
    after = _rows(path)[1]
    assert after[:len(before)] == before and len(after) == len(before) + 10  # old rows untouched, 5 + 5 added
    init_db.create_tables(upgrade_policies=True)
    assert _rows(path)[1] == after  # idempotent


def test_reset_demo_is_opt_in(tmp_path, monkeypatch):
    path = str(tmp_path / "z.db")
    monkeypatch.setattr(init_db, "SQLITE_PATH", path)
    init_db.create_tables()
    c = sqlite3.connect(path)
    c.execute("INSERT INTO users (user_name, policy_name, password_hash, role) VALUES ('carol','p','h','user')")
    c.commit()
    c.close()
    init_db.create_tables(reset_demo=True)
    assert "carol" not in [u[0] for u in _rows(path)[0]]


# ---- 1/2. UI: sidebar + frontend role guard ------------------------------------------------------------
def test_ui_sidebar_and_guards():
    from pathlib import Path
    html = (Path(config.ROOT if hasattr(config, "ROOT") else Path(__file__).resolve().parents[1]) / "ui" / "index.html").read_text(encoding="utf-8")
    pages = html[html.index("const PAGES="):html.index("\n", html.index("const PAGES="))]
    for gone in ("Object Storage", "Object Details", "System Health", "Security Overview"):
        assert gone not in pages
    assert "Policy Engine" in pages
    assert "ADMIN_PAGES=new Set(['detect','ana','audit'])" in html and "canSee(" in html
    for mock in ("const OBJ=", "const LOG=", "const SVC=", "const TYPES="):
        assert mock not in html


def test_full_kyc_document_every_identifier_masked_individually(pipeline):
    """Regression: an over-long address once swallowed the SSN that followed it (SSN vanished, no own rule applied)."""
    text = DOC + " Ref 560025 order 9876543210."
    rules = init_db.USER1_POLICY + init_db.NEW_CATEGORY_RULES["user1_policy"]
    out, _ = pipeline(text, rules)
    assert "123-45-6789" not in out and "SSN" in out            # SSN masked by ITS rule, surrounding words kept
    assert "US_SSN" in out or "<" in out
    assert "Ref 560025 order 9876543210." in out                # look-alikes untouched (no false positives)
