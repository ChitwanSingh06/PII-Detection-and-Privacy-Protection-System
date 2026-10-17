<<<<<<< HEAD
import argparse
=======
>>>>>>> origin/main
import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import SQLITE_PATH  # noqa: E402
from security import hash_password  # noqa: E402

USER1_POLICY = [
    {
        "entity_type": "PERSON",
        "operator_name": "replace",
        "operator_params": {"new_value": "PERSON"},
    },
    {
        "entity_type": "CREDIT_CARD",
        "operator_name": "mask",
        "operator_params": {"from_end": False, "masking_char": "*", "chars_to_mask": 10},
    },
    {
        "entity_type": "EMAIL_ADDRESS",
        "operator_name": "replace",
        "operator_params": {"new_value": "<EMAIL>"},
    },
    {
        "entity_type": "PHONE_NUMBER",
        "operator_name": "replace",
        "operator_params": {"new_value": "PHONE_NUMBER"},
    },
    {
        "entity_type": "US_SSN",
        "operator_name": "redact",
        "operator_params": {},
    },
    {
        "entity_type": "US_BANK_NUMBER",
        "operator_name": "mask",
        "operator_params": {"from_end": False, "masking_char": "*", "chars_to_mask": 10},
    },
]

USER2_POLICY = [
    {
        "entity_type": "CREDIT_CARD",
        "operator_name": "mask",
        "operator_params": {"from_end": False, "masking_char": "*", "chars_to_mask": 10},
    },
    {
        "entity_type": "EMAIL_ADDRESS",
        "operator_name": "mask",
        "operator_params": {"from_end": False, "masking_char": "*", "chars_to_mask": 100},
    },
    {
        "entity_type": "PHONE_NUMBER",
        "operator_name": "replace",
        "operator_params": {"new_value": "<PHONE>"},
    },
    {
        "entity_type": "US_SSN",
        "operator_name": "redact",
        "operator_params": {},
    },
    {
        "entity_type": "US_BANK_NUMBER",
        "operator_name": "mask",
        "operator_params": {"from_end": False, "masking_char": "*", "chars_to_mask": 10},
    },
]

<<<<<<< HEAD
# Rules for the Indian + US categories (Aadhaar, PIN, addresses, ZIP). They are NOT part of the default seed, so
# existing/seeded policies stay exactly as they were. Opt in with
#   python database/init_db.py --add-new-category-rules
# which is additive: a type that already has a rule keeps it, and nothing is modified or deleted.
NEW_CATEGORY_RULES = {
    "user1_policy": [
        {"entity_type": "IN_AADHAAR", "operator_name": "replace", "operator_params": {"new_value": "<AADHAAR>"}},
        {"entity_type": "IN_PIN_CODE", "operator_name": "replace", "operator_params": {"new_value": "<PIN_CODE>"}},
        {"entity_type": "IN_ADDRESS", "operator_name": "replace", "operator_params": {"new_value": "<ADDRESS>"}},
        {"entity_type": "US_ADDRESS", "operator_name": "replace", "operator_params": {"new_value": "<ADDRESS>"}},
        {"entity_type": "US_ZIP_CODE", "operator_name": "replace", "operator_params": {"new_value": "<ZIP_CODE>"}},
    ],
    "user2_policy": [
        {"entity_type": "IN_AADHAAR", "operator_name": "redact", "operator_params": {}},
        {"entity_type": "IN_PIN_CODE", "operator_name": "mask",
         "operator_params": {"from_end": False, "masking_char": "*", "chars_to_mask": 100}},
        {"entity_type": "IN_ADDRESS", "operator_name": "redact", "operator_params": {}},
        {"entity_type": "US_ADDRESS", "operator_name": "redact", "operator_params": {}},
        {"entity_type": "US_ZIP_CODE", "operator_name": "mask",
         "operator_params": {"from_end": False, "masking_char": "*", "chars_to_mask": 100}},
    ],
}

=======
>>>>>>> origin/main
# Demo accounts for local testing ONLY. Change or remove them before any real use.
# (user_name, role, policy_name, password). Admin has no policy, so GETs return the original file.
DEMO_USERS = [
    ("admin", "admin", "", "Admin@12345"),
    ("user1", "user", "user1_policy", "User1@12345"),
    ("user2", "user", "user2_policy", "User2@12345"),
]


def ensure_auth_columns(cur):
    """Add the auth columns to a users table created before authentication existed."""
    existing = {row[1] for row in cur.execute("PRAGMA table_info(users)")}
    if "password_hash" not in existing:
        cur.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
    if "role" not in existing:
        cur.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")


<<<<<<< HEAD
def add_new_category_rules(cur):
    """Additive upgrade for existing databases: give the demo policies rules for the new categories.

    Only policies that already exist are touched, only entity types that have NO rule yet are added, and no
    existing row is modified or deleted. Returns the list of (policy_name, entity_type) added.
    """
    added = []
    for policy_name, rules in NEW_CATEGORY_RULES.items():
        rows = cur.execute("SELECT policy FROM policies WHERE policy_name = ?", (policy_name,)).fetchall()
        if not rows:
            continue
        have = {json.loads(r[0]).get("entity_type") for r in rows}
        for rule in rules:
            if rule["entity_type"] not in have:
                cur.execute("INSERT INTO policies (policy_name, policy) VALUES (?, ?)", (policy_name, json.dumps(rule)))
                added.append((policy_name, rule["entity_type"]))
    return added


def create_tables(reset_demo: bool = False, upgrade_policies: bool = False):
    """Create missing tables/columns and seed demo data WITHOUT touching existing rows.

    reset_demo=True restores the old behaviour (wipes users and policies, then re-seeds the demo data) and is
    only ever used when explicitly requested with --reset-demo.
    """
=======
def create_tables():
>>>>>>> origin/main
    db_path = Path(SQLITE_PATH)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS pii_objects (
            bucket_name TEXT NOT NULL,
            object_key TEXT NOT NULL,
            pii_entities TEXT,
            PRIMARY KEY (bucket_name, object_key)
        );
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            user_name TEXT NOT NULL,
            policy_name TEXT NOT NULL,
            password_hash TEXT,
            role TEXT NOT NULL DEFAULT 'user',
            PRIMARY KEY (user_name, policy_name)
        );
        """
    )
    ensure_auth_columns(cur)  # migrates databases created before authentication was added

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS policies (
            policy_name TEXT NOT NULL,
            policy TEXT NOT NULL
        );
        """
    )

    # Live Dashboard metrics (additive; the proxy also creates it on start). Counts and entity
    # types only - detected PII values are never stored here. Never cleared by this script.
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS dashboard_events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at   TEXT    NOT NULL,
            event_type   TEXT    NOT NULL,
            source       TEXT    NOT NULL DEFAULT 'object',
            actor        TEXT,
            bucket_name  TEXT,
            object_key   TEXT,
            status       TEXT    NOT NULL,
            entity_count INTEGER NOT NULL DEFAULT 0,
            details      TEXT,
            request_id   TEXT
        );
        """
    )
    # databases created before request_id existed: add the column in place (no rows touched)
    if "request_id" not in {row[1] for row in cur.execute("PRAGMA table_info(dashboard_events)")}:
        cur.execute("ALTER TABLE dashboard_events ADD COLUMN request_id TEXT")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_dashboard_events_created ON dashboard_events (created_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_dashboard_events_type ON dashboard_events (event_type, created_at)")
    cur.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_dashboard_events_request "
        "ON dashboard_events (request_id, event_type) WHERE request_id IS NOT NULL"
    )

<<<<<<< HEAD
    if reset_demo:
        cur.execute("DELETE FROM users")
        cur.execute("DELETE FROM policies")

    # Demo users: only the ones that do not exist yet (a password or policy assignment you changed is kept).
    existing_users = {r[0] for r in cur.execute("SELECT user_name FROM users")}
    seeded_users = []
    for user_name, role, policy_name, password in DEMO_USERS:
        if user_name not in existing_users:
            cur.execute(
                "INSERT INTO users (user_name, policy_name, password_hash, role) VALUES (?, ?, ?, ?)",
                (user_name, policy_name, hash_password(password), role),
            )
            seeded_users.append(user_name)

    # Demo policies: only when a policy of that name does not exist yet (an existing one is left as it is).
    existing_policies = {r[0] for r in cur.execute("SELECT DISTINCT policy_name FROM policies")}
    seeded_policies = []
    for name, rules in (("user1_policy", USER1_POLICY), ("user2_policy", USER2_POLICY)):
        if name in existing_policies:
            continue
        for rule in rules:
            cur.execute("INSERT INTO policies (policy_name, policy) VALUES (?, ?)", (name, json.dumps(rule)))
        seeded_policies.append(name)

    added = add_new_category_rules(cur) if upgrade_policies else []
=======
    cur.execute("DELETE FROM users")
    cur.execute("DELETE FROM policies")

    for user_name, role, policy_name, password in DEMO_USERS:
        cur.execute(
            "INSERT INTO users (user_name, policy_name, password_hash, role) VALUES (?, ?, ?, ?)",
            (user_name, policy_name, hash_password(password), role),
        )

    for rule in USER1_POLICY:
        cur.execute(
            "INSERT INTO policies (policy_name, policy) VALUES (?, ?)",
            ("user1_policy", json.dumps(rule)),
        )
    for rule in USER2_POLICY:
        cur.execute(
            "INSERT INTO policies (policy_name, policy) VALUES (?, ?)",
            ("user2_policy", json.dumps(rule)),
        )
>>>>>>> origin/main

    conn.commit()
    cur.close()
    conn.close()
<<<<<<< HEAD
    print(f"SQLite database ready at {db_path}")
    print(f"  demo users added:    {', '.join(seeded_users) or 'none (existing users kept)'}")
    print(f"  demo policies added: {', '.join(seeded_policies) or 'none (existing policies kept)'}")
    if upgrade_policies:
        print(f"  new-category rules added: {len(added)}" + "".join(f"\n    {p}: {t}" for p, t in added))
    elif not seeded_policies:
        print("  tip: run with --add-new-category-rules to add Aadhaar / PIN / address / ZIP rules to the demo policies")
    if reset_demo:
        print("  --reset-demo was given: users and policies were reset to the demo data")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create/upgrade the SQLite schema. Never deletes data by default.")
    parser.add_argument("--add-new-category-rules", action="store_true",
                        help="add rules for Aadhaar, PIN, addresses and ZIP to the existing demo policies (additive)")
    parser.add_argument("--reset-demo", action="store_true",
                        help="DESTRUCTIVE: wipe users and policies and re-seed the demo data")
    args = parser.parse_args()
    create_tables(reset_demo=args.reset_demo, upgrade_policies=args.add_new_category_rules)
=======
    print(f"SQLite tables created; demo users (admin, user1, user2) and sample policies seeded at {db_path}")


if __name__ == "__main__":
    create_tables()
>>>>>>> origin/main
