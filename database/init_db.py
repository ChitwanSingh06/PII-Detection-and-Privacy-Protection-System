import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import SQLITE_PATH  # noqa: E402

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


def create_tables():
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
            PRIMARY KEY (user_name, policy_name)
        );
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS policies (
            policy_name TEXT NOT NULL,
            policy TEXT NOT NULL
        );
        """
    )

    cur.execute("DELETE FROM users")
    cur.execute("DELETE FROM policies")

    cur.execute(
        "INSERT INTO users (user_name, policy_name) VALUES (?, ?)",
        ("user1", "user1_policy"),
    )
    cur.execute(
        "INSERT INTO users (user_name, policy_name) VALUES (?, ?)",
        ("user2", "user2_policy"),
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

    conn.commit()
    cur.close()
    conn.close()
    print(f"SQLite tables created and sample policies seeded at {db_path}")


if __name__ == "__main__":
    create_tables()
