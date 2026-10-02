<<<<<<< HEAD
import psycopg2
import json
def create_tables():
    conn = psycopg2.connect(
        dbname="pii",
        user="admin",
        password="admin",
        host="10.101.180.8"  # Use service name if running in Kubernetes else Cluster IP
    )
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS pii_objects (
        bucket_name VARCHAR(512) NOT NULL,
        object_key VARCHAR(512) NOT NULL,
        pii_entities JSONB,
        PRIMARY KEY (bucket_name, object_key)
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        user_name VARCHAR(512) NOT NULL,
        policy_name VARCHAR(512) NOT NULL,
        PRIMARY KEY (user_name, policy_name)
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS policies (
        policy_name VARCHAR(512) NOT NULL,
        policy JSONB NOT NULL
    );
    """)
    bucket_name = "dummy-bucket"
    object_key = "dummy-object.txt"
    pii_entities = [
    {"type": "CREDIT_CARD", "start": 10, "end": 29, "score": 1.0},
    {"type": "PERSON", "start": 0, "end": 8, "score": 0.85}
    ]   
    cur.execute(
        "INSERT INTO pii_objects (bucket_name, object_key, pii_entities) VALUES (%s, %s, %s)",
        (bucket_name, object_key, json.dumps(pii_entities))
    )
    conn.commit()
    cur.close()
    conn.close()
    print("Tables created successfully.")
=======
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

>>>>>>> d7328bf (changed proj)

if __name__ == "__main__":
    create_tables()
