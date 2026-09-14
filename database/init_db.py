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

if __name__ == "__main__":
    create_tables()
