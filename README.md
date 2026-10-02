# Dynamic Policy-Driven Data Privacy Framework (Local)
A proof-of-concept (PoC) for inline sensitive-data protection on unstructured files.

This local version keeps the original detection and policy-enforcement flow, but stores objects on the filesystem and metadata/policies in SQLite. It does not require Docker, Kubernetes, Kafka, Redis, or HPE Alletra object storage.

## Features
- **Inline Analysis** – Automatically scans for sensitive information and stores entity metadata during object `PUT` operations.
- **Real-time Policy Enforcement** – Applies masking, redaction, or replace actions dynamically during object `GET` based on the requesting user's policy. The original file is never modified.
- **Local Upload Trigger** – PII analysis starts automatically after a local upload (replaces S3 `PUT` events).
- **Pluggable Detection Framework** – Uses Microsoft Presidio for entity resolution and confidence scores.
- **Compatible HTTP API** – The proxy still exposes a catch-all `/{bucket}/{key}` API for GET/PUT/DELETE.

## Local architecture
1. `proxy-server` stores and retrieves files under `data/storage/`.
2. After each `PUT`, `consumer_analyzer` runs Presidio and writes PII metadata to SQLite.
3. On `GET`, the proxy loads the requesting user's policy from SQLite and calls the anonymizer gRPC service.
4. The anonymizer applies mask/redact/replace in memory and returns the transformed bytes.

## Setup
Python 3.11+ is required. Run all commands from the project root.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_sm
python database/init_db.py
```

Optional: copy `.env.example` to `.env` and set `SQLITE_PATH`, `STORAGE_ROOT`, or `AN_SVC_URL`. Defaults are:

| Variable | Default |
| --- | --- |
| `SQLITE_PATH` | `data/pii.db` |
| `STORAGE_ROOT` | `data/storage` |
| `AN_SVC_URL` | `localhost:10666` |
| `PII_SCORE_THRESHOLD` | `0.6` |
| `SPACY_MODEL` | `en_core_web_sm` |
| `DEFAULT_USER` | `admin` |

`database/init_db.py` seeds `user1` and `user2` with the sample mask/redact/replace policies below. Users with no policy (including `admin`) receive the original file.

## Run
Start the anonymizer gRPC service in one terminal:

```bash
cd /path/to/project
source .venv/bin/activate
PYTHONPATH="anonymizer:common:$PYTHONPATH" python -m anonymizer
```

Start the HTTP proxy in a second terminal:

```bash
cd /path/to/project
source .venv/bin/activate
PYTHONPATH="common:consumer_analyzer/pii_analyser:consumer_analyzer/consumer:proxy-server:$PYTHONPATH" python proxy-server/app.py
```

The API listens on `http://127.0.0.1:8080`.

## Example usage

Upload a text object (analysis runs before the response returns; the first upload also loads the spaCy model):

```bash
curl -X PUT "http://127.0.0.1:8080/demo-bucket/sample.txt" \
  --data-binary $'John Smith uses card 4111-1111-1111-1111 and email john@example.com'
```

Admin / no policy (original content):

```bash
curl -H "X-User: admin" "http://127.0.0.1:8080/demo-bucket/sample.txt"
```

User-1 policy (replace names/emails, mask cards, redact SSNs, and so on):

```bash
curl -H "X-User: user1" "http://127.0.0.1:8080/demo-bucket/sample.txt"
```

User-2 policy (does not replace person names):

```bash
curl -H "X-User: user2" "http://127.0.0.1:8080/demo-bucket/sample.txt"
```

The stored file under `data/storage/demo-bucket/sample.txt` remains unchanged. Identify the caller with the `X-User` header (`user1`, `user2`, or `admin`).

### Policy associated with User-1
```json
[
    {
        "entity_type": "PERSON",
        "operator_name": "replace",
        "operator_params": {"new_value": "PERSON"}
    },
    {
        "entity_type": "CREDIT_CARD",
        "operator_name": "mask",
        "operator_params": {"from_end": false, "masking_char": "*", "chars_to_mask": 10}
    },
    {
        "entity_type": "EMAIL_ADDRESS",
        "operator_name": "replace",
        "operator_params": {"new_value": "<EMAIL>"}
    },
    {
        "entity_type": "PHONE_NUMBER",
        "operator_name": "replace",
        "operator_params": {"new_value": "PHONE_NUMBER"}
    },
    {
        "entity_type": "US_SSN",
        "operator_name": "redact"
    },
    {
        "entity_type": "US_BANK_NUMBER",
        "operator_name": "mask",
        "operator_params": {"from_end": false, "masking_char": "*", "chars_to_mask": 10}
    }
]
```

### Policy associated with User-2
```json
[
    {
        "entity_type": "CREDIT_CARD",
        "operator_name": "mask",
        "operator_params": {"from_end": false, "masking_char": "*", "chars_to_mask": 10}
    },
    {
        "entity_type": "EMAIL_ADDRESS",
        "operator_name": "mask",
        "operator_params": {"from_end": false, "masking_char": "*", "chars_to_mask": 100}
    },
    {
        "entity_type": "PHONE_NUMBER",
        "operator_name": "replace",
        "operator_params": {"new_value": "<PHONE>"}
    },
    {
        "entity_type": "US_SSN",
        "operator_name": "redact"
    },
    {
        "entity_type": "US_BANK_NUMBER",
        "operator_name": "mask",
        "operator_params": {"from_end": false, "masking_char": "*", "chars_to_mask": 10}
    }
]
```

## Project layout
- `proxy-server/` – HTTP API, local filesystem storage, user policy lookup
- `anonymizer/` – gRPC anonymizer using stored PII spans and the caller's policy
- `consumer_analyzer/` – Presidio analyzer plus the local PUT trigger
- `database/init_db.py` – SQLite schema and sample users/policies
- `common/` – shared protobuf stubs for the anonymizer RPC
