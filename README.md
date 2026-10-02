<<<<<<< HEAD
# Dynamic Policy-Driven Data Privacy Framework for Alletra MP X10000 and AI Workloads
A proof-of-concept (PoC) implementation of a native, inline sensitive data protection framework for HPE Alletra MP X10000.
This solution integrates sensitive data detection and policy enforcement directly into storage operations such as PUT and GET, enabling secure and intelligent management of unstructured data.

## Features
- **Inline Analysis** – Automatically scans for sensitive information and enriches metadata during object `PUT` operations.  
- **Real-time Policy Enforcement** – Applies masking, redaction, or other anonymization actions dynamically during object `GET` based on user policies.  
- **Event-Driven Architecture** – Analysis pipeline gets automatically triggered on S3 `PUT` object event.  
- **Pluggable Detection Framework** – Supports custom analyzers and policies for diverse data types and governance requirements.
- **Seamless S3 API Compatibility** - The framework works transparently with standard S3 APIs, requiring no changes to existing applications and minimizing integration or operational overhead

## Architecture 

![image](https://github.hpe.com/deepika-indran/PII-for-Object-Storage/assets/80950/0223949c-842f-49c5-83b7-31d51b2ed3a1)

## Results 
The POC was evaluated using Kaggle's PII Data detection competition dataset with -

- **Scale**: 1000 object retrievals (~2450 words, ~45 PII entities each) 
- **CPU**: 40 cores, Memory: 256GiB 

A negligible retrieval latency of ~25ms was observed. Using default Presidio recognisers, it achieved recall rates of **95.8%** for person names and **94%** for emails. Anonymization strategies were correctly applied based on user-specific policies during GET object requests.


![image](https://github.hpe.com/deepika-indran/PII-for-Object-Storage/assets/68480/6b1b126c-d2c6-4c57-acdf-bb27686915a6)

## Example Usage

### Admin User
![image](https://github.hpe.com/deepika-indran/PII-for-Object-Storage/assets/68480/7f020bff-c358-43ce-b828-6338719c0cbe)

### User-1 
Policy associated with User-1
=======
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
>>>>>>> d7328bf (changed proj)
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
<<<<<<< HEAD
![image](https://github.hpe.com/deepika-indran/PII-for-Object-Storage/assets/68480/ff7e63b8-eb15-4be8-92ff-96644e840e07)

### User-2

Policy associated with User-2
=======

### Policy associated with User-2
>>>>>>> d7328bf (changed proj)
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
<<<<<<< HEAD
![image](https://github.hpe.com/deepika-indran/PII-for-Object-Storage/assets/68480/39d8f51f-4aba-4588-987f-156a3a754e74)


=======

## Project layout
- `proxy-server/` – HTTP API, local filesystem storage, user policy lookup
- `anonymizer/` – gRPC anonymizer using stored PII spans and the caller's policy
- `consumer_analyzer/` – Presidio analyzer plus the local PUT trigger
- `database/init_db.py` – SQLite schema and sample users/policies
- `common/` – shared protobuf stubs for the anonymizer RPC
>>>>>>> d7328bf (changed proj)
