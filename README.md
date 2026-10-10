# Dynamic Policy-Driven Data Privacy Framework (Local)
A proof-of-concept (PoC) for inline sensitive-data protection on unstructured files.

This local version keeps the original detection and policy-enforcement flow, but stores objects on the filesystem and metadata/policies in SQLite. It does not require Docker, Kubernetes, Kafka, Redis, or HPE Alletra object storage.

## Features
- **Inline Analysis** – Automatically scans for sensitive information and stores entity metadata during object `PUT` operations.
- **Real-time Policy Enforcement** – Applies masking, redaction, or replace actions dynamically during object `GET` based on the requesting user's policy. The original file is never modified.
- **Local Upload Trigger** – PII analysis starts automatically after a local upload (replaces S3 `PUT` events).
- **Pluggable Detection Framework** – Uses Microsoft Presidio for entity resolution and confidence scores.
- **Compatible HTTP API** – The proxy still exposes a catch-all `/{bucket}/{key}` API for GET/PUT/DELETE.
- **Authentication & RBAC** – Username/password login returns a signed JWT. Every object and LLM request must carry `Authorization: Bearer <token>`; the caller's identity and role come only from the verified token.

## Local architecture
1. `proxy-server` stores and retrieves files under `data/storage/`.
2. After each `PUT`, `consumer_analyzer` runs Presidio and writes PII metadata to SQLite.
3. On `GET`, the proxy takes the username from the verified JWT, loads that user's policy from SQLite and calls the anonymizer gRPC service.
4. The anonymizer applies mask/redact/replace in memory and returns the transformed bytes.

## Setup
Python 3.11+ is required (3.11 is tested; on 3.13 the pinned `pydantic==2.7.2` fails to build `pydantic-core`). Run all commands from the project root.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_sm
python database/init_db.py
```

Copy `.env.example` to `.env` and **set `JWT_SECRET`** (see [Authentication & authorization](#authentication--authorization)). You can also set `SQLITE_PATH`, `STORAGE_ROOT`, or `AN_SVC_URL`. Defaults are:

| Variable | Default |
| --- | --- |
| `SQLITE_PATH` | `data/pii.db` |
| `STORAGE_ROOT` | `data/storage` |
| `AN_SVC_URL` | `localhost:10666` |
| `PII_SCORE_THRESHOLD` | `0.6` |
| `SPACY_MODEL` | `en_core_web_sm` |
| `JWT_SECRET` | *(none; a random temporary secret is generated and a warning is logged)* |
| `JWT_ALGORITHM` | `HS256` (`HS384`/`HS512` also allowed) |
| `JWT_EXPIRE_MINUTES` | `60` |

`database/init_db.py` seeds the demo users below plus the sample mask/redact/replace policies. Users with no policy (including `admin`) receive the original file. Re-running it resets the `users` and `policies` tables; on a database created before authentication existed it also adds the `password_hash` and `role` columns.

## Authentication & authorization

### Demo credentials (local testing only)

| Username | Password | Role | Policy |
| --- | --- | --- | --- |
| `admin` | `Admin@12345` | `admin` | none (original file) |
| `user1` | `User1@12345` | `user` | `user1_policy` |
| `user2` | `User2@12345` | `user` | `user2_policy` |

Change or remove these accounts before any real deployment. Passwords are stored as salted PBKDF2-HMAC-SHA256 hashes, never in plain text.

### Roles

| Action | `admin` | `user` |
| --- | --- | --- |
| `GET /{bucket}/{key}` (policy applied) | yes | yes |
| `GET /{bucket}` (list) | yes | yes |
| `PUT` / `POST` / `DELETE` objects | yes | no (403) |
| `POST /api/llm/chat` | yes | yes |
| Policy management APIs (below) | yes | no (403) |

### Endpoints
- `POST /api/auth/login` – body `{"username": "...", "password": "..."}`; returns `access_token`, `token_type`, `expires_in` and `user`. Invalid credentials return `401`.
- `GET /api/auth/me` – returns the identity from the verified token.
- All other routes (object API and `/api/llm/chat`) require a valid Bearer token: missing/invalid/expired gives `401`, insufficient role gives `403`.

The JWT carries `sub` (username), `role`, `iat` and `exp`. The `X-User` header is **no longer read**; sending it has no effect.

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

Log in and keep the tokens (admin uploads; users read through their policy):

```bash
BASE=http://127.0.0.1:8080
login() { curl -s -X POST $BASE/api/auth/login -H 'Content-Type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"$2\"}" | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])"; }
ADMIN=$(login admin 'Admin@12345'); USER1=$(login user1 'User1@12345'); USER2=$(login user2 'User2@12345')
```

Upload a text object as admin (analysis runs before the response returns; the first upload also loads the spaCy model):

```bash
curl -X PUT "$BASE/demo-bucket/sample.txt" -H "Authorization: Bearer $ADMIN" \
  --data-binary 'John Smith uses card 4111-1111-1111-1111 and email john@example.com'
```

Admin / no policy (original content):

```bash
curl -H "Authorization: Bearer $ADMIN" "$BASE/demo-bucket/sample.txt"
```

User-1 policy (replace names/emails, mask cards, redact SSNs, and so on):

```bash
curl -H "Authorization: Bearer $USER1" "$BASE/demo-bucket/sample.txt"
```

User-2 policy (does not replace person names):

```bash
curl -H "Authorization: Bearer $USER2" "$BASE/demo-bucket/sample.txt"
```

The stored file under `data/storage/demo-bucket/sample.txt` remains unchanged. The caller is identified by the JWT in the `Authorization` header.

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

## LLM Playground: which protection applies
`POST /api/llm/chat` runs three separate steps: **detect** PII (analyzer only, text unchanged), **decide** which detected types the caller's effective policy covers, and **anonymize** through the gRPC service only if a rule applies.

| Caller | Effective policy | What Ollama receives |
| --- | --- | --- |
| Any user with a policy (admins included) | exactly that policy's rules | the prompt with those rules applied; types without a rule are kept |
| `admin` with no policy | none applies | the original prompt, unchanged |
| Regular user with no policy | fail-safe defaults (`replace` with `<TYPE>` for person, e-mail, phone, card, SSN, bank number, IP) | the prompt with the defaults applied, never the raw text |

The admin exemption needs both the signed token and the current `users` row to say `admin`. Errors never bypass an applicable policy: if detection fails, the detected spans cannot be staged, or the anonymizer is unavailable, the request ends with `502` and nothing is sent to Ollama. (An admin with no applicable rules has nothing to bypass, so a failed detection there only means no findings are reported.) `LLM_STRICT_PII=1` still adds replace rules for every other detected type, for regular users only.

## Policy management (admin only)

Policies are managed in the existing SQLite `policies` table (one row per rule, `policy_name` + the rule JSON, unchanged) and assigned through the existing `users.policy_name`. No schema change. The GET path and the LLM endpoint read these tables on every request, so an edit or reassignment applies to the **next** request.

A rule uses the same format as the seeded policies:

```json
{"entity_type": "CREDIT_CARD", "operator_name": "mask",
 "operator_params": {"masking_char": "*", "chars_to_mask": 10, "from_end": false}}
```

| `operator_name` | `operator_params` |
| --- | --- |
| `mask` | `chars_to_mask` (required integer), `masking_char` (1 char, default `*`), `from_end` (default `false`) |
| `redact` | none |
| `replace` | `new_value` (optional string; default is `<ENTITY_TYPE>`) |
| `hash` | `hash_type`: `sha256` (default) or `sha512` |

A policy needs at least one rule and at most one rule per `entity_type`. Names: 1-64 characters of letters, digits, `_`, `.`, `-`.

| Endpoint | Purpose |
| --- | --- |
| `GET /api/policies` | list policies with their rules and assigned users |
| `GET /api/policies/{policy_name}` | one policy (404 if missing) |
| `POST /api/policies` | create: `{"policy_name": "...", "rules": [...]}` (201; 409 if the name exists; 422 if invalid) |
| `PUT /api/policies/{policy_name}` | replace all rules: `{"rules": [...]}`; assigned users keep the policy |
| `DELETE /api/policies/{policy_name}` | delete (204; 409 while users are assigned) |
| `GET /api/users` | users, roles and assigned policy (no password hashes) |
| `PUT /api/users/{user_name}/policy` | assign or change: `{"policy_name": "..."}`; `null` removes the user's policy |

All of these return 401 without a valid token and 403 for the `user` role. Example:

```bash
curl -X POST $BASE/api/policies -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"policy_name":"analyst","rules":[{"entity_type":"EMAIL_ADDRESS","operator_name":"hash"},
       {"entity_type":"CREDIT_CARD","operator_name":"mask","operator_params":{"chars_to_mask":12}}]}'
curl -X PUT $BASE/api/users/user2/policy -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"policy_name":"analyst"}'
curl -H "Authorization: Bearer $USER2" "$BASE/demo-bucket/sample.txt"   # already uses "analyst"
```

In the web UI, the **Policy Engine** page (admins only) lists policies and lets you create, edit, delete and assign them. Other users see a notice instead.

## Live Dashboard
The **Dashboard** page in the UI shows live figures read from the storage folder and SQLite. Nothing on it is hardcoded or estimated. It refreshes when you open it, every 30 seconds while it is visible, and on **Refresh**. Each card has its own loading, empty and error state.

### Endpoints (any signed-in user; read-only)
Every response has the same envelope: `{"generated_at": "<UTC ISO-8601>", "data": {...}}`. The full schemas are in `/docs` (OpenAPI).

| Endpoint | `data` fields |
| --- | --- |
| `GET /api/dashboard/summary` | `total_objects`, `total_buckets`, `total_size_bytes`, `scanned_objects`, `unscanned_objects`, `objects_with_pii`, `objects_without_pii`, `scan_coverage_pct` (null when empty), `orphaned_metadata_rows`, `buckets[] {bucket, objects, scanned, with_pii, size_bytes}` |
| `GET /api/dashboard/pii-types` | `total_entities`, `objects_with_pii`, `types[] {entity_type, count, objects, avg_score, min_score, max_score}` (sorted by count) |
| `GET /api/dashboard/detection?days=14&tz_offset_minutes=330` | `window_days`, `tz_offset_minutes`, `objects_scanned`, `objects_with_pii`, `total_entities`, `detection_runs_total`, `detection_failures_total`, `tracking_since`, `timeline[] {date, detection_runs, entities_detected, failed_runs}`, `protection {basis, assigned_policies[], users_without_policy, protected_objects, partially_protected_objects, unprotected_objects, *_pct, uncovered_entity_types[] {entity_type, count}}` |
| `GET /api/dashboard/anonymization?days=14&tz_offset_minutes=330` | `window_days`, `tz_offset_minutes`, `requests_total`, `anonymized_ok`, `failed`, `served_original`, `entities_anonymized`, `by_operator[]`, `by_entity_type[]`, `by_source[]` (each `{name, count}`), `tracking_since`, `timeline[] {date, anonymized, failed}` |
| `GET /api/dashboard/llm-prompts?days=14&tz_offset_minutes=330` | LLM Playground prompts, counted per prompt and kept apart from stored objects: `prompts_total`, `prompts_sent`, `prompts_blocked`, `prompts_with_pii`, `prompts_protected`, `prompts_unchanged`, `entities_detected`, `entities_protected`, `by_entity_type[]`, `by_operator[]` (each `{name, count}`), `tracking_since`, `timeline[] {date, prompts, with_pii, blocked}` |
| `GET /api/dashboard/activity?limit=10` (1-100) | `limit`, `total_events`, `items[] {id, timestamp, event_type, source, actor, bucket, object_key, status, entity_count, summary}` (newest first) |

How the figures are defined:
- **Objects** are the files under `STORAGE_ROOT`. An object counts as **scanned** when it has a `pii_objects` row. A `pii_objects` row whose file is gone is reported as `orphaned_metadata_rows` and left out of every other figure.
- **PII by type** counts the spans exactly as the analyzer stored them, including overlapping spans such as spaCy `DATE_TIME` on a card number.
- **Protection** is based on the policies assigned to at least one user. An object is *protected* when every detected type has a rule in **every** assigned policy, *unprotected* when no assigned policy covers any of its types, and *partially protected* otherwise. Users without a policy (for example `admin`) receive original files by design.
- **Anonymized entities** are counted from Presidio's own conflict resolution (`AnonymizerEngine.anonymize(...).items`, run with `keep` so no text is produced). The count therefore matches what was actually transformed.
- The day buckets use the client's UTC offset, which the UI sends automatically.

### Database change (additive)
One new table, `dashboard_events`. Both `init_db.py` and the proxy create it with `CREATE TABLE IF NOT EXISTS` on start; a table from an earlier version gets the nullable `request_id` column added in place (and a partial unique index on `(request_id, event_type)`), and no existing row is changed or deleted. Each LLM prompt request writes one event with a server-generated `request_id`, so it cannot be recorded twice; it is written once the prompt has been forwarded to the model (or blocked fail-closed). The proxy writes one row per upload, detection run, policy-protected `GET`, original-file `GET` (no policy), delete, and LLM Playground prompt. Each row holds the timestamp, the actor from the JWT, the bucket/key, the status, and **counts by entity type and operator only**. Detected values and prompt text are never stored. Metric writes are best effort: if one fails, the request still succeeds.

Objects analysed before this table existed have no timestamps. They are included in the totals but not in the 14-day charts.

## Web UI
Open `http://127.0.0.1:8080/ui/`. You are asked to sign in first (use a demo account above). The token is kept in `sessionStorage` (cleared when the tab closes) and sent as `Authorization: Bearer <token>` on API calls. The UI returns to the login screen on a `401` or when you click **Sign out**. In the LLM Playground the policy user is the signed-in user.

## Tests
```bash
pip install -r requirements-dev.txt
python -m pytest
```
The tests use a temporary SQLite database and cover login, invalid credentials, JWT validation (expired, tampered, `alg=none`, missing claims), roles, `X-User` impersonation, and the policy APIs (CRUD, validation, assignment, admin-only access, and that edits reach the anonymizer request on the next GET). `tests/test_llm.py` also covers the admin pass-through, the per-user policies and the fail-closed paths. `tests/test_dashboard.py` covers the dashboard API, including that LLM prompts reach the metrics without touching stored-object counts or duplicating events: schemas, metric accuracy against SQLite and storage, an empty and a never-initialised database, overlapping spans, day buckets by timezone, and that no raw PII reaches the events table or the API responses. They do not need the anonymizer or Ollama.

## Project layout
- `proxy-server/` – HTTP API, local filesystem storage, user policy lookup
- `anonymizer/` – gRPC anonymizer using stored PII spans and the caller's policy
- `consumer_analyzer/` – Presidio analyzer plus the local PUT trigger
- `security.py` – password hashing and JWT create/verify helpers
- `proxy-server/auth.py` – login route, token dependency and role check
- `proxy-server/policies.py` – policy CRUD and policy assignment APIs
- `proxy-server/dashboard.py` – Live Dashboard API and `dashboard_events` persistence
- `tests/` – authentication, RBAC, policy, LLM and dashboard tests
- `database/init_db.py` – SQLite schema and demo users/policies
- `common/` – shared protobuf stubs for the anonymizer RPC
