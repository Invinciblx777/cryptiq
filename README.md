# Cryptiq

Deterministic cryptographic static-analysis backend.

Cryptiq analyses a repository at an exact commit and produces reproducible
findings about its use of cryptography. The engine is deterministic: the same
commit and the same rule set always yield the same findings.

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

cp .env.example .env

alembic upgrade head
```

A scan is submitted over HTTP and executed by a separate worker process. Run
both:

```bash
# terminal 1 -- the API
cryptiq-api            # uvicorn on http://127.0.0.1:8000

# terminal 2 -- the worker that claims and runs queued scans
cryptiq-worker
```

## API

All endpoints except `/health` live under `/api/v1`. OpenAPI docs are at
`http://127.0.0.1:8000/docs`.

```bash
# health (no database needed)
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/api/v1/health

# submit a scan -- returns 202 with a scan_id; the worker runs it
curl -sX POST http://127.0.0.1:8000/api/v1/scans \
  -H 'content-type: application/json' \
  -d '{"repository_url":"https://github.com/pyca/cryptography",
       "commit_sha":"1f903f5ed2e5e316f345a927555e48535829d8de"}'
# {"scan_id":"<id>","status":"QUEUED","cached":false}
# commit_sha may be a 7-40 character ref; the stored scan holds the full SHA.

# scan status and statistics
curl http://127.0.0.1:8000/api/v1/scans/<scan_id>

# findings, paginated (page_size max 200) and filterable
curl "http://127.0.0.1:8000/api/v1/scans/<scan_id>/findings?page=1&page_size=50"
curl "http://127.0.0.1:8000/api/v1/scans/<scan_id>/findings?priority=HIGH&algorithm=RSA&role=DIGITAL_SIGNATURE&status=ACTIVE&confidence=HIGH"

# one finding in full (id is the database row id from a list item)
curl http://127.0.0.1:8000/api/v1/findings/<finding_id>

# migration review queue, paginated and filterable
curl "http://127.0.0.1:8000/api/v1/review-queue?page=1&page_size=50"
curl "http://127.0.0.1:8000/api/v1/review-queue?scan_id=<scan_id>&status=OPEN&priority=HIGH"

# advance a review item: OPEN <-> IN_REVIEW <-> REVIEWED
curl -sX PATCH http://127.0.0.1:8000/api/v1/review-items/<review_id> \
  -H 'content-type: application/json' \
  -d '{"status":"IN_REVIEW","assigned_to":"you","note":"needs protocol owner"}'
```

Browser origins allowed to call the API in development are set with
`CORS_ALLOWED_ORIGINS` (comma-separated; defaults to the common local dev
servers). Credentials are never allowed.

## Tests

```bash
pytest                                    # unit, integration and security tests
CRYPTIQ_RUN_NETWORK_TESTS=1 pytest -m network   # opt-in, reaches github.com
ruff check .
```

## Pipeline

```
Repository -> exact commit -> source snapshot -> file discovery
  -> Python AST parser -> cryptographic rules -> source evidence
  -> bounded impact -> migration review priority -> fingerprint
```

`app/engine/pipeline.py` runs the whole chain over one extracted snapshot.
The snapshot exists only inside `async with ingest_commit(...)`, so every
stage that reads source runs within that block.

Rules implemented: RSA, ECDSA, Ed25519, ECDH, X25519, AES and hashes, all
against the Python `cryptography` library.

A finding separates what was observed from what was inferred: the algorithm,
API, location and source excerpt can be checked against the file, while the
cryptographic role, the post-quantum review path, the impact and the priority
follow from them. `FRONTEND_BACKEND_CONTRACT.md` records the response shape.

The engine result is persisted (`app/db/repositories/`), executed by a
database-backed worker (`app/workers/scan_worker.py`), and served over the
HTTP API above (`app/api/v1/`). The API reads persisted rows only; it never
re-runs the engine or reaches GitHub for a read. Three canonical fields are
not persisted and are therefore absent or empty in API responses:
`inference.evidence_basis`, `priority.score` / `priority.reasons`, and
`impact.relationships`.

Not implemented: explanation generation (Gemini), a CLI, and authentication.

See `MERGE_AUDIT.md` for how this repository was assembled.
