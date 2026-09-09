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
uvicorn app.main:app --reload
```

Then:

```bash
curl http://localhost:8000/health
curl http://localhost:8000/api/v1/health
```

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

The `roles` and `pqc` stages are declared but not implemented: a finding
carries no cryptographic role and no post-quantum review path yet.

See `MERGE_AUDIT.md` for how this repository was assembled.
