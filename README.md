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
pytest
```
