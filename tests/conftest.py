"""Shared test fixtures."""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.database import Base
from app.db.models import (
    Evidence,
    Finding,
    Repository,
    Scan,
)
from app.db.models.enums import Confidence, CryptographicRole, ReviewPriority
from app.engine.fingerprints import fingerprint
from app.main import create_app


@pytest.fixture
def client() -> TestClient:
    """Return a test client bound to a fresh application instance."""
    return TestClient(create_app())


@pytest.fixture
def api_client(session_factory: sessionmaker) -> Iterator[TestClient]:
    """A TestClient whose requests use the in-memory schema.

    ``get_db`` is overridden to yield from the test session factory so an
    endpoint and the test see the same rows.
    """
    from app.dependencies import get_db

    app = create_app()

    def _override_get_db() -> Iterator[Session]:
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _override_get_db
    # raise_server_exceptions=False so a deliberate 500 is asserted as a
    # response, matching how the app behaves in production.
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def engine() -> Iterator[Engine]:
    """Return an in-memory SQLite engine with the full schema and FKs enforced."""
    engine = create_engine(
        "sqlite://",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    # SQLite ignores foreign keys unless the pragma is set per connection, so
    # ON DELETE behaviour would be untestable without this.
    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(connection, _record) -> None:
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    try:
        yield engine
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.fixture
def session_factory(engine: Engine) -> sessionmaker:
    """Return a session factory bound to the in-memory schema.

    The scan worker and execution service open and close their own sessions,
    so they take a factory rather than a live session.
    """
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@pytest.fixture
def session(session_factory: sessionmaker) -> Iterator[Session]:
    """Return a session bound to the in-memory schema."""
    with session_factory() as session:
        yield session


@pytest.fixture
def repository(session: Session) -> Repository:
    """Return a persisted repository."""
    repository = Repository(
        provider="github",
        owner="pyca",
        name="cryptography",
        canonical_url="https://github.com/pyca/cryptography",
    )
    session.add(repository)
    session.commit()
    return repository


@pytest.fixture
def scan(session: Session, repository: Repository) -> Scan:
    """Return a persisted scan of the repository fixture."""
    scan = Scan(repository_id=repository.id, commit_sha="a" * 40)
    session.add(scan)
    session.commit()
    return scan


def build_finding(scan_id: str, **overrides: object) -> Finding:
    """Return an unsaved finding with its required evidence attached."""
    fields: dict[str, object] = {
        "scan_id": scan_id,
        "fingerprint": fingerprint("github/pyca/cryptography", "src/keys.py", "rsa-generate"),
        "algorithm": "RSA",
        "primitive": "PUBLIC_KEY",
        "library": "cryptography",
        "api": "rsa.generate_private_key",
        "operation": "KEY_GENERATION",
        "file_path": "src/keys.py",
        "start_line": 10,
        "end_line": 12,
        "role": CryptographicRole.DIGITAL_SIGNATURE,
        "confidence": Confidence.HIGH,
        "priority": ReviewPriority.HIGH,
    }
    fields.update(overrides)
    finding = Finding(**fields)
    finding.evidence = Evidence(
        repository_sha="a" * 40,
        file_path=str(fields["file_path"]),
        start_line=int(fields["start_line"]),  # type: ignore[arg-type]
        end_line=int(fields["end_line"]),  # type: ignore[arg-type]
        source_excerpt="rsa.generate_private_key(public_exponent=65537, key_size=2048)",
        rule_id="rsa-key-generation",
        parser_version="python-ast-1",
        ruleset_version="0.3.0",
    )
    return finding


@pytest.fixture
def finding(session: Session, scan: Scan) -> Finding:
    """Return a persisted finding with evidence."""
    finding = build_finding(scan.id)
    session.add(finding)
    session.commit()
    return finding


@pytest.fixture
def seeded_scan(session_factory: sessionmaker) -> str:
    """Persist a small completed scan through the real pipeline and return its id.

    Two RSA findings (a sign and a key generation), each with evidence, impact
    nodes and an OPEN review item. No network.
    """
    from app.db.repositories import apply_analysis_counts, persist_analysis
    from app.engine.ingestion import IngestionLimits, RepositoryReference, SourceSnapshot
    from app.engine.ingestion.service import build_result
    from app.engine.pipeline import analyze_snapshot
    from app.services import create_scan

    reference = RepositoryReference(
        provider="github",
        owner="pyca",
        name="cryptography",
        canonical_url="https://github.com/pyca/cryptography",
    )
    commit = "1f903f5ed2e5e316f345a927555e48535829d8de"
    imp = b"from cryptography.hazmat.primitives.asymmetric import rsa\n"
    tree = {
        "src/sign.py": imp
        + b"class Signer:\n"
        + b"    def run(self, key: rsa.RSAPrivateKey, data):\n"
        + b"        return key.sign(data)\n",
        "src/keys.py": imp + b"def build():\n    return rsa.generate_private_key()\n",
    }
    limits = IngestionLimits(
        max_archive_bytes=1 << 20,
        max_extracted_bytes=1 << 20,
        max_files=100,
        max_file_bytes=8192,
    )

    import tempfile
    from pathlib import Path

    from tests.support import write_tree

    root = write_tree(Path(tempfile.mkdtemp(prefix="cryptiq-seed-")), tree)
    snapshot = SourceSnapshot(
        root_path=root, repository=reference, commit_sha=commit,
        content_hash="0" * 64, file_count=len(tree),
    )
    result = analyze_snapshot(build_result(snapshot, limits), root)

    with session_factory() as session:
        scan = create_scan(session, repository=reference, commit_sha=commit).scan
        with session.begin():
            persist_analysis(session, scan, result)
            apply_analysis_counts(scan, result)
            from app.db.repositories import mark_completed

            mark_completed(scan)
        return scan.id
