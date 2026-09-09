"""execute_scan drives the whole pipeline into the database, or fails cleanly."""

import pytest

from app.db.models import AuditEvent, Evidence, Finding, ImpactNode, ReviewItem, Scan
from app.db.models.enums import AuditEventType, ScanStatus, SourceState
from app.engine.ingestion import RepositoryReference
from app.errors import RepositoryUnavailableError
from app.services import create_scan, execute_scan
from app.services.scan_service import create_scan as service_create_scan
from tests.support import FakeSourceProvider

REF = RepositoryReference(
    provider="github",
    owner="pyca",
    name="cryptography",
    canonical_url="https://github.com/pyca/cryptography",
)
SHA = "1f903f5ed2e5e316f345a927555e48535829d8de"
IMPORT = b"from cryptography.hazmat.primitives.asymmetric import rsa\n"

CRYPTO_TREE = {
    "src/sign.py": IMPORT
    + b"def sign(key: rsa.RSAPrivateKey, data):\n"
    + b"    return key.sign(data)\n"
    + b"def gen():\n    return rsa.generate_private_key()\n",
    "src/keys.py": IMPORT + b"def build():\n    return rsa.generate_private_key()\n",
}


async def _run(session_factory, provider, *, commit_sha=SHA):
    with session_factory() as session:
        creation = service_create_scan(session, repository=REF, commit_sha=commit_sha)
        scan_id = creation.scan.id
    await execute_scan(scan_id, session_factory=session_factory, provider=provider)
    return scan_id


async def test_a_successful_scan_is_persisted_end_to_end(session_factory) -> None:
    provider = FakeSourceProvider(CRYPTO_TREE)

    scan_id = await _run(session_factory, provider)

    with session_factory() as session:
        scan = session.get(Scan, scan_id)
        assert scan.status is ScanStatus.COMPLETED
        assert scan.source_state is SourceState.LIVE
        assert scan.commit_sha == SHA
        assert scan.started_at is not None
        assert scan.completed_at is not None
        assert scan.file_count == 2
        assert scan.analyzed_file_count == 2
        assert scan.skipped_file_count == 0
        assert scan.finding_count > 0

        findings = session.query(Finding).filter_by(scan_id=scan_id).all()
        assert len(findings) == scan.finding_count
        assert session.query(Evidence).count() == scan.finding_count
        assert session.query(ReviewItem).count() == scan.finding_count
        assert session.query(ImpactNode).count() > 0

        events = {e.event_type for e in session.query(AuditEvent).filter_by(scan_id=scan_id)}
        assert {
            AuditEventType.SCAN_CREATED,
            AuditEventType.SCAN_STARTED,
            AuditEventType.SCAN_COMPLETED,
        } <= events


async def test_the_persisted_findings_record_the_observed_facts(session_factory) -> None:
    provider = FakeSourceProvider(CRYPTO_TREE)
    scan_id = await _run(session_factory, provider)

    with session_factory() as session:
        findings = session.query(Finding).filter_by(scan_id=scan_id).all()

    assert {f.algorithm for f in findings} == {"RSA"}
    assert {f.operation for f in findings} >= {"SIGN", "KEY_GENERATION"}
    assert all(f.library == "cryptography" for f in findings)
    assert all(f.role is not None and f.priority is not None for f in findings)


async def test_a_failing_ingestion_does_not_leave_a_completed_scan(session_factory) -> None:
    provider = FakeSourceProvider(
        CRYPTO_TREE, fail_with=RepositoryUnavailableError("provider down")
    )

    with session_factory() as session:
        creation = service_create_scan(session, repository=REF, commit_sha=SHA)
        scan_id = creation.scan.id

    with pytest.raises(RepositoryUnavailableError):
        await execute_scan(scan_id, session_factory=session_factory, provider=provider)

    with session_factory() as session:
        scan = session.get(Scan, scan_id)
        # execute_scan marks RUNNING then raises; the worker owns FAILED.
        assert scan.status is ScanStatus.RUNNING
        assert session.query(Finding).count() == 0


async def test_executing_a_terminal_scan_is_a_no_op(session_factory) -> None:
    provider = FakeSourceProvider(CRYPTO_TREE)
    scan_id = await _run(session_factory, provider)
    first_calls = provider.calls

    await execute_scan(scan_id, session_factory=session_factory, provider=provider)

    assert provider.calls == first_calls


async def test_a_second_identical_request_is_served_from_cache(session_factory) -> None:
    provider = FakeSourceProvider(CRYPTO_TREE)
    first_id = await _run(session_factory, provider)
    calls_after_first = provider.calls

    with session_factory() as session:
        creation = service_create_scan(session, repository=REF, commit_sha=SHA)

    assert creation.cached is True
    assert creation.job is None
    assert creation.scan.id == first_id
    assert creation.scan.source_state is SourceState.CACHED_REAL
    # No new ingestion or analysis happened.
    assert provider.calls == calls_after_first

    with session_factory() as session:
        first_findings = {
            (f.fingerprint, f.algorithm, f.file_path)
            for f in session.query(Finding).filter_by(scan_id=first_id)
        }
    assert first_findings  # the cached result is the persisted one


def test_create_scan_is_re_exported_from_services() -> None:
    assert create_scan is service_create_scan
