"""The database-backed worker: claim, run, complete, retry, permanent failure."""

from app.db.models import AuditEvent, Finding, Scan, ScanJob
from app.db.models.enums import (
    AuditEventType,
    ScanJobStatus,
    ScanStatus,
    SourceState,
)
from app.engine.ingestion import RepositoryReference
from app.errors import RepositoryUnavailableError
from app.services.scan_service import create_scan
from app.workers import ScanWorker
from tests.support import FakeSourceProvider

REF = RepositoryReference(
    provider="github",
    owner="pyca",
    name="cryptography",
    canonical_url="https://github.com/pyca/cryptography",
)
SHA = "1f903f5ed2e5e316f345a927555e48535829d8de"
IMPORT = b"from cryptography.hazmat.primitives.asymmetric import rsa\n"
TREE = {
    "src/keys.py": IMPORT + b"def build():\n    return rsa.generate_private_key()\n",
}


def _queue_scan(session_factory) -> str:
    with session_factory() as session:
        return create_scan(session, repository=REF, commit_sha=SHA).scan.id


def test_the_worker_claims_runs_and_completes_a_job(session_factory) -> None:
    scan_id = _queue_scan(session_factory)
    worker = ScanWorker(
        session_factory=session_factory,
        worker_id="w-test",
        provider_factory=lambda: FakeSourceProvider(TREE),
    )

    assert worker.run_once() is True
    assert worker.run_once() is False  # queue now empty

    with session_factory() as session:
        scan = session.get(Scan, scan_id)
        assert scan.status is ScanStatus.COMPLETED
        assert scan.source_state is SourceState.LIVE
        assert scan.finding_count > 0
        job = session.query(ScanJob).filter_by(scan_id=scan_id).one()
        assert job.status is ScanJobStatus.COMPLETED
        assert job.attempt_count == 1
        assert job.locked_by is None


def test_a_transient_failure_is_retried_then_fails_permanently(session_factory) -> None:
    scan_id = _queue_scan(session_factory)
    worker = ScanWorker(
        session_factory=session_factory,
        worker_id="w-test",
        provider_factory=lambda: FakeSourceProvider(
            TREE, fail_with=RepositoryUnavailableError("provider down")
        ),
    )

    # max_attempts defaults to 3: two requeues, then permanent failure.
    worker.run_once()
    with session_factory() as session:
        job = session.query(ScanJob).filter_by(scan_id=scan_id).one()
        assert job.status is ScanJobStatus.QUEUED
        assert job.attempt_count == 1
        assert session.get(Scan, scan_id).status is ScanStatus.QUEUED

    worker.run_once()
    with session_factory() as session:
        job = session.query(ScanJob).filter_by(scan_id=scan_id).one()
        assert job.status is ScanJobStatus.QUEUED
        assert job.attempt_count == 2

    worker.run_once()
    with session_factory() as session:
        job = session.query(ScanJob).filter_by(scan_id=scan_id).one()
        scan = session.get(Scan, scan_id)
        assert job.status is ScanJobStatus.FAILED
        assert job.attempt_count == 3
        assert scan.status is ScanStatus.FAILED
        assert scan.error_code == "REPOSITORY_UNAVAILABLE"
        assert scan.error_message
        assert "Traceback" not in (scan.error_message or "")
        events = {e.event_type for e in session.query(AuditEvent).filter_by(scan_id=scan_id)}
        assert AuditEventType.SCAN_FAILED in events

    assert worker.run_once() is False  # nothing left to claim


def test_an_unexpected_error_is_recorded_without_internals(session_factory) -> None:
    scan_id = _queue_scan(session_factory)
    worker = ScanWorker(
        session_factory=session_factory,
        worker_id="w-test",
        provider_factory=lambda: FakeSourceProvider(
            TREE, fail_with=ValueError("secret internal detail")
        ),
    )

    for _ in range(3):
        worker.run_once()

    with session_factory() as session:
        scan = session.get(Scan, scan_id)
        assert scan.status is ScanStatus.FAILED
        assert scan.error_code == "SCAN_EXECUTION_FAILED"
        assert "secret internal detail" not in (scan.error_message or "")


def test_the_worker_persists_real_findings_via_the_full_path(session_factory) -> None:
    scan_id = _queue_scan(session_factory)
    worker = ScanWorker(
        session_factory=session_factory,
        worker_id="w-test",
        provider_factory=lambda: FakeSourceProvider(TREE),
    )
    worker.run_once()

    with session_factory() as session:
        findings = session.query(Finding).filter_by(scan_id=scan_id).all()
        assert findings
        assert all(f.evidence is not None for f in findings)
        assert {f.algorithm for f in findings} == {"RSA"}
