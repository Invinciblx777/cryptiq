"""create_scan: it inserts a scan and job, stamps versions, and reuses a cache hit."""

import pytest

from app.db.models import AuditEvent, Repository, Scan, ScanJob
from app.db.models.enums import (
    AuditEventType,
    ScanJobStatus,
    ScanStatus,
    SourceState,
)
from app.engine.engine import engine_versions
from app.engine.ingestion import RepositoryReference
from app.errors import InvalidCommitShaError
from app.services import create_scan

REF = RepositoryReference(
    provider="github",
    owner="pyca",
    name="cryptography",
    canonical_url="https://github.com/pyca/cryptography",
)
SHA = "1f903f5ed2e5e316f345a927555e48535829d8de"


def test_creating_a_scan_inserts_a_queued_scan_and_job(session) -> None:
    result = create_scan(session, repository=REF, commit_sha=SHA)

    assert result.cached is False
    scan = session.get(Scan, result.scan.id)
    assert scan.status is ScanStatus.QUEUED
    assert scan.source_state is SourceState.UNAVAILABLE
    assert scan.commit_sha == SHA

    job = session.get(ScanJob, result.job.id)
    assert job.status is ScanJobStatus.QUEUED
    assert job.attempt_count == 0
    assert job.scan_id == scan.id


def test_the_scan_is_stamped_with_the_configured_versions(session) -> None:
    result = create_scan(session, repository=REF, commit_sha=SHA)
    versions = engine_versions()

    scan = session.get(Scan, result.scan.id)
    assert scan.parser_version == versions.parser_version
    assert scan.ruleset_version == versions.ruleset_version
    assert scan.pqc_ruleset_version == versions.pqc_ruleset_version


def test_creating_a_scan_records_an_audit_event(session) -> None:
    result = create_scan(session, repository=REF, commit_sha=SHA)

    events = session.query(AuditEvent).filter_by(scan_id=result.scan.id).all()
    assert [e.event_type for e in events] == [AuditEventType.SCAN_CREATED]


def test_a_short_sha_is_rejected(session) -> None:
    with pytest.raises(InvalidCommitShaError):
        create_scan(session, repository=REF, commit_sha="1f903f5")


def test_an_identical_completed_scan_is_reused(session) -> None:
    first = create_scan(session, repository=REF, commit_sha=SHA)
    scan = session.get(Scan, first.scan.id)
    scan.status = ScanStatus.COMPLETED
    scan.source_state = SourceState.LIVE
    session.commit()

    second = create_scan(session, repository=REF, commit_sha=SHA)

    assert second.cached is True
    assert second.job is None
    assert second.scan.id == first.scan.id
    assert session.query(Scan).count() == 1
    assert session.query(ScanJob).count() == 1
    assert session.get(Scan, first.scan.id).source_state is SourceState.CACHED_REAL


def test_a_queued_scan_is_not_a_cache_hit(session) -> None:
    create_scan(session, repository=REF, commit_sha=SHA)
    second = create_scan(session, repository=REF, commit_sha=SHA)

    assert second.cached is False
    assert session.query(Scan).count() == 2


def test_the_repository_row_is_shared_across_scans(session) -> None:
    create_scan(session, repository=REF, commit_sha=SHA)
    create_scan(session, repository=REF, commit_sha="a" * 40)

    assert session.query(Repository).count() == 1
