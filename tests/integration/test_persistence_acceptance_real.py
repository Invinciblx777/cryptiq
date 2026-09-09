"""End-to-end persisted acceptance against the real pyca/cryptography repo.

Enable with CRYPTIQ_RUN_NETWORK_TESTS=1. Runs the exact-commit pipeline once,
persists it through the real services, and checks the stored rows. Then issues
the identical request again and checks it is served from the database cache
without re-ingesting.
"""

import os
from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.database import Base
from app.db.models import Evidence, Finding, ImpactNode, ReviewItem, Scan
from app.db.models.enums import ScanJobStatus, ScanStatus, SourceState
from app.db.models.scan_job import ScanJob
from app.integrations.github import GitHubSourceProvider, parse_repository_url
from app.services.scan_service import create_scan
from app.workers import ScanWorker

REPOSITORY_URL = "https://github.com/pyca/cryptography"
COMMIT_SHA = "1f903f5ed2e5e316f345a927555e48535829d8de"
EXPECTED_FAMILIES = {"RSA", "ECDSA", "Ed25519", "ECDH", "X25519", "AES"}

pytestmark = [
    pytest.mark.network,
    pytest.mark.skipif(
        os.getenv("CRYPTIQ_RUN_NETWORK_TESTS") != "1",
        reason="set CRYPTIQ_RUN_NETWORK_TESTS=1 to run tests that reach GitHub",
    ),
]


@pytest.fixture(scope="module")
def session_factory() -> Iterator[sessionmaker]:
    engine: Engine = create_engine(
        "sqlite://",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _fk_on(connection, _record) -> None:
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    try:
        yield sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.fixture(scope="module")
def persisted_scan(session_factory: sessionmaker) -> str:
    reference = parse_repository_url(REPOSITORY_URL)
    with session_factory() as session:
        creation = create_scan(session, repository=reference, commit_sha=COMMIT_SHA)
        scan_id = creation.scan.id
        assert creation.cached is False
        assert creation.job is not None
        assert creation.job.status is ScanJobStatus.QUEUED
        assert creation.job.attempt_count == 0

    worker = ScanWorker(
        session_factory=session_factory,
        worker_id="acceptance",
        provider_factory=GitHubSourceProvider,
    )
    assert worker.run_once() is True
    return scan_id


def test_the_persisted_scan_is_complete_and_live(persisted_scan, session_factory) -> None:
    with session_factory() as session:
        scan = session.get(Scan, persisted_scan)
        findings = session.query(Finding).filter_by(scan_id=scan.id).all()
        families = {f.algorithm for f in findings}
        hashes = [f for f in findings if f.primitive == "HASH"]
        evidence = session.query(Evidence).count()
        impact_nodes = session.query(ImpactNode).count()
        review_items = session.query(ReviewItem).count()
        job = session.query(ScanJob).filter_by(scan_id=scan.id).one()

        print("\nSCAN")
        print(f"status={scan.status.value}")
        print(f"source_state={scan.source_state.value}")
        print(f"commit={scan.commit_sha}")
        print(f"files={scan.file_count}")
        print(f"analyzed={scan.analyzed_file_count}")
        print(f"skipped={scan.skipped_file_count}")
        print(f"findings={scan.finding_count}")
        print("\nFINDINGS")
        for family in ("RSA", "ECDSA", "Ed25519", "ECDH", "X25519", "AES"):
            print(f"{family}={sum(1 for f in findings if f.algorithm == family)}")
        print(f"HASH={len(hashes)}")
        print(f"\nevidence={evidence}")
        print(f"impact_nodes={impact_nodes}")
        print(f"review_items={review_items}")

        assert scan.status is ScanStatus.COMPLETED
        assert scan.source_state is SourceState.LIVE
        assert scan.commit_sha == COMMIT_SHA
        assert scan.completed_at is not None
        assert scan.file_count > 0
        assert scan.analyzed_file_count > 0
        assert scan.finding_count == len(findings)
        assert job.status is ScanJobStatus.COMPLETED

        # No finding without evidence; one review item per finding.
        assert evidence == scan.finding_count
        assert review_items == scan.finding_count
        assert impact_nodes > scan.finding_count
        assert hashes

        assert EXPECTED_FAMILIES <= families


async def test_finding_count_is_unique_not_raw_observations(persisted_scan, session_factory) -> None:
    """The acceptance repo has many repeated hash calls; persistence collapses them."""
    with session_factory() as session:
        scan = session.get(Scan, persisted_scan)
        fingerprints = [
            f.fingerprint for f in session.query(Finding).filter_by(scan_id=scan.id)
        ]

    assert len(fingerprints) == len(set(fingerprints))
    assert scan.finding_count == len(set(fingerprints))


async def test_the_second_identical_request_is_served_from_cache(
    persisted_scan, session_factory
) -> None:
    reference = parse_repository_url(REPOSITORY_URL)
    with session_factory() as session:
        before = {
            (f.fingerprint, f.algorithm, f.file_path, f.start_line)
            for f in session.query(Finding).filter_by(scan_id=persisted_scan)
        }

        creation = create_scan(session, repository=reference, commit_sha=COMMIT_SHA)

        assert creation.cached is True
        assert creation.job is None
        assert creation.scan.id == persisted_scan
        assert creation.scan.source_state is SourceState.CACHED_REAL

        after = {
            (f.fingerprint, f.algorithm, f.file_path, f.start_line)
            for f in session.query(Finding).filter_by(scan_id=creation.scan.id)
        }
        assert after == before
        assert session.query(Scan).count() == 1  # no second scan row
        print("\nsource_state=CACHED_REAL")
