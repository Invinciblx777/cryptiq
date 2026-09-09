"""Claiming, retrying and reclaiming scan jobs."""

from datetime import UTC, datetime, timedelta

from app.db.models import Scan, ScanJob
from app.db.models.enums import ScanJobStatus, ScanStatus
from app.db.repositories import (
    claim_next_job,
    complete_job,
    create_job,
    create_scan,
    fail_job,
    find_stale_jobs,
    get_or_create_repository,
    reclaim_stale_jobs,
    release_for_retry,
)
from app.engine.ingestion import RepositoryReference

REF = RepositoryReference(
    provider="github",
    owner="pyca",
    name="cryptography",
    canonical_url="https://github.com/pyca/cryptography",
)


def _queued_job(session, commit_sha: str = "a" * 40) -> ScanJob:
    repository = get_or_create_repository(session, REF)
    scan = create_scan(session, repository, commit_sha)
    job = create_job(session, scan)
    session.commit()
    return job


def test_claiming_moves_a_job_to_running_and_stamps_the_lock(session) -> None:
    job = _queued_job(session)

    claimed = claim_next_job(session, "worker-1")

    assert claimed.id == job.id
    assert claimed.status is ScanJobStatus.RUNNING
    assert claimed.attempt_count == 1
    assert claimed.locked_by == "worker-1"
    assert claimed.locked_at is not None
    assert claimed.started_at is not None


def test_claiming_an_empty_queue_returns_none(session) -> None:
    assert claim_next_job(session, "worker-1") is None


def test_the_oldest_queued_job_is_claimed_first(session) -> None:
    first = _queued_job(session, "a" * 40)
    second = _queued_job(session, "b" * 40)

    assert claim_next_job(session, "w").id == first.id
    assert claim_next_job(session, "w").id == second.id
    assert claim_next_job(session, "w") is None


def test_a_completed_job_leaves_the_queue(session) -> None:
    _queued_job(session)
    job = claim_next_job(session, "w")

    complete_job(session, job)
    session.commit()

    assert session.get(ScanJob, job.id).status is ScanJobStatus.COMPLETED
    assert claim_next_job(session, "w") is None


def test_release_for_retry_returns_a_job_to_the_queue(session) -> None:
    _queued_job(session)
    job = claim_next_job(session, "w")

    release_for_retry(session, job, "transient failure")
    session.commit()

    assert job.status is ScanJobStatus.QUEUED
    assert job.locked_by is None
    assert job.last_error == "transient failure"

    again = claim_next_job(session, "w")
    assert again.id == job.id
    assert again.attempt_count == 2


def test_a_job_fails_permanently_once_attempts_are_spent(session) -> None:
    _queued_job(session)

    # max_attempts defaults to 3.
    for _ in range(3):
        job = claim_next_job(session, "w")
        release_for_retry(session, job, "still failing")
        session.commit()

    job = session.get(ScanJob, job.id)
    assert job.attempt_count == 3
    fail_job(session, job, "still failing")
    session.commit()

    assert session.get(ScanJob, job.id).status is ScanJobStatus.FAILED


def test_stale_running_jobs_are_found_and_reclaimed(session) -> None:
    _queued_job(session)
    job = claim_next_job(session, "w")
    job.locked_at = datetime.now(UTC) - timedelta(hours=1)
    session.commit()

    cutoff = datetime.now(UTC) - timedelta(minutes=15)
    assert [j.id for j in find_stale_jobs(session, cutoff)] == [job.id]

    reclaimed = reclaim_stale_jobs(session, cutoff)
    assert reclaimed == 1
    assert session.get(ScanJob, job.id).status is ScanJobStatus.QUEUED


def test_a_fresh_running_job_is_not_stale(session) -> None:
    _queued_job(session)
    claim_next_job(session, "w")

    cutoff = datetime.now(UTC) - timedelta(minutes=15)
    assert find_stale_jobs(session, cutoff) == []


def test_claim_leaves_the_scan_for_the_executor(session) -> None:
    """Claiming touches the job only; the scan stays QUEUED until execution."""
    job = _queued_job(session)
    claim_next_job(session, "w")

    assert session.get(Scan, job.scan_id).status is ScanStatus.QUEUED
