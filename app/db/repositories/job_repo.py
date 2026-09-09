"""Claiming and closing scan jobs for a database-backed worker.

One QUEUED job is claimed at a time, oldest first. On SQLite the single
worker serialises naturally; on PostgreSQL the same query adds
``FOR UPDATE SKIP LOCKED`` so several workers can claim disjoint rows. The
lifecycle rules themselves live in ``app.services.scan_jobs``.
"""

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.base import utcnow
from app.db.models.enums import ScanJobStatus
from app.db.models.scan_job import ScanJob


def claim_next_job(session: Session, worker_id: str, *, now: datetime | None = None) -> ScanJob | None:
    """Claim the oldest QUEUED job, or return None when the queue is empty.

    Claiming moves the job QUEUED -> RUNNING, increments ``attempt_count`` and
    stamps ``locked_at``, ``locked_by`` and ``started_at``. The change is
    committed before the job is returned so the lock is visible at once.
    """
    now = now or utcnow()
    statement = (
        select(ScanJob)
        .where(ScanJob.status == ScanJobStatus.QUEUED)
        .order_by(ScanJob.created_at, ScanJob.id)
        .limit(1)
    )
    if session.bind is not None and session.bind.dialect.name != "sqlite":
        statement = statement.with_for_update(skip_locked=True)

    job = session.scalars(statement).first()
    if job is None:
        return None

    job.status = ScanJobStatus.RUNNING
    job.attempt_count += 1
    job.locked_at = now
    job.locked_by = worker_id
    job.started_at = now
    session.commit()
    return job


def complete_job(session: Session, job: ScanJob) -> ScanJob:
    """Close a job that finished successfully."""
    job.status = ScanJobStatus.COMPLETED
    job.completed_at = utcnow()
    job.locked_at = None
    job.locked_by = None
    return job


def release_for_retry(session: Session, job: ScanJob, message: str) -> ScanJob:
    """Return a failed attempt to the queue for another worker to pick up."""
    job.status = ScanJobStatus.QUEUED
    job.locked_at = None
    job.locked_by = None
    job.started_at = None
    job.last_error = message
    return job


def fail_job(session: Session, job: ScanJob, message: str) -> ScanJob:
    """Close a job that has run out of attempts."""
    job.status = ScanJobStatus.FAILED
    job.completed_at = utcnow()
    job.locked_at = None
    job.locked_by = None
    job.last_error = message
    return job


def find_stale_jobs(session: Session, older_than: datetime) -> list[ScanJob]:
    """Return RUNNING jobs whose lock was taken before ``older_than``.

    A worker that dies mid-job leaves its row RUNNING forever otherwise.
    """
    statement = select(ScanJob).where(
        ScanJob.status == ScanJobStatus.RUNNING,
        ScanJob.locked_at.is_not(None),
        ScanJob.locked_at < older_than,
    )
    return list(session.scalars(statement))


def reclaim_stale_jobs(session: Session, older_than: datetime) -> int:
    """Return every stale RUNNING job to QUEUED and report how many."""
    jobs = find_stale_jobs(session, older_than)
    for job in jobs:
        job.status = ScanJobStatus.QUEUED
        job.locked_at = None
        job.locked_by = None
        job.last_error = "reclaimed after a stale lock"
    if jobs:
        session.commit()
    return len(jobs)
