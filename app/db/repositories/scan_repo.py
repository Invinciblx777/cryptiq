"""Persistence for the Scan row and its status/counter columns.

The three version columns fall back to the engine defaults declared on the
model, so a version string is never retyped here. Status changes are plain
column writes: the Scan lifecycle has no separate transition guard the way
ScanJob does.
"""

from sqlalchemy.orm import Session

from app.db.models.base import utcnow
from app.db.models.enums import ScanJobStatus, ScanStatus, SourceState
from app.db.models.repository import Repository
from app.db.models.scan import Scan
from app.db.models.scan_job import ScanJob
from app.engine.pipeline import AnalysisResult


def create_scan(session: Session, repository: Repository, commit_sha: str) -> Scan:
    """Insert a QUEUED scan for a repository at an exact commit.

    ``source_state`` starts UNAVAILABLE: no source has been fetched yet. The
    parser and rule-set versions come from the model's engine-backed defaults.
    """
    scan = Scan(
        repository_id=repository.id,
        commit_sha=commit_sha,
        status=ScanStatus.QUEUED,
        source_state=SourceState.UNAVAILABLE,
    )
    session.add(scan)
    session.flush()
    return scan


def create_job(session: Session, scan: Scan) -> ScanJob:
    """Insert the QUEUED job that will execute a scan."""
    job = ScanJob(scan_id=scan.id, status=ScanJobStatus.QUEUED, attempt_count=0)
    session.add(job)
    session.flush()
    return job


def get_scan(session: Session, scan_id: str) -> Scan | None:
    """Return a scan by id, or None."""
    return session.get(Scan, scan_id)


def mark_running(scan: Scan) -> Scan:
    """Move a scan into RUNNING and stamp the start time."""
    scan.status = ScanStatus.RUNNING
    scan.started_at = utcnow()
    return scan


def reset_to_queued(scan: Scan) -> Scan:
    """Return a scan to QUEUED so a retried job can run it again."""
    scan.status = ScanStatus.QUEUED
    scan.started_at = None
    return scan


def apply_analysis_counts(scan: Scan, result: AnalysisResult) -> Scan:
    """Copy the file counters off an analysis result.

    ``finding_count`` is not set here: it is the number of unique findings
    actually persisted, which the finding repository knows.
    """
    scan.file_count = result.total_files
    scan.analyzed_file_count = result.analyzed_files
    scan.skipped_file_count = result.skipped_files
    return scan


def mark_completed(scan: Scan, *, source_state: SourceState = SourceState.LIVE) -> Scan:
    """Move a scan into COMPLETED and stamp the completion time."""
    scan.status = ScanStatus.COMPLETED
    scan.source_state = source_state
    scan.completed_at = utcnow()
    return scan


def mark_failed(scan: Scan, *, code: str, message: str) -> Scan:
    """Move a scan into FAILED with a client-safe code and message.

    The message must already be safe to surface: no traceback, no provider
    body, no path.
    """
    scan.status = ScanStatus.FAILED
    scan.error_code = code
    scan.error_message = message
    scan.completed_at = utcnow()
    return scan
