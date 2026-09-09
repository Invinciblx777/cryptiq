"""Data-access helpers over the SQLAlchemy models.

Each module owns one aggregate. Repository functions mutate and flush; the
caller owns the transaction, except ``job_repo.claim_next_job`` and the
stale-job reclaim, which commit so a lock is released promptly. Read helpers
run filtering, ordering and pagination in the database, never in Python.
"""

from app.db.repositories.audit_repo import record_event
from app.db.repositories.finding_repo import (
    FindingFilters,
    PersistOutcome,
    count_findings,
    get_finding,
    list_findings,
    page_findings,
    persist_analysis,
)
from app.db.repositories.job_repo import (
    claim_next_job,
    complete_job,
    fail_job,
    find_stale_jobs,
    reclaim_stale_jobs,
    release_for_retry,
)
from app.db.repositories.repository_repo import get_or_create_repository
from app.db.repositories.review_repo import (
    LEGAL_REVIEW_TRANSITIONS,
    ReviewQueueFilters,
    assert_review_transition,
    count_review_queue,
    get_review_item,
    get_review_queue,
    page_review_queue,
    update_review_item,
)
from app.db.repositories.scan_repo import (
    apply_analysis_counts,
    create_job,
    create_scan,
    get_scan,
    mark_completed,
    mark_failed,
    mark_running,
    reset_to_queued,
)

__all__ = [
    "LEGAL_REVIEW_TRANSITIONS",
    "FindingFilters",
    "PersistOutcome",
    "ReviewQueueFilters",
    "apply_analysis_counts",
    "assert_review_transition",
    "claim_next_job",
    "complete_job",
    "count_findings",
    "count_review_queue",
    "create_job",
    "create_scan",
    "fail_job",
    "find_stale_jobs",
    "get_finding",
    "get_or_create_repository",
    "get_review_item",
    "get_review_queue",
    "get_scan",
    "list_findings",
    "mark_completed",
    "mark_failed",
    "mark_running",
    "page_findings",
    "page_review_queue",
    "persist_analysis",
    "reclaim_stale_jobs",
    "record_event",
    "release_for_retry",
    "reset_to_queued",
    "update_review_item",
]
