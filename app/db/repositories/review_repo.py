"""The review queue and the workflow state on each review item.

A ReviewItem owns workflow state only; the crypto fact stays on the Finding.
Moving an item to IN_REVIEW or REVIEWED records an audit event so the review
history is reconstructable without the item's mutable columns. The legal
state changes live here so no caller -- the API included -- can skip them.
"""

from dataclasses import dataclass

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session, joinedload

from app.db.models.enums import (
    AuditEventType,
    Confidence,
    CryptographicRole,
    ReviewPriority,
    ReviewStatus,
)
from app.db.models.finding import Finding
from app.db.models.review_item import ReviewItem
from app.db.repositories.audit_repo import record_event
from app.errors import InvalidReviewTransitionError

_PRIORITY_ORDER = {
    ReviewPriority.CRITICAL: 0,
    ReviewPriority.HIGH: 1,
    ReviewPriority.MEDIUM: 2,
    ReviewPriority.LOW: 3,
    ReviewPriority.INFORMATIONAL: 4,
}

_CONFIDENCE_ORDER = {
    Confidence.HIGH: 0,
    Confidence.MEDIUM: 1,
    Confidence.LOW: 2,
}

_ENTRY_EVENT = {
    ReviewStatus.IN_REVIEW: AuditEventType.REVIEW_STARTED,
    ReviewStatus.REVIEWED: AuditEventType.REVIEW_COMPLETED,
}

# A review is opened, then reviewed; either step can be walked back. Jumping
# OPEN straight to REVIEWED skips the review itself and is refused.
LEGAL_REVIEW_TRANSITIONS: frozenset[tuple[ReviewStatus, ReviewStatus]] = frozenset(
    {
        (ReviewStatus.OPEN, ReviewStatus.IN_REVIEW),
        (ReviewStatus.IN_REVIEW, ReviewStatus.REVIEWED),
        (ReviewStatus.IN_REVIEW, ReviewStatus.OPEN),
        (ReviewStatus.REVIEWED, ReviewStatus.IN_REVIEW),
    }
)


def assert_review_transition(current: ReviewStatus, target: ReviewStatus) -> None:
    """Raise unless a review item may move from one status to the other."""
    if current == target:
        return
    if (current, target) not in LEGAL_REVIEW_TRANSITIONS:
        raise InvalidReviewTransitionError(
            f"A review item cannot move from {current.value} to {target.value}."
        )


@dataclass(frozen=True)
class ReviewQueueFilters:
    """Column filters for the review queue. Enums or None only."""

    scan_id: str | None = None
    status: ReviewStatus | None = None
    algorithm: str | None = None
    role: CryptographicRole | None = None
    priority: ReviewPriority | None = None


def _queue_ordering() -> tuple:
    return (
        case(_PRIORITY_ORDER, value=Finding.priority, else_=9),
        case(_CONFIDENCE_ORDER, value=Finding.confidence, else_=9),
        Finding.file_path,
        Finding.start_line,
        ReviewItem.id,
    )


def _queue_filtered(statement, filters: ReviewQueueFilters | None):
    if filters is None:
        return statement
    if filters.scan_id is not None:
        statement = statement.where(Finding.scan_id == filters.scan_id)
    if filters.status is not None:
        statement = statement.where(ReviewItem.status == filters.status)
    if filters.algorithm is not None:
        statement = statement.where(Finding.algorithm == filters.algorithm)
    if filters.role is not None:
        statement = statement.where(Finding.role == filters.role)
    if filters.priority is not None:
        statement = statement.where(Finding.priority == filters.priority)
    return statement


def get_review_queue(
    session: Session, scan_id: str, *, status: ReviewStatus | None = None
) -> list[ReviewItem]:
    """Return a scan's review items, highest finding priority first."""
    ordering = case(_PRIORITY_ORDER, value=Finding.priority, else_=9)
    statement = (
        select(ReviewItem)
        .join(Finding, ReviewItem.finding_id == Finding.id)
        .where(Finding.scan_id == scan_id)
        .order_by(ordering, Finding.file_path, Finding.start_line, ReviewItem.id)
        .options(joinedload(ReviewItem.finding))
    )
    if status is not None:
        statement = statement.where(ReviewItem.status == status)
    return list(session.scalars(statement))


def count_review_queue(
    session: Session, *, filters: ReviewQueueFilters | None = None
) -> int:
    """Return how many review items match the filters."""
    statement = _queue_filtered(
        select(func.count()).select_from(ReviewItem).join(
            Finding, ReviewItem.finding_id == Finding.id
        ),
        filters,
    )
    return session.scalar(statement) or 0


def page_review_queue(
    session: Session,
    *,
    filters: ReviewQueueFilters | None = None,
    limit: int,
    offset: int,
) -> list[ReviewItem]:
    """Return one deterministically ordered page of the review queue.

    Highest migration-review band first, then confidence, then source
    location. Filtering and ordering run in the database.
    """
    statement = _queue_filtered(
        select(ReviewItem).join(Finding, ReviewItem.finding_id == Finding.id),
        filters,
    )
    statement = (
        statement.order_by(*_queue_ordering())
        .limit(limit)
        .offset(offset)
        .options(joinedload(ReviewItem.finding))
    )
    return list(session.scalars(statement))


def get_review_item(session: Session, review_id: str) -> ReviewItem | None:
    """Return one review item, or None."""
    return session.get(ReviewItem, review_id)


def update_review_item(
    session: Session,
    review_id: str,
    *,
    status: ReviewStatus | None = None,
    assigned_to: str | None = None,
    note: str | None = None,
) -> ReviewItem | None:
    """Apply a workflow change to a review item and audit a status entry.

    Fields left as None are unchanged. A status change is checked against
    ``LEGAL_REVIEW_TRANSITIONS`` and raises on an illegal move. The caller
    owns the commit.
    """
    item = session.get(ReviewItem, review_id)
    if item is None:
        return None

    if assigned_to is not None:
        item.assigned_to = assigned_to
    if note is not None:
        item.note = note
    if status is not None and status != item.status:
        assert_review_transition(item.status, status)
        item.status = status
        event = _ENTRY_EVENT.get(status)
        if event is not None:
            record_event(
                session,
                event,
                finding_id=item.finding_id,
                metadata={"review_id": item.id, "status": status.value},
            )
    return item
