"""Review-queue endpoints: read the queue, update one item's workflow state."""

from typing import Annotated

from fastapi import APIRouter, Path, Query

from app.db.models.enums import CryptographicRole, ReviewPriority, ReviewStatus
from app.db.repositories import ReviewQueueFilters
from app.dependencies import DbSession
from app.schemas.common import Page
from app.schemas.review import ReviewItemRead, ReviewQueueRow, ReviewUpdateRequest
from app.services import apply_review_update, review_queue_page

router = APIRouter(tags=["reviews"])


@router.get(
    "/review-queue",
    response_model=Page[ReviewQueueRow],
    summary="List the migration review queue, paginated and filterable",
)
def review_queue_endpoint(
    session: DbSession,
    page: Annotated[int, Query(ge=1, description="1-based page number.")] = 1,
    page_size: Annotated[
        int, Query(ge=1, le=200, description="Rows per page (max 200).")
    ] = 50,
    scan_id: Annotated[str | None, Query(description="Restrict to one scan.")] = None,
    review_status: Annotated[
        ReviewStatus | None, Query(alias="status", description="Filter by review status.")
    ] = None,
    algorithm: Annotated[str | None, Query(description="Filter by algorithm, exact match.")] = None,
    role: Annotated[CryptographicRole | None, Query(description="Filter by inferred role.")] = None,
    priority: Annotated[ReviewPriority | None, Query(description="Filter by review band.")] = None,
) -> Page[ReviewQueueRow]:
    """Return one page of the queue, highest migration-review band first.

    Then match confidence, then source location. Each row nests the review
    workflow state and the finding fields a reviewer needs before opening the
    full record.
    """
    filters = ReviewQueueFilters(
        scan_id=scan_id,
        status=review_status,
        algorithm=algorithm,
        role=role,
        priority=priority,
    )
    return review_queue_page(session, page=page, page_size=page_size, filters=filters)


@router.patch(
    "/review-items/{review_id}",
    response_model=ReviewItemRead,
    summary="Update one review item's workflow state",
    responses={
        404: {"description": "No review item with this id."},
        409: {"description": "The status transition is not allowed."},
    },
)
def update_review_item_endpoint(
    review_id: Annotated[str, Path(description="The review item's id.")],
    body: ReviewUpdateRequest,
    session: DbSession,
) -> ReviewItemRead:
    """Apply a status, assignee or note change.

    Legal status moves: OPEN <-> IN_REVIEW <-> REVIEWED. OPEN straight to
    REVIEWED is refused with 409. A status entry is audited.
    """
    return apply_review_update(session, review_id, body)
