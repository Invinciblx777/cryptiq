"""Scan endpoints: submit a scan, read its status, page its findings.

Submitting a scan resolves the commit reference and writes Repository -> Scan
-> ScanJob, then returns 202 at once. The archive download and analysis run
later in the ``cryptiq-worker`` process; this handler never calls the engine.
"""

from typing import Annotated

from fastapi import APIRouter, Path, Query, Response, status

from app.db.models.enums import Confidence, CryptographicRole, FindingStatus, ReviewPriority
from app.db.repositories import FindingFilters
from app.dependencies import CommitResolverDep, DbSession
from app.schemas.common import Page
from app.schemas.finding import FindingListItem
from app.schemas.scan import ScanAccepted, ScanDetail, ScanRequest
from app.services import finding_list_page, get_scan_detail, submit_scan

router = APIRouter(prefix="/scans", tags=["scans"])

ScanId = Annotated[str, Path(description="The scan identifier returned by POST /scans.")]


@router.post(
    "",
    response_model=ScanAccepted,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit a repository and commit for analysis",
    responses={
        202: {"description": "Scan queued, or an identical completed scan reused."},
        422: {"description": "The repository URL or commit reference is invalid."},
        404: {"description": "The repository or commit was not found."},
        502: {"description": "The provider could not be reached."},
    },
)
async def create_scan_endpoint(
    body: ScanRequest, session: DbSession, resolver: CommitResolverDep, response: Response
) -> ScanAccepted:
    """Resolve the commit reference, create the scan, and return immediately.

    A 7-40 character ``commit_sha`` is accepted; the stored scan always holds
    the full 40-character SHA. If an identical completed scan exists it is
    reused (``cached: true``) and no new job is queued.
    """
    creation = await submit_scan(
        session,
        repository_url=body.repository_url,
        commit_ref=body.commit_sha,
        resolver=resolver,
    )
    if creation.cached:
        response.status_code = status.HTTP_200_OK
    return ScanAccepted(
        scan_id=creation.scan.id, status=creation.scan.status, cached=creation.cached
    )


@router.get(
    "/{scan_id}",
    response_model=ScanDetail,
    summary="Read a scan's status and statistics",
    responses={404: {"description": "No scan with this id."}},
)
def get_scan_endpoint(scan_id: ScanId, session: DbSession) -> ScanDetail:
    """Return the scan's status, source state, counters and engine versions."""
    return get_scan_detail(session, scan_id)


@router.get(
    "/{scan_id}/findings",
    response_model=Page[FindingListItem],
    summary="List a scan's persisted findings, paginated and filterable",
    responses={404: {"description": "No scan with this id."}},
)
def list_scan_findings_endpoint(
    scan_id: ScanId,
    session: DbSession,
    page: Annotated[int, Query(ge=1, description="1-based page number.")] = 1,
    page_size: Annotated[
        int, Query(ge=1, le=200, description="Rows per page (max 200).")
    ] = 50,
    priority: Annotated[ReviewPriority | None, Query(description="Filter by review band.")] = None,
    algorithm: Annotated[str | None, Query(description="Filter by algorithm, exact match.")] = None,
    role: Annotated[CryptographicRole | None, Query(description="Filter by inferred role.")] = None,
    finding_status: Annotated[
        FindingStatus | None, Query(alias="status", description="Filter by finding status.")
    ] = None,
    confidence: Annotated[Confidence | None, Query(description="Filter by match confidence.")] = None,
) -> Page[FindingListItem]:
    """Return one deterministically ordered page of persisted findings.

    Order: review band, then confidence, then file path, line and fingerprint.
    The numeric priority score is not a persisted column, so it does not
    appear and is not used for ordering.
    """
    filters = FindingFilters(
        priority=priority,
        algorithm=algorithm,
        role=role,
        status=finding_status,
        confidence=confidence,
    )
    return finding_list_page(
        session, scan_id, page=page, page_size=page_size, filters=filters
    )
