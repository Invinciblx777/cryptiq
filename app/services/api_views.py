"""Map persisted rows to the canonical API schemas, and page the list reads.

The database is the source of truth for a completed scan. These functions
never re-run the engine: they read the stored Finding / Evidence / ImpactNode
/ ReviewItem rows and shape them into the response models. Two pieces of
*derived* text are regenerated from persisted facts because they are pure
functions of them and are not stored:

* ``inference.rationale`` -- from the persisted algorithm, operation, primitive
  and API, via the role classifier.
* the whole ``migration`` block -- from the persisted algorithm and role, via
  the PQC mapper.

Not persisted, and therefore not reconstructed: ``inference.evidence_basis``
(null), ``priority.score`` / ``priority.reasons`` (null / empty), and
``impact.relationships`` (empty -- edges are not stored).
"""

import logging

from sqlalchemy.orm import Session

from app.db.models.enums import ImpactNodeType
from app.db.models.finding import Finding
from app.db.models.repository import Repository
from app.db.models.review_item import ReviewItem
from app.db.models.scan import Scan
from app.db.repositories import (
    FindingFilters,
    ReviewQueueFilters,
    count_findings,
    count_review_queue,
    get_finding,
    get_scan,
    page_findings,
    page_review_queue,
    update_review_item,
)
from app.engine.impact import ImpactScope
from app.engine.parser import SourceLocation
from app.engine.pqc import map_review_path
from app.engine.roles import CryptographicRole as EngineRole
from app.engine.roles import classify
from app.engine.rules import CryptoOperation, EvidenceBasis, MatchConfidence, RuleMatch
from app.errors import FindingNotFoundError, ReviewItemNotFoundError, ScanNotFoundError
from app.schemas.common import Page
from app.schemas.finding import (
    FindingDetail,
    FindingListItem,
    ImpactDetail,
    ImpactNodeRead,
    InferenceDetail,
    MigrationRead,
    ObservedRead,
    PriorityDetail,
    RepositoryRef,
    ReviewRead,
    SourceLocationRead,
)
from app.schemas.review import (
    ReviewItemRead,
    ReviewQueueFinding,
    ReviewQueueRow,
    ReviewUpdateRequest,
)
from app.schemas.scan import ScanDetail, ScanEngine, ScanStatistics

logger = logging.getLogger(__name__)

MAX_PAGE_SIZE = 200
DEFAULT_PAGE_SIZE = 50


# --- shared mapping helpers ---------------------------------------------------


def _repository_ref(repository: Repository) -> RepositoryRef:
    return RepositoryRef(
        provider=repository.provider,
        owner=repository.owner,
        name=repository.name,
        url=repository.canonical_url,
    )


def _engine_role(finding: Finding) -> EngineRole:
    return EngineRole(finding.role.value)


def _migration(finding: Finding, pqc_ruleset_version: str) -> MigrationRead:
    assessment = map_review_path(finding.algorithm, _engine_role(finding))
    return MigrationRead(
        review_path=assessment.review_path,
        rationale=assessment.rationale,
        is_migration_candidate=assessment.is_migration_candidate,
        pqc_ruleset_version=pqc_ruleset_version,
    )


def _rationale(finding: Finding) -> str | None:
    """Regenerate the role rationale from the persisted observed facts.

    A minimal RuleMatch is assembled purely to call the classifier;
    ``evidence_basis`` is a placeholder the classifier does not read.
    """
    try:
        match = RuleMatch(
            rule_id=finding.evidence.rule_id if finding.evidence else "",
            ruleset_version=finding.evidence.ruleset_version if finding.evidence else "",
            algorithm=finding.algorithm,
            primitive=finding.primitive,
            library=finding.library,
            api=finding.api,
            operation=CryptoOperation(finding.operation),
            file_path=finding.file_path,
            location=SourceLocation(
                start_line=finding.start_line,
                end_line=finding.end_line,
                start_column=finding.start_column or 0,
                end_column=finding.end_column or 0,
            ),
            confidence=MatchConfidence(finding.confidence.value),
            evidence_basis=EvidenceBasis.DIRECT_MODULE_API,
        )
        return classify(match).rationale
    except (ValueError, KeyError):  # pragma: no cover - defensive
        logger.warning("could not regenerate rationale for finding %s", finding.id)
        return None


def _enclosing(finding: Finding) -> tuple[str | None, str | None]:
    """Read the enclosing function and class off the persisted impact nodes."""
    function = klass = None
    for node in finding.impact_nodes:
        if node.node_type is ImpactNodeType.FUNCTION:
            function = node.label
        elif node.node_type is ImpactNodeType.CLASS:
            klass = node.label
    return function, klass


def _impact_detail(finding: Finding) -> ImpactDetail:
    nodes = [
        ImpactNodeRead(
            id=f"{node.node_type.value}:{node.label}",
            node_type=node.node_type.value,
            label=node.label,
            relationship=node.relationship_type.value if node.relationship_type else None,
        )
        for node in finding.impact_nodes
    ]
    return ImpactDetail(
        scope=ImpactScope.STATICALLY_OBSERVED,
        node_count=len(nodes),
        nodes=nodes,
        relationships=[],
    )


def _review_read(item: ReviewItem | None) -> ReviewRead | None:
    return ReviewRead.model_validate(item) if item is not None else None


def _first_review(finding: Finding) -> ReviewItem | None:
    items = sorted(finding.review_items, key=lambda review: review.created_at)
    return items[0] if items else None


def _observed(finding: Finding) -> ObservedRead:
    evidence = finding.evidence
    function, klass = _enclosing(finding)
    return ObservedRead(
        rule_id=evidence.rule_id if evidence else "",
        algorithm=finding.algorithm,
        primitive=finding.primitive,
        library=finding.library,
        api=finding.api,
        operation=CryptoOperation(finding.operation),
        location=SourceLocationRead(
            file_path=finding.file_path,
            start_line=finding.start_line,
            end_line=finding.end_line,
            start_column=finding.start_column,
            end_column=finding.end_column,
        ),
        source_excerpt=evidence.source_excerpt if evidence else "",
        enclosing_function=function,
        enclosing_class=klass,
        parser_version=evidence.parser_version if evidence else "",
        ruleset_version=evidence.ruleset_version if evidence else "",
    )


# --- scan -------------------------------------------------------------------


def scan_detail(scan: Scan, repository: Repository) -> ScanDetail:
    """Shape a stored scan and its repository into the API detail model."""
    return ScanDetail(
        scan_id=scan.id,
        status=scan.status,
        source_state=scan.source_state,
        repository=_repository_ref(repository),
        commit_sha=scan.commit_sha,
        base_commit_sha=scan.base_commit_sha,
        statistics=ScanStatistics(
            files=scan.file_count,
            analyzed=scan.analyzed_file_count,
            skipped=scan.skipped_file_count,
            findings=scan.finding_count,
        ),
        engine=ScanEngine(
            parser_version=scan.parser_version,
            ruleset_version=scan.ruleset_version,
            pqc_ruleset_version=scan.pqc_ruleset_version,
        ),
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        error_code=scan.error_code,
        error_message=scan.error_message,
        created_at=scan.created_at,
    )


def get_scan_detail(session: Session, scan_id: str) -> ScanDetail:
    """Return the API view of a scan, or raise SCAN_NOT_FOUND."""
    scan = get_scan(session, scan_id)
    if scan is None:
        raise ScanNotFoundError("Scan was not found.")
    repository = session.get(Repository, scan.repository_id)
    return scan_detail(scan, repository)


# --- findings -------------------------------------------------------------------


def _list_item(finding: Finding) -> FindingListItem:
    assessment = map_review_path(finding.algorithm, _engine_role(finding))
    review = _first_review(finding)
    return FindingListItem(
        id=finding.id,
        fingerprint=finding.fingerprint,
        scan_id=finding.scan_id,
        algorithm=finding.algorithm,
        primitive=finding.primitive,
        library=finding.library,
        api=finding.api,
        operation=CryptoOperation(finding.operation),
        role=finding.role,
        confidence=MatchConfidence(finding.confidence.value),
        priority=finding.priority.value,
        review_path=assessment.review_path,
        is_migration_candidate=assessment.is_migration_candidate,
        status=finding.status.value,
        file_path=finding.file_path,
        start_line=finding.start_line,
        end_line=finding.end_line,
        review_status=review.status if review is not None else None,
    )


def finding_list_page(
    session: Session,
    scan_id: str,
    *,
    page: int,
    page_size: int,
    filters: FindingFilters | None = None,
) -> Page[FindingListItem]:
    """Return one page of a scan's persisted findings, deterministically ordered."""
    scan = get_scan(session, scan_id)
    if scan is None:
        raise ScanNotFoundError("Scan was not found.")

    total = count_findings(session, scan_id, filters=filters)
    rows = page_findings(
        session, scan_id, filters=filters, limit=page_size, offset=(page - 1) * page_size
    )
    return Page.build(
        [_list_item(row) for row in rows], page=page, page_size=page_size, total=total
    )


def finding_detail(session: Session, finding_id: str) -> FindingDetail:
    """Return the canonical persisted view of one finding, or raise FINDING_NOT_FOUND."""
    finding = get_finding(session, finding_id)
    if finding is None:
        raise FindingNotFoundError("Finding was not found.")

    scan = session.get(Scan, finding.scan_id)
    repository = session.get(Repository, scan.repository_id)
    review = _first_review(finding)

    return FindingDetail(
        id=finding.id,
        fingerprint=finding.fingerprint,
        scan_id=finding.scan_id,
        repository=_repository_ref(repository),
        commit_sha=scan.commit_sha,
        observed=_observed(finding),
        inference=InferenceDetail(
            role=finding.role,
            confidence=MatchConfidence(finding.confidence.value),
            rationale=_rationale(finding),
            evidence_basis=None,
        ),
        migration=_migration(finding, scan.pqc_ruleset_version),
        impact=_impact_detail(finding),
        priority=PriorityDetail(level=finding.priority.value, score=None, reasons=[]),
        review=_review_read(review),
    )


# --- review queue ------------------------------------------------------------


def _queue_row(item: ReviewItem) -> ReviewQueueRow:
    finding = item.finding
    assessment = map_review_path(finding.algorithm, _engine_role(finding))
    return ReviewQueueRow(
        review=ReviewItemRead.model_validate(item),
        finding=ReviewQueueFinding(
            id=finding.id,
            fingerprint=finding.fingerprint,
            scan_id=finding.scan_id,
            algorithm=finding.algorithm,
            api=finding.api,
            operation=CryptoOperation(finding.operation),
            role=finding.role,
            confidence=MatchConfidence(finding.confidence.value),
            priority=finding.priority.value,
            review_path=assessment.review_path,
            is_migration_candidate=assessment.is_migration_candidate,
            file_path=finding.file_path,
            start_line=finding.start_line,
        ),
    )


def review_queue_page(
    session: Session,
    *,
    page: int,
    page_size: int,
    filters: ReviewQueueFilters | None = None,
) -> Page[ReviewQueueRow]:
    """Return one page of the review queue, highest migration-review band first."""
    total = count_review_queue(session, filters=filters)
    rows = page_review_queue(
        session, filters=filters, limit=page_size, offset=(page - 1) * page_size
    )
    return Page.build(
        [_queue_row(row) for row in rows], page=page, page_size=page_size, total=total
    )


def apply_review_update(
    session: Session, review_id: str, request: ReviewUpdateRequest
) -> ReviewItemRead:
    """Apply a workflow change and return the updated review item.

    Raises REVIEW_ITEM_NOT_FOUND if the id is unknown and
    INVALID_REVIEW_TRANSITION if the status move is not allowed.
    """
    item = update_review_item(
        session,
        review_id,
        status=request.status,
        assigned_to=request.assigned_to,
        note=request.note,
    )
    if item is None:
        raise ReviewItemNotFoundError("Review item was not found.")
    session.commit()
    return ReviewItemRead.model_validate(item)
