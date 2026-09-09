"""Persisting an analysed result as the Finding object graph.

The engine produces one ``AnalyzedFinding`` per observation. A fingerprint is
deliberately not unique per call site -- two identical calls in one function
share it -- so the acceptance repository's ~1,441 observations collapse to
~1,042 unique findings. The table has ``UNIQUE(scan_id, fingerprint)``, so
this module deduplicates in memory *before* inserting: it never inserts and
catches the collision.

For each unique fingerprint exactly one Finding is written, with:

* one Evidence row (the "no finding without evidence" rule),
* its ImpactNode rows (the reachable elements; the algorithm root node has no
  relationship and is represented by ``Finding.algorithm`` instead),
* one OPEN ReviewItem,
* one FINDING_CREATED audit event.

The whole graph is built in memory and flushed once, so persistence costs a
single round of inserts rather than one transaction per finding.
"""

from dataclasses import dataclass

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session, selectinload

from app.db.models.enums import (
    AuditEventType,
    Confidence,
    CryptographicRole,
    FindingStatus,
    ImpactNodeType,
    ImpactRelationship,
    ReviewPriority,
    ReviewStatus,
)
from app.db.models.evidence import Evidence
from app.db.models.finding import Finding
from app.db.models.impact_node import ImpactNode
from app.db.models.review_item import ReviewItem
from app.db.models.scan import Scan
from app.db.repositories.audit_repo import record_event
from app.engine.pipeline import AnalysisResult, AnalyzedFinding

# Persisted Confidence has no UNKNOWN; no rule emits it, but map defensively.
_CONFIDENCE = {
    "HIGH": Confidence.HIGH,
    "MEDIUM": Confidence.MEDIUM,
    "LOW": Confidence.LOW,
    "UNKNOWN": Confidence.LOW,
}

_PRIORITY_ORDER = {
    ReviewPriority.CRITICAL: 0,
    ReviewPriority.HIGH: 1,
    ReviewPriority.MEDIUM: 2,
    ReviewPriority.LOW: 3,
    ReviewPriority.INFORMATIONAL: 4,
}


@dataclass(frozen=True)
class PersistOutcome:
    """What was written for one scan."""

    finding_count: int
    evidence_count: int
    impact_node_count: int
    review_item_count: int
    duplicate_observations: int


def _confidence(value: str) -> Confidence:
    return _CONFIDENCE.get(value, Confidence.LOW)


def _deduplicate(findings: tuple[AnalyzedFinding, ...]) -> list[AnalyzedFinding]:
    """Keep the first finding per fingerprint.

    ``findings`` is already in the engine's deterministic sort order, so the
    first occurrence is the canonical one and the choice is stable.
    """
    canonical: dict[str, AnalyzedFinding] = {}
    for finding in findings:
        canonical.setdefault(finding.fingerprint, finding)
    return list(canonical.values())


def _build_finding(scan_id: str, analyzed: AnalyzedFinding) -> Finding:
    match = analyzed.match
    evidence = analyzed.evidence

    finding = Finding(
        scan_id=scan_id,
        fingerprint=analyzed.fingerprint,
        algorithm=match.algorithm,
        primitive=match.primitive,
        library=match.library,
        api=match.api,
        operation=match.operation.value,
        file_path=match.file_path,
        start_line=match.location.start_line,
        end_line=match.location.end_line,
        start_column=match.location.start_column,
        end_column=match.location.end_column,
        role=CryptographicRole(analyzed.role.role.value),
        confidence=_confidence(match.confidence.value),
        priority=ReviewPriority(analyzed.priority.level.value),
        status=FindingStatus.ACTIVE,
    )
    finding.evidence = Evidence(
        repository_sha=evidence.repository_sha,
        file_path=evidence.file_path,
        start_line=evidence.start_line,
        end_line=evidence.end_line,
        source_excerpt=evidence.source_excerpt,
        rule_id=evidence.rule_id,
        parser_version=evidence.parser_version,
        ruleset_version=evidence.ruleset_version,
    )
    for node in analyzed.impact.nodes:
        if node.relationship is None:
            # The algorithm root node; carried by Finding.algorithm already.
            continue
        finding.impact_nodes.append(
            ImpactNode(
                node_type=ImpactNodeType(node.node_type.value),
                label=node.label,
                relationship_type=ImpactRelationship(node.relationship.value),
                confidence=_confidence(node.confidence.value),
            )
        )
    finding.review_items.append(ReviewItem(status=ReviewStatus.OPEN))
    return finding


def persist_analysis(session: Session, scan: Scan, result: AnalysisResult) -> PersistOutcome:
    """Write the whole analysed result under ``scan`` and return the counts.

    Must run inside the caller's transaction: a flush here that later rolls
    back leaves nothing behind, which is what keeps a failed scan from being
    presented as completed.
    """
    unique = _deduplicate(result.findings)

    findings = [_build_finding(scan.id, analyzed) for analyzed in unique]
    session.add_all(findings)
    session.flush()  # assign ids before the audit events reference them

    impact_nodes = sum(len(finding.impact_nodes) for finding in findings)
    review_items = sum(len(finding.review_items) for finding in findings)

    for finding in findings:
        record_event(
            session,
            AuditEventType.FINDING_CREATED,
            scan_id=scan.id,
            finding_id=finding.id,
            metadata={
                "fingerprint": finding.fingerprint,
                "algorithm": finding.algorithm,
                "rule_id": finding.evidence.rule_id,
            },
        )

    scan.finding_count = len(findings)
    return PersistOutcome(
        finding_count=len(findings),
        evidence_count=len(findings),
        impact_node_count=impact_nodes,
        review_item_count=review_items,
        duplicate_observations=len(result.findings) - len(unique),
    )


_CONFIDENCE_ORDER = {
    Confidence.HIGH: 0,
    Confidence.MEDIUM: 1,
    Confidence.LOW: 2,
}

# The strongest deterministic order the persisted columns allow: the numeric
# priority score is not a column, so the band leads, then confidence, then the
# source location, then the fingerprint as the final tie-break.
def _ordering() -> tuple:
    return (
        case(_PRIORITY_ORDER, value=Finding.priority, else_=9),
        case(_CONFIDENCE_ORDER, value=Finding.confidence, else_=9),
        Finding.file_path,
        Finding.start_line,
        Finding.fingerprint,
    )


@dataclass(frozen=True)
class FindingFilters:
    """Column filters for the findings and review-queue queries.

    Every field is an enum or None; the router never passes a free string.
    """

    priority: ReviewPriority | None = None
    algorithm: str | None = None
    role: CryptographicRole | None = None
    status: FindingStatus | None = None
    confidence: Confidence | None = None


def _apply_filters(statement, filters: FindingFilters | None):
    if filters is None:
        return statement
    if filters.priority is not None:
        statement = statement.where(Finding.priority == filters.priority)
    if filters.algorithm is not None:
        statement = statement.where(Finding.algorithm == filters.algorithm)
    if filters.role is not None:
        statement = statement.where(Finding.role == filters.role)
    if filters.status is not None:
        statement = statement.where(Finding.status == filters.status)
    if filters.confidence is not None:
        statement = statement.where(Finding.confidence == filters.confidence)
    return statement


def list_findings(session: Session, scan_id: str) -> list[Finding]:
    """Return a scan's persisted findings, highest review priority first."""
    statement = (
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .order_by(*_ordering())
        .options(selectinload(Finding.evidence), selectinload(Finding.impact_nodes))
    )
    return list(session.scalars(statement))


def count_findings(
    session: Session, scan_id: str, *, filters: FindingFilters | None = None
) -> int:
    """Return how many findings a scan has after filters."""
    statement = _apply_filters(
        select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id), filters
    )
    return session.scalar(statement) or 0


def page_findings(
    session: Session,
    scan_id: str,
    *,
    filters: FindingFilters | None = None,
    limit: int,
    offset: int,
) -> list[Finding]:
    """Return one deterministically ordered page of a scan's findings.

    Filtering and ordering run in the database; the caller never loads the
    whole result set to slice it in Python.
    """
    statement = _apply_filters(
        select(Finding).where(Finding.scan_id == scan_id), filters
    )
    statement = (
        statement.order_by(*_ordering())
        .limit(limit)
        .offset(offset)
        .options(
            selectinload(Finding.evidence),
            selectinload(Finding.impact_nodes),
            selectinload(Finding.review_items),
        )
    )
    return list(session.scalars(statement))


def get_finding(session: Session, finding_id: str) -> Finding | None:
    """Return one persisted finding with its evidence, impact and review loaded."""
    statement = (
        select(Finding)
        .where(Finding.id == finding_id)
        .options(
            selectinload(Finding.evidence),
            selectinload(Finding.impact_nodes),
            selectinload(Finding.review_items),
        )
    )
    return session.scalars(statement).first()
