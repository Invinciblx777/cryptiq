"""The canonical finding response.

The shape follows the engine's own division of labour, because that division
is the contract: a reader must be able to tell what Cryptiq *saw* from what it
*concluded*. Flattening the two together would let an inference be mistaken
for a fact about the source.

* ``observed``  -- checkable against the file at that commit.
* ``inference`` -- what the engine concludes the construct is for.
* ``migration`` -- which guidance to review, derived from the inference.
* ``impact``, ``priority`` -- consequences, also derived.
* ``review``    -- human workflow state, present only once a review exists.

Each fact appears once, under one name. There is no ``algorithm`` beside an
``observed_algorithm``.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.db.models.enums import ReviewStatus
from app.engine.impact import ImpactScope
from app.engine.pqc import PqcReviewPath
from app.engine.roles import CryptographicRole
from app.engine.rules import CryptoOperation, EvidenceBasis, MatchConfidence


class RepositoryRef(BaseModel):
    """The repository a finding belongs to."""

    provider: str
    owner: str
    name: str
    url: str


class SourceLocationRead(BaseModel):
    """An exact span in a source file, as the parser reported it."""

    file_path: str
    start_line: int
    end_line: int
    start_column: int | None = None
    end_column: int | None = None


class ObservedRead(BaseModel):
    """What the rules established from the source. Every field is checkable.

    ``source_excerpt`` is the text at ``location`` in the analysed commit, so
    a reviewer can confirm the finding without leaving the response.
    """

    rule_id: str
    algorithm: str
    primitive: str
    library: str
    api: str
    operation: CryptoOperation
    location: SourceLocationRead
    source_excerpt: str
    enclosing_function: str | None = None
    enclosing_class: str | None = None
    parser_version: str
    ruleset_version: str


class InferenceRead(BaseModel):
    """What the engine concluded, and how firmly.

    ``rationale`` is a fixed sentence chosen by the classifier, never
    generated text.
    """

    role: CryptographicRole
    rationale: str
    confidence: MatchConfidence
    evidence_basis: EvidenceBasis


class MigrationRead(BaseModel):
    """The post-quantum guidance to review this finding against.

    A review path, never a replacement: it names the standard a reviewer
    should open, not a change to apply.
    """

    review_path: PqcReviewPath
    rationale: str
    is_migration_candidate: bool
    pqc_ruleset_version: str


class ImpactNodeRead(BaseModel):
    """One program element inside the finding's bounded impact."""

    id: str
    node_type: str
    label: str
    relationship: str | None = None


class ImpactEdgeRead(BaseModel):
    """A directed relationship between two impact nodes."""

    source_id: str
    target_id: str
    relationship: str


class ImpactRead(BaseModel):
    """How far the finding reaches, within the analysed snapshot only."""

    scope: ImpactScope
    node_count: int
    nodes: list[ImpactNodeRead]
    relationships: list[ImpactEdgeRead]


class PriorityRead(BaseModel):
    """Where the finding sits in the migration review queue."""

    level: str
    score: int
    reasons: list[str]


class ReviewRead(BaseModel):
    """Human review state. Absent until someone opens a review."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    status: ReviewStatus
    assigned_to: str | None = None
    note: str | None = None
    created_at: datetime
    updated_at: datetime


class FindingRead(BaseModel):
    """One finding, complete.

    ``id`` is the fingerprint: stable for the same logical finding across
    commits, so a client can follow a finding from scan to scan.
    """

    id: str
    scan_id: str
    repository: RepositoryRef
    commit_sha: str
    observed: ObservedRead
    inference: InferenceRead
    migration: MigrationRead
    impact: ImpactRead
    priority: PriorityRead
    review: ReviewRead | None = None


class FindingSummary(BaseModel):
    """A finding as it appears in a list, without the impact graph or excerpt.

    The fields are the ones a table needs; a client opens the full record for
    the evidence and the blast radius.
    """

    id: str
    scan_id: str
    algorithm: str
    api: str
    operation: CryptoOperation
    role: CryptographicRole
    confidence: MatchConfidence
    review_path: PqcReviewPath
    is_migration_candidate: bool
    priority: str
    priority_score: int
    file_path: str
    start_line: int
    end_line: int
    review_status: ReviewStatus | None = None


class FindingPage(BaseModel):
    """A page of findings, ordered by the engine's own deterministic order."""

    scan_id: str
    total: int
    findings: list[FindingSummary]


class ReviewQueueItem(BaseModel):
    """One entry in the migration review queue."""

    review_id: str
    finding_id: str
    scan_id: str
    algorithm: str
    api: str
    role: CryptographicRole
    review_path: PqcReviewPath
    priority: str
    priority_score: int
    status: ReviewStatus
    assigned_to: str | None = None
    note: str | None = None
    file_path: str
    start_line: int
    updated_at: datetime


class ReviewQueue(BaseModel):
    """The review queue for one scan, highest priority first."""

    scan_id: str
    total: int
    items: list[ReviewQueueItem] = Field(default_factory=list)


# --- Database-backed views -------------------------------------------------
#
# The schemas above are produced from the engine's ``AnalyzedFinding``. The
# ones below are produced from the persisted rows (Finding + Evidence +
# ImpactNode + ReviewItem). They keep the same canonical nesting, but a few
# fields are not columns and are handled explicitly:
#
#   * inference.evidence_basis  -- not persisted; always null.
#   * priority.score / reasons  -- not persisted; score null, reasons empty.
#   * impact.relationships      -- edges are not persisted; always [].
#
# inference.rationale and the whole migration block are regenerated from the
# persisted observed facts plus the persisted role, which are pure functions.


class InferenceDetail(BaseModel):
    """What the engine concluded, rebuilt from persisted columns.

    ``evidence_basis`` is not persisted, so it is always null here.
    """

    role: CryptographicRole
    confidence: MatchConfidence
    rationale: str | None = None
    evidence_basis: EvidenceBasis | None = None


class PriorityDetail(BaseModel):
    """The persisted migration-review band.

    The numeric score and the reason list are not persisted, so ``score`` is
    null and ``reasons`` is empty. The band is authoritative.
    """

    level: str
    score: int | None = None
    reasons: list[str] = Field(default_factory=list)


class ImpactDetail(BaseModel):
    """The persisted impact nodes. Edges are not persisted, so ``relationships`` is []."""

    scope: ImpactScope
    node_count: int
    nodes: list[ImpactNodeRead] = Field(default_factory=list)
    relationships: list[ImpactEdgeRead] = Field(default_factory=list)


class FindingDetail(BaseModel):
    """One persisted finding, complete, in the canonical nesting.

    ``id`` is the database row id and is what ``GET /findings/{id}`` takes.
    ``fingerprint`` is the cross-scan logical identity (unique within a scan),
    so a client can follow the same finding from one scan to the next.
    ``observed`` holds only checkable facts; ``inference`` never contains an
    observed field.
    """

    id: str
    fingerprint: str
    scan_id: str
    repository: RepositoryRef
    commit_sha: str
    observed: ObservedRead
    inference: InferenceDetail
    migration: MigrationRead
    impact: ImpactDetail
    priority: PriorityDetail
    review: ReviewRead | None = None


class FindingListItem(BaseModel):
    """A persisted finding as a list row: the columns a results table needs.

    ``id`` is the database row id (use it for ``GET /findings/{id}``);
    ``fingerprint`` is the cross-scan logical identity.
    """

    id: str
    fingerprint: str
    scan_id: str
    algorithm: str
    primitive: str
    library: str
    api: str
    operation: CryptoOperation
    role: CryptographicRole
    confidence: MatchConfidence
    priority: str
    review_path: PqcReviewPath
    is_migration_candidate: bool
    status: str
    file_path: str
    start_line: int
    end_line: int
    review_status: ReviewStatus | None = None
