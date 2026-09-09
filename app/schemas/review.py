"""Review-workflow request and response schemas."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.db.models.enums import CryptographicRole, ReviewStatus
from app.engine.pqc import PqcReviewPath
from app.engine.rules import CryptoOperation, MatchConfidence


class ReviewUpdateRequest(BaseModel):
    """A change to one review item. Every field is optional; omitted stays put."""

    status: ReviewStatus | None = None
    assigned_to: str | None = Field(default=None, max_length=255)
    note: str | None = None


class ReviewItemRead(BaseModel):
    """The workflow state of one review item."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_id: str
    status: ReviewStatus
    assigned_to: str | None = None
    note: str | None = None
    created_at: datetime
    updated_at: datetime


class ReviewQueueFinding(BaseModel):
    """The finding fields a reviewer needs before opening the full record.

    ``id`` is the database row id (for ``GET /findings/{id}``);
    ``fingerprint`` is the cross-scan logical identity.
    """

    id: str
    fingerprint: str
    scan_id: str
    algorithm: str
    api: str
    operation: CryptoOperation
    role: CryptographicRole
    confidence: MatchConfidence
    priority: str
    review_path: PqcReviewPath
    is_migration_candidate: bool
    file_path: str
    start_line: int


class ReviewQueueRow(BaseModel):
    """One review-queue entry: the workflow state plus its finding."""

    review: ReviewItemRead
    finding: ReviewQueueFinding
