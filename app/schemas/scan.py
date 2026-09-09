"""Scan schemas for the domain and API boundary."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.db.models.enums import ScanStatus, SourceState
from app.schemas.finding import RepositoryRef


class ScanCreate(BaseModel):
    """The internal request to analyse a repository at an exact commit."""

    repository_id: str
    commit_sha: str = Field(min_length=7, max_length=40)
    base_commit_sha: str | None = Field(default=None, min_length=7, max_length=40)


class ScanRequest(BaseModel):
    """The HTTP request body for POST /api/v1/scans.

    ``commit_sha`` may be a short reference (7-40 hex characters); the API
    resolves it to the full 40-character SHA before a scan is stored.
    """

    repository_url: str = Field(min_length=1, max_length=1024)
    commit_sha: str = Field(pattern=r"^[0-9a-fA-F]{7,40}$")


class ScanAccepted(BaseModel):
    """The response to a scan request: the scan exists, work is queued.

    ``cached`` is true when an identical completed scan was reused; in that
    case ``status`` is already COMPLETED and no job was queued.
    """

    scan_id: str
    status: ScanStatus
    cached: bool


class ScanStatistics(BaseModel):
    """File and finding counters for a scan."""

    files: int
    analyzed: int
    skipped: int
    findings: int


class ScanEngine(BaseModel):
    """The version stamps that make a scan reproducible."""

    parser_version: str
    ruleset_version: str
    pqc_ruleset_version: str


class ScanDetail(BaseModel):
    """A stored scan as the API exposes it, with counters and repository nested."""

    scan_id: str
    status: ScanStatus
    source_state: SourceState
    repository: RepositoryRef
    commit_sha: str
    base_commit_sha: str | None = None
    statistics: ScanStatistics
    engine: ScanEngine
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_code: str | None = None
    error_message: str | None = None
    created_at: datetime


class ScanRead(BaseModel):
    """A stored scan, flat, including the version stamps that make it reproducible."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    repository_id: str
    commit_sha: str
    base_commit_sha: str | None
    status: ScanStatus
    source_state: SourceState
    parser_version: str
    ruleset_version: str
    pqc_ruleset_version: str
    file_count: int
    analyzed_file_count: int
    skipped_file_count: int
    finding_count: int
    started_at: datetime | None
    completed_at: datetime | None
    error_code: str | None
    error_message: str | None
    created_at: datetime
