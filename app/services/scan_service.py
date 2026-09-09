"""The service surface the eventual API will call.

Everything here is a plain function taking a Session. No HTTP, no routes. The
one piece of real logic is scan creation, which consults the scan cache: an
identical COMPLETED scan is reused rather than a new run being queued.
"""

import logging
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.db import repositories as repo
from app.db.models.enums import AuditEventType, ReviewStatus
from app.db.models.finding import Finding
from app.db.models.review_item import ReviewItem
from app.db.models.scan import Scan
from app.db.models.scan_job import ScanJob
from app.engine.engine import engine_versions
from app.engine.fingerprints import ScanIdentity
from app.engine.ingestion import RepositoryReference
from app.errors import InvalidCommitShaError
from app.services.reference_resolver import CommitResolver, resolve_commit_reference
from app.services.scan_cache import find_completed_scan, mark_served_from_cache

logger = logging.getLogger(__name__)

_FULL_SHA_LENGTH = 40


@dataclass(frozen=True)
class ScanCreation:
    """The outcome of a create_scan call.

    ``job`` is None when an existing completed scan was reused: nothing new
    needs to run.
    """

    scan: Scan
    job: ScanJob | None
    cached: bool


def _full_sha(commit_sha: str) -> str:
    candidate = commit_sha.strip().lower()
    if len(candidate) != _FULL_SHA_LENGTH or not all(
        character in "0123456789abcdef" for character in candidate
    ):
        raise InvalidCommitShaError("A full 40-character commit SHA is required.")
    return candidate


def create_scan(
    session: Session,
    *,
    repository: RepositoryReference,
    commit_sha: str,
) -> ScanCreation:
    """Create a scan for a repository at an exact commit, or reuse a cached one.

    The repository row is get-or-created. If a COMPLETED scan already exists
    for the same seven-part identity (provider, owner, name, commit, parser
    version, rule-set version, PQC rule-set version), that scan is returned,
    marked CACHED_REAL, and no job is queued. Otherwise a QUEUED scan and a
    QUEUED job are inserted.
    """
    sha = _full_sha(commit_sha)
    repository_row = repo.get_or_create_repository(session, repository)
    versions = engine_versions()
    slug = f"{repository_row.owner}/{repository_row.name}"

    identity = ScanIdentity(
        provider=repository_row.provider,
        owner=repository_row.owner,
        name=repository_row.name,
        commit_sha=sha,
        parser_version=versions.parser_version,
        ruleset_version=versions.ruleset_version,
        pqc_ruleset_version=versions.pqc_ruleset_version,
    )

    cached = find_completed_scan(session, identity)
    if cached is not None:
        mark_served_from_cache(cached)
        repo.record_event(
            session,
            AuditEventType.SCAN_CREATED,
            scan_id=cached.id,
            metadata={"repository": slug, "commit_sha": sha, "cached": True},
        )
        session.commit()
        logger.info("scan request for %s@%s served from cache %s", slug, sha, cached.id)
        return ScanCreation(scan=cached, job=None, cached=True)

    scan = repo.create_scan(session, repository_row, sha)
    job = repo.create_job(session, scan)
    repo.record_event(
        session,
        AuditEventType.SCAN_CREATED,
        scan_id=scan.id,
        metadata={"repository": slug, "commit_sha": sha, "cached": False},
    )
    session.commit()
    logger.info("scan %s queued for %s@%s (job %s)", scan.id, slug, sha, job.id)
    return ScanCreation(scan=scan, job=job, cached=False)


async def submit_scan(
    session: Session,
    *,
    repository_url: str,
    commit_ref: str,
    resolver: CommitResolver | None = None,
) -> ScanCreation:
    """Validate a URL, resolve the ref to a full SHA, and create the scan.

    This is the API entry point: URL parsing raises INVALID_REPOSITORY_URL,
    ref resolution raises INVALID_COMMIT_SHA / REPOSITORY_NOT_FOUND /
    COMMIT_NOT_FOUND / REPOSITORY_UNAVAILABLE, and scan creation is the same
    cache-aware path as ``create_scan``. No archive is fetched here.
    """
    from app.integrations.github import parse_repository_url

    reference = parse_repository_url(repository_url)
    full_sha = await resolve_commit_reference(reference, commit_ref, resolver=resolver)
    return create_scan(session, repository=reference, commit_sha=full_sha)


def get_scan(session: Session, scan_id: str) -> Scan | None:
    """Return a scan by id."""
    return repo.get_scan(session, scan_id)


def list_findings(session: Session, scan_id: str) -> list[Finding]:
    """Return a scan's persisted unique findings, highest priority first."""
    return repo.list_findings(session, scan_id)


def get_finding(session: Session, finding_id: str) -> Finding | None:
    """Return one persisted finding with evidence and impact."""
    return repo.get_finding(session, finding_id)


def get_review_queue(
    session: Session, scan_id: str, *, status: ReviewStatus | None = None
) -> list[ReviewItem]:
    """Return the review queue for a scan."""
    return repo.get_review_queue(session, scan_id, status=status)


def update_review_item(
    session: Session,
    review_id: str,
    *,
    status: ReviewStatus | None = None,
    assigned_to: str | None = None,
    note: str | None = None,
) -> ReviewItem | None:
    """Apply a workflow change to a review item and commit."""
    item = repo.update_review_item(
        session, review_id, status=status, assigned_to=assigned_to, note=note
    )
    if item is not None:
        session.commit()
    return item
