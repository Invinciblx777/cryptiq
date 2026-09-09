"""Executing one scan: ingest the exact commit, analyse it, persist the result.

The engine stays provider-neutral; the provider is chosen here. The source
snapshot lives only inside the ``ingest_commit`` block, so the analysis --
which captures every evidence excerpt -- runs there, and the database work
runs afterwards against the returned result, which holds no paths into the
snapshot.

Sessions are short-lived: one to mark the scan RUNNING, then none while the
archive is fetched and analysed, then one transaction for the whole persisted
graph. A failure in any step propagates to the caller (the worker), which
decides retry or permanent failure; nothing half-written is left as COMPLETED
because the persist step is a single transaction.
"""

import logging
import time

from sqlalchemy.orm import sessionmaker

from app.db.database import SessionLocal
from app.db.models.enums import AuditEventType, ScanStatus, SourceState
from app.db.models.repository import Repository
from app.db.repositories import (
    apply_analysis_counts,
    get_scan,
    mark_completed,
    mark_running,
    persist_analysis,
    record_event,
)
from app.engine.ingestion import RepositoryReference
from app.engine.ingestion.service import ingest_commit
from app.engine.ingestion.source import SourceProvider
from app.engine.pipeline import analyze_snapshot
from app.errors import ScanNotFoundError

logger = logging.getLogger(__name__)

__all__ = ["ScanNotFoundError", "execute_scan"]


def _default_provider() -> SourceProvider:
    # Imported lazily so the engine and this module never import the provider
    # package at load time.
    from app.integrations.github import GitHubSourceProvider

    return GitHubSourceProvider()


async def execute_scan(
    scan_id: str,
    *,
    session_factory: sessionmaker = SessionLocal,
    provider: SourceProvider | None = None,
) -> None:
    """Run the full pipeline for one scan and persist it, or raise.

    Idempotent on a scan that already reached a terminal state: it logs and
    returns. Any other outcome -- ingestion failure, analysis failure,
    persistence failure -- raises, leaving the scan RUNNING for the worker to
    resolve.
    """
    started = time.monotonic()

    with session_factory() as session:
        scan = get_scan(session, scan_id)
        if scan is None:
            raise ScanNotFoundError(f"Scan {scan_id!r} was not found.")
        if scan.status in {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}:
            logger.info("scan %s is already %s; nothing to execute", scan_id, scan.status.value)
            return

        repo = session.get(Repository, scan.repository_id)
        reference = RepositoryReference(
            provider=repo.provider,
            owner=repo.owner,
            name=repo.name,
            canonical_url=repo.canonical_url,
        )
        commit_sha = scan.commit_sha
        mark_running(scan)
        record_event(session, AuditEventType.SCAN_STARTED, scan_id=scan_id)
        session.commit()

    source_provider = provider or _default_provider()

    async with ingest_commit(source_provider, reference, commit_sha) as ingestion:
        result = analyze_snapshot(ingestion, ingestion.snapshot.root_path)

    with session_factory() as session, session.begin():
        scan = get_scan(session, scan_id)
        outcome = persist_analysis(session, scan, result)
        apply_analysis_counts(scan, result)
        mark_completed(scan, source_state=SourceState.LIVE)
        record_event(
            session,
            AuditEventType.SCAN_COMPLETED,
            scan_id=scan_id,
            metadata={
                "finding_count": scan.finding_count,
                "file_count": scan.file_count,
                "analyzed_file_count": scan.analyzed_file_count,
                "skipped_file_count": scan.skipped_file_count,
            },
        )

    logger.info(
        "scan %s COMPLETED repo=%s commit=%s files=%d analyzed=%d skipped=%d "
        "findings=%d evidence=%d impact_nodes=%d review_items=%d duplicates=%d duration=%.2fs",
        scan_id,
        reference.slug,
        commit_sha,
        result.total_files,
        result.analyzed_files,
        result.skipped_files,
        outcome.finding_count,
        outcome.evidence_count,
        outcome.impact_node_count,
        outcome.review_item_count,
        outcome.duplicate_observations,
        time.monotonic() - started,
    )
