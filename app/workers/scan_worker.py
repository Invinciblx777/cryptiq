"""A single-process, database-backed scan worker.

The loop is deliberately plain: claim the oldest QUEUED job, run it, close
it. No broker, no threads, no distributed queue. On SQLite one worker runs;
the claim query switches to ``FOR UPDATE SKIP LOCKED`` on PostgreSQL so the
same loop scales to several processes later.

Security boundary: the worker only fetches an archive over HTTPS and parses
it with Python's ``ast``. It never executes, imports, installs or shells out
to repository code.
"""

import asyncio
import logging
import os
import time
from datetime import timedelta

from sqlalchemy.orm import sessionmaker

from app.db.database import SessionLocal
from app.db.models.base import utcnow
from app.db.models.enums import AuditEventType
from app.db.models.scan_job import ScanJob
from app.db.repositories import (
    claim_next_job,
    complete_job,
    fail_job,
    get_scan,
    mark_failed,
    reclaim_stale_jobs,
    release_for_retry,
    reset_to_queued,
)
from app.db.repositories.audit_repo import record_event
from app.engine.ingestion.source import SourceProvider
from app.errors import CryptiqError
from app.services.scan_execution import execute_scan
from app.services.scan_jobs import should_retry

logger = logging.getLogger(__name__)

DEFAULT_POLL_SECONDS = 2.0
DEFAULT_STALE_AFTER = timedelta(minutes=15)
_GENERIC_ERROR_CODE = "SCAN_EXECUTION_FAILED"
_GENERIC_ERROR_MESSAGE = "Scan execution failed."


def _safe_error(exc: BaseException) -> tuple[str, str]:
    """Return a client-safe (code, message) for a failure.

    A CryptiqError already carries a stable code and a written message. Any
    other exception is reduced to a generic pair so no traceback text is
    persisted.
    """
    if isinstance(exc, CryptiqError):
        return exc.code, exc.message
    return _GENERIC_ERROR_CODE, _GENERIC_ERROR_MESSAGE


class ScanWorker:
    """Claims and runs scan jobs until asked to stop."""

    def __init__(
        self,
        *,
        session_factory: sessionmaker = SessionLocal,
        worker_id: str | None = None,
        provider_factory=None,
        poll_seconds: float = DEFAULT_POLL_SECONDS,
        stale_after: timedelta = DEFAULT_STALE_AFTER,
    ) -> None:
        self._session_factory = session_factory
        self._worker_id = worker_id or f"scan-worker-{os.getpid()}"
        self._provider_factory = provider_factory
        self._poll_seconds = poll_seconds
        self._stale_after = stale_after
        self._stop = False

    def request_stop(self) -> None:
        """Ask the loop to exit after the current job."""
        self._stop = True

    def run_once(self) -> bool:
        """Claim and run one job. Return False when the queue was empty."""
        with self._session_factory() as session:
            job = claim_next_job(session, self._worker_id)
            if job is None:
                return False
            job_id, scan_id, attempt = job.id, job.scan_id, job.attempt_count

        logger.info("worker %s claimed job %s (scan %s, attempt %d)",
                    self._worker_id, job_id, scan_id, attempt)
        try:
            asyncio.run(
                execute_scan(
                    scan_id,
                    session_factory=self._session_factory,
                    provider=self._make_provider(),
                )
            )
        except (KeyboardInterrupt, SystemExit):
            self._handle_failure(job_id, scan_id, RuntimeError("worker interrupted"))
            raise
        except BaseException as exc:  # noqa: BLE001 - a bad job must not kill the worker
            self._handle_failure(job_id, scan_id, exc)
            return True

        with self._session_factory() as session:
            complete_job(session, session.get(ScanJob, job_id))
            session.commit()
        logger.info("worker %s completed job %s (scan %s)", self._worker_id, job_id, scan_id)
        return True

    def run_forever(self) -> None:
        """Loop until ``request_stop`` or an interrupt."""
        logger.info("scan worker %s started", self._worker_id)
        while not self._stop:
            try:
                did_work = self.run_once()
            except (KeyboardInterrupt, SystemExit):
                logger.info("scan worker %s stopping", self._worker_id)
                return
            if not did_work:
                self._reclaim_stale()
                time.sleep(self._poll_seconds)
        logger.info("scan worker %s stopped", self._worker_id)

    def _make_provider(self) -> SourceProvider | None:
        return self._provider_factory() if self._provider_factory is not None else None

    def _handle_failure(self, job_id: str, scan_id: str, exc: BaseException) -> None:
        code, message = _safe_error(exc)
        with self._session_factory() as session:
            job = session.get(ScanJob, job_id)
            scan = get_scan(session, scan_id)
            if job is None:
                return
            if should_retry(job):
                release_for_retry(session, job, message)
                if scan is not None:
                    reset_to_queued(scan)
                logger.warning(
                    "job %s (scan %s) failed on attempt %d, requeued: %s",
                    job_id, scan_id, job.attempt_count, code,
                )
            else:
                fail_job(session, job, message)
                if scan is not None:
                    mark_failed(scan, code=code, message=message)
                    record_event(
                        session,
                        AuditEventType.SCAN_FAILED,
                        scan_id=scan_id,
                        metadata={"error_code": code, "attempts": job.attempt_count},
                    )
                logger.error(
                    "job %s (scan %s) failed permanently after %d attempts: %s",
                    job_id, scan_id, job.attempt_count, code,
                )
            session.commit()

    def _reclaim_stale(self) -> None:
        cutoff = utcnow() - self._stale_after
        try:
            with self._session_factory() as session:
                reclaimed = reclaim_stale_jobs(session, cutoff)
        except Exception:
            logger.exception("stale-job reclaim failed")
            return
        if reclaimed:
            logger.info("worker %s reclaimed %d stale job(s)", self._worker_id, reclaimed)


def main() -> None:
    """Console entry point: run a worker against the configured database."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    ScanWorker().run_forever()


if __name__ == "__main__":
    main()
