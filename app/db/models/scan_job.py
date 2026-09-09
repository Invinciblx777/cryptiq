"""ScanJob: the queued unit of work that executes a scan.

The columns are shaped for a database-backed worker: a poller claims a QUEUED
row, stamps locked_at, and increments attempt_count on each retry. The worker
itself is a later phase.
"""

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base
from app.db.models.base import ID_LENGTH, CreatedAtMixin, UUIDPrimaryKeyMixin
from app.db.models.enums import ScanJobStatus, enum_column

if TYPE_CHECKING:
    from app.db.models.scan import Scan


class ScanJob(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """A claimable execution attempt for one scan."""

    __tablename__ = "scan_jobs"
    __table_args__ = (
        Index("ix_scan_jobs_scan_id", "scan_id"),
        Index("ix_scan_jobs_status", "status"),
    )

    scan_id: Mapped[str] = mapped_column(
        String(ID_LENGTH),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    status: Mapped[ScanJobStatus] = mapped_column(
        enum_column(ScanJobStatus, "scan_job_status"),
        nullable=False,
        default=ScanJobStatus.QUEUED,
    )
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="jobs")
