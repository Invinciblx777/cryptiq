"""Explanation: a natural-language rendering of an existing deterministic finding.

An explanation never establishes a fact. It restates what the engine already
found. The provider and model columns record which system produced the text;
no generation happens in this phase.
"""

from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base
from app.db.models.base import ID_LENGTH, CreatedAtMixin, UUIDPrimaryKeyMixin
from app.db.models.enums import ExplanationStatus, enum_column

if TYPE_CHECKING:
    from app.db.models.finding import Finding


class Explanation(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """A generated explanation of one finding."""

    __tablename__ = "explanations"

    finding_id: Mapped[str] = mapped_column(
        String(ID_LENGTH),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[ExplanationStatus] = mapped_column(
        enum_column(ExplanationStatus, "explanation_status"),
        nullable=False,
        default=ExplanationStatus.PENDING,
    )

    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    what_was_found: Mapped[str | None] = mapped_column(Text, nullable=True)
    what_it_means: Mapped[str | None] = mapped_column(Text, nullable=True)
    why_it_matters: Mapped[str | None] = mapped_column(Text, nullable=True)
    review_action: Mapped[str | None] = mapped_column(Text, nullable=True)

    finding: Mapped["Finding"] = relationship(back_populates="explanations")
