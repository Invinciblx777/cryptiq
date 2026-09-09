"""Append-only audit events for pipeline lifecycle points.

The event is added to the caller's session and committed with the caller's
transaction, so an audited step and its record land together or not at all.
Metadata is small and structural: identifiers, counts and codes only, never
source content or secrets.
"""

from typing import Any

from sqlalchemy.orm import Session

from app.db.models.audit_event import AuditEvent
from app.db.models.enums import AuditEventType


def record_event(
    session: Session,
    event_type: AuditEventType,
    *,
    scan_id: str | None = None,
    finding_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    """Add one audit event to the session without committing it."""
    event = AuditEvent(
        scan_id=scan_id,
        finding_id=finding_id,
        event_type=event_type,
        event_metadata=metadata or {},
    )
    session.add(event)
    return event
