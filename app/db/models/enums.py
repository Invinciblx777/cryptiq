"""Controlled vocabularies persisted by the domain models.

Every value is stored as its own name, so the database rows stay readable and
the columns render as VARCHAR with a CHECK constraint on both SQLite and
PostgreSQL. Adding a member requires a migration that widens the constraint.
"""

from enum import StrEnum

from sqlalchemy import Enum as SAEnum


class ScanStatus(StrEnum):
    """Lifecycle of a scan."""

    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class SourceState(StrEnum):
    """Where the analysed source snapshot came from."""

    LIVE = "LIVE"
    CACHED_REAL = "CACHED_REAL"
    UNAVAILABLE = "UNAVAILABLE"


class ScanJobStatus(StrEnum):
    """Lifecycle of the unit of work that executes a scan."""

    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class CryptographicRole(StrEnum):
    """What a detected construct does cryptographically."""

    SIGNATURE = "SIGNATURE"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    ENCRYPTION = "ENCRYPTION"
    HASH = "HASH"
    KEY_DERIVATION = "KEY_DERIVATION"
    RANDOMNESS = "RANDOMNESS"
    CERTIFICATE = "CERTIFICATE"
    UNKNOWN = "UNKNOWN"


class Confidence(StrEnum):
    """How certain the deterministic rule is about a match."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ReviewPriority(StrEnum):
    """Migration review priority assigned by the priority stage."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class FindingStatus(StrEnum):
    """Lifecycle of a finding across scans.

    This is not the review workflow; ReviewItem owns that.
    """

    ACTIVE = "ACTIVE"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


class ImpactNodeType(StrEnum):
    """Kind of program element a finding touches."""

    ALGORITHM = "ALGORITHM"
    API = "API"
    FUNCTION = "FUNCTION"
    CLASS = "CLASS"
    MODULE = "MODULE"
    FILE = "FILE"


class ImpactRelationship(StrEnum):
    """How an impact node relates to the finding."""

    USES = "USES"
    CALLS = "CALLS"
    DEFINED_IN = "DEFINED_IN"
    CONTAINS = "CONTAINS"
    IMPORTS = "IMPORTS"


class ReviewStatus(StrEnum):
    """Human review workflow state."""

    OPEN = "OPEN"
    IN_REVIEW = "IN_REVIEW"
    REVIEWED = "REVIEWED"


class ExplanationStatus(StrEnum):
    """State of a generated explanation."""

    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class AuditEventType(StrEnum):
    """Recorded transitions in the pipeline."""

    SCAN_CREATED = "SCAN_CREATED"
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    SCAN_FAILED = "SCAN_FAILED"
    FINDING_CREATED = "FINDING_CREATED"
    REVIEW_STARTED = "REVIEW_STARTED"
    REVIEW_COMPLETED = "REVIEW_COMPLETED"
    EXPLANATION_REQUESTED = "EXPLANATION_REQUESTED"
    EXPLANATION_COMPLETED = "EXPLANATION_COMPLETED"


def enum_column(enum_class: type[StrEnum], constraint_name: str) -> SAEnum:
    """Return a portable VARCHAR-backed enum type with a named CHECK constraint.

    Native database enums are avoided: PostgreSQL would need a CREATE TYPE and
    SQLite has none, so a named check constraint keeps one schema for both.
    """
    return SAEnum(
        enum_class,
        native_enum=False,
        length=32,
        validate_strings=True,
        name=constraint_name,
    )
