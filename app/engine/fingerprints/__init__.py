"""Stable fingerprints for findings.

A fingerprint identifies the same finding across scans, so a result can be
tracked, deduplicated and marked as reviewed. It is a hash of canonical parts
only, never of line numbers or timestamps, which drift between commits.
"""

import hashlib

_SEPARATOR = "\x1f"


def fingerprint(*parts: str) -> str:
    """Return a hex SHA-256 fingerprint over the given canonical parts.

    Parts are joined with a separator that cannot appear in them, so distinct
    inputs cannot collide by concatenation.
    """
    if not parts:
        raise ValueError("fingerprint requires at least one part")
    if any(_SEPARATOR in part for part in parts):
        raise ValueError("fingerprint parts must not contain the unit separator")
    payload = _SEPARATOR.join(parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
