"""The rule registry.

An explicit table of the rules the engine runs. Rules register themselves here
at import time; nothing is discovered from repository content.
"""

from app.engine.rules.base import CryptoRule
from app.engine.rules.rsa import RULE_ID as RSA_RULE_ID
from app.engine.rules.rsa import RsaRule

_RULES: dict[str, CryptoRule] = {}


def register(rule: CryptoRule) -> None:
    """Register a rule, replacing any earlier rule with the same identifier."""
    _RULES[rule.rule_id] = rule


def get_rule(rule_id: str) -> CryptoRule | None:
    """Return a rule by identifier, or None when it is not registered."""
    return _RULES.get(rule_id)


def all_rules() -> tuple[CryptoRule, ...]:
    """Return every registered rule, ordered by identifier."""
    return tuple(_RULES[rule_id] for rule_id in sorted(_RULES))


def registered_rule_ids() -> tuple[str, ...]:
    """Return the registered rule identifiers, in a stable order."""
    return tuple(sorted(_RULES))


register(RsaRule())

__all__ = [
    "RSA_RULE_ID",
    "all_rules",
    "get_rule",
    "register",
    "registered_rule_ids",
]
