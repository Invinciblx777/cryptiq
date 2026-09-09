"""Rules: match cryptographic constructs in an AST and emit raw observations.

A rule reports only what the syntax establishes. Roles, impact, post-quantum
review paths and priority are decided by later stages from these observations.
"""

from app.engine.rules.base import (
    AnalysisContext,
    CryptoOperation,
    CryptoRule,
    EvidenceBasis,
    MatchConfidence,
    RuleMatch,
)
from app.engine.rules.registry import (
    all_rules,
    get_rule,
    register,
    registered_rule_ids,
)
from app.engine.rules.rsa import RSA_MODULE, RsaRule
from app.engine.rules.rsa import RULE_ID as RSA_RULE_ID
from app.engine.rules.runner import evaluate_file, evaluate_files

__all__ = [
    "RSA_MODULE",
    "RSA_RULE_ID",
    "AnalysisContext",
    "CryptoOperation",
    "CryptoRule",
    "EvidenceBasis",
    "MatchConfidence",
    "RsaRule",
    "RuleMatch",
    "all_rules",
    "evaluate_file",
    "evaluate_files",
    "get_rule",
    "register",
    "registered_rule_ids",
]
