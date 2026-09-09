"""Deterministic cryptographic analysis engine.

Pipeline stages, in order: ingestion, discovery, parser, rules, evidence,
impact, priority, fingerprints. Each stage is a separate subpackage and
consumes only the output of the stage before it. ``pipeline`` runs them over
one extracted snapshot.

The roles and pqc stages are declared but not implemented; a finding therefore
carries no cryptographic role and no post-quantum review path yet.
"""

from app.engine.engine import engine_versions
from app.engine.models import EngineVersions
from app.engine.pipeline import AnalysisResult, AnalyzedFinding, analyze_snapshot

__all__ = [
    "AnalysisResult",
    "AnalyzedFinding",
    "EngineVersions",
    "analyze_snapshot",
    "engine_versions",
]
