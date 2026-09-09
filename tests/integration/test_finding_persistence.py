"""Persisting an analysed result: the object graph, dedup, counters, rollback."""

from pathlib import Path

import pytest

from app.db.models import AuditEvent, Evidence, Finding, ImpactNode, ReviewItem, Scan
from app.db.models.enums import AuditEventType, FindingStatus, ReviewStatus
from app.db.repositories import apply_analysis_counts, persist_analysis
from app.engine.ingestion import (
    IngestionLimits,
    RepositoryReference,
    SourceSnapshot,
)
from app.engine.ingestion.service import build_result
from app.engine.pipeline import analyze_snapshot
from tests.support import write_tree

LIMITS = IngestionLimits(
    max_archive_bytes=1024 * 1024,
    max_extracted_bytes=1024 * 1024,
    max_files=100,
    max_file_bytes=8192,
)
REFERENCE = RepositoryReference(
    provider="github",
    owner="pyca",
    name="cryptography",
    canonical_url="https://github.com/pyca/cryptography",
)
COMMIT = "1f903f5ed2e5e316f345a927555e48535829d8de"
IMPORT = b"from cryptography.hazmat.primitives.asymmetric import rsa\n"

MIXED_TREE = {
    "src/signing.py": IMPORT
    + b"class Signer:\n"
    + b"    def sign(self, key: rsa.RSAPrivateKey, payload):\n"
    + b"        return key.sign(payload)\n",
    "src/keys.py": IMPORT + b"def build():\n    return rsa.generate_private_key()\n",
}

DUPLICATE_TREE = {
    "src/twice.py": IMPORT
    + b"def build():\n"
    + b"    first = rsa.generate_private_key()\n"
    + b"    second = rsa.generate_private_key()\n"
    + b"    return first, second\n",
}


def _analyze(tmp_path: Path, tree: dict[str, bytes]):
    root = write_tree(tmp_path / "snapshot", tree)
    snapshot = SourceSnapshot(
        root_path=root,
        repository=REFERENCE,
        commit_sha=COMMIT,
        content_hash="0" * 64,
        file_count=len(tree),
    )
    return analyze_snapshot(build_result(snapshot, LIMITS), root)


def test_every_finding_is_persisted_with_its_evidence(session, scan, tmp_path) -> None:
    result = _analyze(tmp_path, MIXED_TREE)

    with session.begin():
        outcome = persist_analysis(session, scan, result)

    findings = session.query(Finding).filter_by(scan_id=scan.id).all()
    assert len(findings) == outcome.finding_count == 2
    for finding in findings:
        assert finding.status is FindingStatus.ACTIVE
        assert finding.evidence is not None
        assert finding.evidence.source_excerpt.strip()
        assert finding.evidence.repository_sha == COMMIT
        assert finding.evidence.parser_version
        assert finding.evidence.ruleset_version
    assert session.query(Evidence).count() == 2


def test_impact_nodes_are_persisted_from_the_engine_graph(session, scan, tmp_path) -> None:
    result = _analyze(tmp_path, MIXED_TREE)

    with session.begin():
        outcome = persist_analysis(session, scan, result)

    nodes = session.query(ImpactNode).all()
    assert len(nodes) == outcome.impact_node_count > 0
    # The algorithm root node has no relationship and is not persisted.
    assert all(node.relationship_type is not None for node in nodes)
    labels = {node.label for node in nodes}
    assert "src/signing.py" in labels


def test_one_open_review_item_per_finding(session, scan, tmp_path) -> None:
    result = _analyze(tmp_path, MIXED_TREE)

    with session.begin():
        persist_analysis(session, scan, result)

    items = session.query(ReviewItem).all()
    assert len(items) == 2
    assert {item.status for item in items} == {ReviewStatus.OPEN}


def test_a_finding_created_event_is_recorded_per_finding(session, scan, tmp_path) -> None:
    result = _analyze(tmp_path, MIXED_TREE)

    with session.begin():
        persist_analysis(session, scan, result)

    events = session.query(AuditEvent).filter_by(event_type=AuditEventType.FINDING_CREATED).all()
    assert len(events) == 2
    assert all(e.finding_id is not None for e in events)
    assert all("source" not in e.event_metadata for e in events)


def test_duplicate_fingerprints_collapse_to_one_finding(session, scan, tmp_path) -> None:
    result = _analyze(tmp_path, DUPLICATE_TREE)

    # The engine reports both call sites as separate observations...
    assert len(result.findings) == 2
    assert result.findings[0].fingerprint == result.findings[1].fingerprint

    with session.begin():
        outcome = persist_analysis(session, scan, result)

    # ...but persistence keeps exactly one, with one evidence and one review.
    assert outcome.finding_count == 1
    assert outcome.duplicate_observations == 1
    assert session.query(Finding).count() == 1
    assert session.query(Evidence).count() == 1
    assert session.query(ReviewItem).count() == 1
    assert session.get(Scan, scan.id).finding_count == 1


def test_scan_counters_come_from_the_analysis_result(session, scan, tmp_path) -> None:
    result = _analyze(tmp_path, MIXED_TREE)

    with session.begin():
        persist_analysis(session, scan, result)
        apply_analysis_counts(scan, result)

    stored = session.get(Scan, scan.id)
    assert stored.file_count == result.total_files
    assert stored.analyzed_file_count == result.analyzed_files
    assert stored.skipped_file_count == result.skipped_files
    assert stored.finding_count == 2


def test_a_failed_persist_leaves_nothing_behind(session, scan, tmp_path) -> None:
    result = _analyze(tmp_path, MIXED_TREE)

    with pytest.raises(RuntimeError), session.begin():
        persist_analysis(session, scan, result)
        raise RuntimeError("boom after persist, before commit")

    assert session.query(Finding).count() == 0
    assert session.query(Evidence).count() == 0
    assert session.query(ImpactNode).count() == 0
    assert session.query(ReviewItem).count() == 0
    assert session.get(Scan, scan.id).finding_count == 0
