"""The review-queue read and the review-item workflow update."""

from app.db.models import AuditEvent
from app.db.models.enums import AuditEventType, ReviewPriority, ReviewStatus
from app.db.repositories import persist_analysis
from app.engine.ingestion import IngestionLimits, RepositoryReference, SourceSnapshot
from app.engine.ingestion.service import build_result
from app.engine.pipeline import analyze_snapshot
from app.services import get_review_queue, update_review_item
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
IMPORT = b"from cryptography.hazmat.primitives.asymmetric import rsa\n"
TREE = {
    "src/a.py": IMPORT
    + b"def sign(key: rsa.RSAPrivateKey, data):\n    return key.sign(data)\n",
    "src/b.py": IMPORT + b"def gen():\n    return rsa.generate_private_key()\n",
}


def _persist(session, scan, tmp_path):
    root = write_tree(tmp_path / "snapshot", TREE)
    snapshot = SourceSnapshot(
        root_path=root,
        repository=REFERENCE,
        commit_sha="1f903f5ed2e5e316f345a927555e48535829d8de",
        content_hash="0" * 64,
        file_count=len(TREE),
    )
    result = analyze_snapshot(build_result(snapshot, LIMITS), root)
    with session.begin():
        persist_analysis(session, scan, result)
    return result


def test_the_queue_has_one_open_item_per_finding(session, scan, tmp_path) -> None:
    _persist(session, scan, tmp_path)

    queue = get_review_queue(session, scan.id)

    assert len(queue) == 2
    assert {item.status for item in queue} == {ReviewStatus.OPEN}
    assert all(item.finding is not None for item in queue)


def test_the_queue_is_ordered_by_finding_priority(session, scan, tmp_path) -> None:
    _persist(session, scan, tmp_path)

    queue = get_review_queue(session, scan.id)
    ranks = [list(ReviewPriority).index(item.finding.priority) for item in queue]

    assert ranks == sorted(ranks)


def test_filtering_the_queue_by_status(session, scan, tmp_path) -> None:
    _persist(session, scan, tmp_path)
    first = get_review_queue(session, scan.id)[0]

    update_review_item(session, first.id, status=ReviewStatus.IN_REVIEW, assigned_to="alice")

    assert len(get_review_queue(session, scan.id, status=ReviewStatus.OPEN)) == 1
    in_review = get_review_queue(session, scan.id, status=ReviewStatus.IN_REVIEW)
    assert [item.id for item in in_review] == [first.id]
    assert in_review[0].assigned_to == "alice"


def test_a_status_change_records_an_audit_event(session, scan, tmp_path) -> None:
    _persist(session, scan, tmp_path)
    item = get_review_queue(session, scan.id)[0]

    update_review_item(session, item.id, status=ReviewStatus.IN_REVIEW)
    update_review_item(session, item.id, status=ReviewStatus.REVIEWED, note="looks fine")

    events = [
        e.event_type
        for e in session.query(AuditEvent).filter_by(finding_id=item.finding_id).all()
    ]
    assert AuditEventType.REVIEW_STARTED in events
    assert AuditEventType.REVIEW_COMPLETED in events
    assert session.get(type(item), item.id).note == "looks fine"


def test_updating_a_missing_review_item_returns_none(session) -> None:
    assert update_review_item(session, "does-not-exist", status=ReviewStatus.REVIEWED) is None
