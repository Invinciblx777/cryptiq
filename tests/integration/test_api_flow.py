"""The whole API path over HTTP, with a fake source provider and the real worker.

POST /scans -> worker runs the scan -> GET /scans/{id} -> GET findings page ->
GET one finding -> GET review-queue -> PATCH a review item. No network.
"""

import pytest

from app.db.models.enums import ScanJobStatus
from app.db.models.scan import Scan
from app.db.models.scan_job import ScanJob
from app.dependencies import get_commit_resolver
from app.workers import ScanWorker
from tests.support import ACCEPTANCE_SHA, FakeCommitResolver, FakeSourceProvider

IMPORT = b"from cryptography.hazmat.primitives.asymmetric import rsa\n"
TREE = {
    "src/sign.py": IMPORT
    + b"class Signer:\n"
    + b"    def run(self, key: rsa.RSAPrivateKey, data):\n"
    + b"        return key.sign(data)\n",
    "src/keys.py": IMPORT + b"def build():\n    return rsa.generate_private_key()\n",
}


@pytest.fixture
def flow(api_client, session_factory):
    api_client.app.dependency_overrides[get_commit_resolver] = lambda: FakeCommitResolver()

    created = api_client.post(
        "/api/v1/scans",
        json={
            "repository_url": "https://github.com/pyca/cryptography",
            "commit_sha": "1f903f5",  # short ref, resolved by the fake resolver
        },
    )
    assert created.status_code == 202
    scan_id = created.json()["scan_id"]

    worker = ScanWorker(
        session_factory=session_factory,
        worker_id="api-flow",
        provider_factory=lambda: FakeSourceProvider(TREE),
    )
    assert worker.run_once() is True

    return api_client, scan_id, session_factory


def test_post_scans_returns_202_and_queues_a_job(api_client, session_factory) -> None:
    api_client.app.dependency_overrides[get_commit_resolver] = lambda: FakeCommitResolver()

    response = api_client.post(
        "/api/v1/scans",
        json={"repository_url": "https://github.com/pyca/cryptography", "commit_sha": "1f903f5"},
    )

    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "QUEUED"
    assert body["cached"] is False
    with session_factory() as session:
        scan = session.get(Scan, body["scan_id"])
        assert scan.commit_sha == ACCEPTANCE_SHA  # stored full, not the short ref
        job = session.query(ScanJob).filter_by(scan_id=scan.id).one()
        assert job.status is ScanJobStatus.QUEUED


def test_get_scan_reflects_persisted_state(flow) -> None:
    api_client, scan_id, session_factory = flow

    response = api_client.get(f"/api/v1/scans/{scan_id}")
    assert response.status_code == 200
    body = response.json()

    assert body["scan_id"] == scan_id
    assert body["status"] == "COMPLETED"
    assert body["source_state"] == "LIVE"
    assert body["commit_sha"] == ACCEPTANCE_SHA
    assert body["repository"] == {
        "provider": "github",
        "owner": "pyca",
        "name": "cryptography",
        "url": "https://github.com/pyca/cryptography",
    }
    assert body["engine"]["parser_version"]
    with session_factory() as session:
        scan = session.get(Scan, scan_id)
        assert body["statistics"] == {
            "files": scan.file_count,
            "analyzed": scan.analyzed_file_count,
            "skipped": scan.skipped_file_count,
            "findings": scan.finding_count,
        }


def test_findings_page_is_paginated_and_matches_the_count(flow) -> None:
    api_client, scan_id, _ = flow

    first = api_client.get(f"/api/v1/scans/{scan_id}/findings", params={"page": 1, "page_size": 1})
    assert first.status_code == 200
    body = first.json()

    assert body["page"] == 1
    assert body["page_size"] == 1
    assert len(body["items"]) == 1
    assert body["total"] >= 2
    assert body["pages"] == body["total"]  # page_size 1

    scan = api_client.get(f"/api/v1/scans/{scan_id}").json()
    assert body["total"] == scan["statistics"]["findings"]


def test_finding_detail_has_the_canonical_shape(flow) -> None:
    api_client, scan_id, _ = flow

    page = api_client.get(f"/api/v1/scans/{scan_id}/findings").json()
    item = page["items"][0]
    assert "rationale" not in item  # list rows stay lean

    detail = api_client.get(f"/api/v1/findings/{item['id']}")
    assert detail.status_code == 200
    body = detail.json()

    assert set(body) == {
        "id",
        "fingerprint",
        "scan_id",
        "repository",
        "commit_sha",
        "observed",
        "inference",
        "migration",
        "impact",
        "priority",
        "review",
    }
    assert body["id"] == item["id"]
    assert body["fingerprint"] == item["fingerprint"]
    # observed vs inference separation
    assert "role" not in body["observed"]
    assert "confidence" not in body["observed"]
    assert body["inference"]["role"]
    assert body["inference"]["confidence"]
    assert body["inference"]["rationale"]
    assert body["inference"]["evidence_basis"] is None  # not persisted
    assert body["migration"]["review_path"]
    assert body["priority"]["level"]
    assert body["priority"]["score"] is None  # not persisted
    assert body["priority"]["reasons"] == []
    assert body["impact"]["relationships"] == []  # edges not persisted
    assert body["review"]["status"] == "OPEN"


def test_review_queue_and_update_round_trip(flow) -> None:
    api_client, scan_id, _ = flow

    queue = api_client.get("/api/v1/review-queue", params={"scan_id": scan_id})
    assert queue.status_code == 200
    body = queue.json()
    assert body["total"] >= 2
    row = body["items"][0]
    assert set(row) == {"review", "finding"}
    assert row["review"]["status"] == "OPEN"
    review_id = row["review"]["id"]

    started = api_client.patch(
        f"/api/v1/review-items/{review_id}",
        json={"status": "IN_REVIEW", "assigned_to": "alice", "note": "taking a look"},
    )
    assert started.status_code == 200
    assert started.json()["status"] == "IN_REVIEW"
    assert started.json()["assigned_to"] == "alice"

    done = api_client.patch(
        f"/api/v1/review-items/{review_id}", json={"status": "REVIEWED"}
    )
    assert done.status_code == 200
    assert done.json()["status"] == "REVIEWED"

    open_only = api_client.get(
        "/api/v1/review-queue", params={"scan_id": scan_id, "status": "OPEN"}
    ).json()
    assert review_id not in {item["review"]["id"] for item in open_only["items"]}


def test_a_cached_second_submission_reuses_the_scan(flow) -> None:
    api_client, scan_id, _ = flow
    api_client.app.dependency_overrides[get_commit_resolver] = lambda: FakeCommitResolver()

    again = api_client.post(
        "/api/v1/scans",
        json={
            "repository_url": "https://github.com/pyca/cryptography",
            "commit_sha": ACCEPTANCE_SHA,
        },
    )

    assert again.status_code == 200  # not 202: nothing queued
    body = again.json()
    assert body["cached"] is True
    assert body["scan_id"] == scan_id
    assert body["status"] == "COMPLETED"
