"""The HTTP API over a real scan of pyca/cryptography.

Enable with CRYPTIQ_RUN_NETWORK_TESTS=1. Submits a scan through the API, runs
the worker against the real GitHub provider, then checks that every endpoint's
response matches the persisted database state.
"""

import os
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.database import Base
from app.db.models import Finding, Scan
from app.dependencies import get_db
from app.integrations.github import GitHubSourceProvider
from app.main import create_app
from app.workers import ScanWorker

REPOSITORY_URL = "https://github.com/pyca/cryptography"
COMMIT_SHA = "1f903f5ed2e5e316f345a927555e48535829d8de"

pytestmark = [
    pytest.mark.network,
    pytest.mark.skipif(
        os.getenv("CRYPTIQ_RUN_NETWORK_TESTS") != "1",
        reason="set CRYPTIQ_RUN_NETWORK_TESTS=1 to run tests that reach GitHub",
    ),
]


@pytest.fixture(scope="module")
def engine() -> Iterator[Engine]:
    engine = create_engine(
        "sqlite://",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _fk_on(connection, _record) -> None:
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    try:
        yield engine
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.fixture(scope="module")
def session_factory(engine: Engine) -> sessionmaker:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@pytest.fixture(scope="module")
def client(session_factory: sessionmaker) -> Iterator[TestClient]:
    app = create_app()

    def _get_db() -> Iterator[Session]:
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture(scope="module")
def scan_id(client: TestClient, session_factory: sessionmaker) -> str:
    created = client.post(
        "/api/v1/scans",
        json={"repository_url": REPOSITORY_URL, "commit_sha": COMMIT_SHA},
    )
    assert created.status_code == 202
    identifier = created.json()["scan_id"]

    worker = ScanWorker(
        session_factory=session_factory,
        worker_id="api-acceptance",
        provider_factory=GitHubSourceProvider,
    )
    assert worker.run_once() is True
    return identifier


def test_get_scan_matches_the_database(client: TestClient, scan_id, session_factory) -> None:
    body = client.get(f"/api/v1/scans/{scan_id}").json()

    with session_factory() as session:
        scan = session.get(Scan, scan_id)

    assert body["status"] == "COMPLETED" == scan.status.value
    assert body["source_state"] == "LIVE"
    assert body["commit_sha"] == COMMIT_SHA
    assert body["statistics"]["findings"] == scan.finding_count
    assert body["statistics"]["files"] == scan.file_count
    assert body["engine"]["ruleset_version"] == scan.ruleset_version


def test_findings_page_matches_the_database(client: TestClient, scan_id, session_factory) -> None:
    page = client.get(
        f"/api/v1/scans/{scan_id}/findings", params={"page": 1, "page_size": 20}
    ).json()

    with session_factory() as session:
        total = session.query(Finding).filter_by(scan_id=scan_id).count()

    assert page["total"] == total
    assert page["page_size"] == 20
    assert len(page["items"]) == 20
    assert page["pages"] == (total + 19) // 20

    # Walk enough pages to see several algorithm families.
    families: set[str] = set()
    for number in range(1, page["pages"] + 1):
        rows = client.get(
            f"/api/v1/scans/{scan_id}/findings", params={"page": number, "page_size": 200}
        ).json()["items"]
        families.update(row["algorithm"] for row in rows)
    assert {"RSA", "ECDSA", "Ed25519", "AES"} <= families


def test_a_filtered_page_is_a_strict_subset(client: TestClient, scan_id) -> None:
    everything = client.get(
        f"/api/v1/scans/{scan_id}/findings", params={"page_size": 1}
    ).json()["total"]
    rsa_only = client.get(
        f"/api/v1/scans/{scan_id}/findings", params={"page_size": 1, "algorithm": "RSA"}
    ).json()["total"]

    assert 0 < rsa_only < everything


def test_finding_detail_matches_the_database(client: TestClient, scan_id, session_factory) -> None:
    item = client.get(
        f"/api/v1/scans/{scan_id}/findings", params={"page_size": 1}
    ).json()["items"][0]

    body = client.get(f"/api/v1/findings/{item['id']}").json()

    with session_factory() as session:
        row = session.get(Finding, item["id"])

    assert body["fingerprint"] == row.fingerprint
    assert body["observed"]["algorithm"] == row.algorithm
    assert body["observed"]["api"] == row.api
    assert body["inference"]["role"] == row.role.value
    assert body["priority"]["level"] == row.priority.value
    assert body["impact"]["relationships"] == []


def test_review_queue_matches_the_database(client: TestClient, scan_id, session_factory) -> None:
    body = client.get(
        "/api/v1/review-queue", params={"scan_id": scan_id, "page_size": 10}
    ).json()

    with session_factory() as session:
        scan = session.get(Scan, scan_id)

    assert body["total"] == scan.finding_count
    assert len(body["items"]) == 10
    assert all(row["review"]["status"] == "OPEN" for row in body["items"])


def test_a_review_update_round_trips_over_http(client: TestClient, scan_id) -> None:
    review_id = client.get(
        "/api/v1/review-queue", params={"scan_id": scan_id, "page_size": 1}
    ).json()["items"][0]["review"]["id"]

    started = client.patch(
        f"/api/v1/review-items/{review_id}", json={"status": "IN_REVIEW"}
    )
    assert started.status_code == 200 and started.json()["status"] == "IN_REVIEW"

    reviewed = client.patch(
        f"/api/v1/review-items/{review_id}", json={"status": "REVIEWED", "note": "ok"}
    )
    assert reviewed.status_code == 200 and reviewed.json()["status"] == "REVIEWED"

    # REVIEWED -> OPEN skips a step and is refused.
    bad = client.patch(f"/api/v1/review-items/{review_id}", json={"status": "OPEN"})
    assert bad.status_code == 409
    assert bad.json()["error"]["code"] == "INVALID_REVIEW_TRANSITION"


def test_a_second_submission_is_served_from_cache(client: TestClient, scan_id) -> None:
    again = client.post(
        "/api/v1/scans",
        json={"repository_url": REPOSITORY_URL, "commit_sha": COMMIT_SHA},
    )

    assert again.status_code == 200
    body = again.json()
    assert body["cached"] is True
    assert body["scan_id"] == scan_id
    assert body["status"] == "COMPLETED"
