"""POST /api/v1/scans and GET /api/v1/scans/{id}."""

import pytest

from app.dependencies import get_commit_resolver
from app.errors import CommitNotFoundError, RepositoryNotFoundError
from tests.support import ACCEPTANCE_SHA, FakeCommitResolver

URL = "https://github.com/pyca/cryptography"


@pytest.fixture(autouse=True)
def _fake_resolver(api_client):
    api_client.app.dependency_overrides[get_commit_resolver] = lambda: FakeCommitResolver()


def _submit(api_client, **body):
    payload = {"repository_url": URL, "commit_sha": ACCEPTANCE_SHA}
    payload.update(body)
    return api_client.post("/api/v1/scans", json=payload)


def test_a_valid_request_is_accepted_with_202(api_client) -> None:
    response = _submit(api_client)

    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "QUEUED"
    assert body["cached"] is False
    assert len(body["scan_id"]) == 36


def test_a_full_sha_skips_the_resolver(api_client) -> None:
    resolver = FakeCommitResolver()
    api_client.app.dependency_overrides[get_commit_resolver] = lambda: resolver

    _submit(api_client, commit_sha=ACCEPTANCE_SHA)

    assert resolver.calls == 0  # already 40 hex chars


def test_a_short_sha_is_resolved_and_the_full_sha_is_stored(api_client) -> None:
    resolver = FakeCommitResolver(full_sha=ACCEPTANCE_SHA)
    api_client.app.dependency_overrides[get_commit_resolver] = lambda: resolver

    response = _submit(api_client, commit_sha="1f903f5")

    assert response.status_code == 202
    assert resolver.calls == 1
    scan = api_client.get(f"/api/v1/scans/{response.json()['scan_id']}").json()
    assert scan["commit_sha"] == ACCEPTANCE_SHA


def test_an_invalid_url_is_rejected(api_client) -> None:
    response = _submit(api_client, repository_url="https://gitlab.com/x/y")

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_REPOSITORY_URL"


def test_a_malformed_sha_is_rejected_before_resolution(api_client) -> None:
    response = _submit(api_client, commit_sha="nothex!")

    assert response.status_code == 422  # fails the request-body pattern


def test_a_too_short_sha_is_rejected(api_client) -> None:
    response = _submit(api_client, commit_sha="abc")

    assert response.status_code == 422


def test_a_missing_repository_is_reported(api_client) -> None:
    api_client.app.dependency_overrides[get_commit_resolver] = lambda: FakeCommitResolver(
        fail_with=RepositoryNotFoundError("Repository pyca/none was not found.")
    )

    response = _submit(api_client, commit_sha="1f903f5")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "REPOSITORY_NOT_FOUND"


def test_a_missing_commit_is_reported(api_client) -> None:
    api_client.app.dependency_overrides[get_commit_resolver] = lambda: FakeCommitResolver(
        fail_with=CommitNotFoundError("Commit was not found.")
    )

    response = _submit(api_client, commit_sha="1f903f5")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "COMMIT_NOT_FOUND"


def test_getting_a_missing_scan_is_a_structured_404(api_client) -> None:
    response = api_client.get("/api/v1/scans/00000000-0000-0000-0000-000000000000")

    assert response.status_code == 404
    assert response.json() == {
        "error": {"code": "SCAN_NOT_FOUND", "message": "Scan was not found."}
    }


def test_scan_detail_serialises_the_persisted_row(api_client, seeded_scan) -> None:
    body = api_client.get(f"/api/v1/scans/{seeded_scan}").json()

    assert set(body) == {
        "scan_id",
        "status",
        "source_state",
        "repository",
        "commit_sha",
        "base_commit_sha",
        "statistics",
        "engine",
        "started_at",
        "completed_at",
        "error_code",
        "error_message",
        "created_at",
    }
    assert body["status"] == "COMPLETED"
    assert set(body["statistics"]) == {"files", "analyzed", "skipped", "findings"}
    assert set(body["engine"]) == {"parser_version", "ruleset_version", "pqc_ruleset_version"}
    assert set(body["repository"]) == {"provider", "owner", "name", "url"}
    assert "root_path" not in body and "snapshot" not in body


def test_a_cached_identical_request_returns_200_and_reuses_the_scan(
    api_client, seeded_scan
) -> None:
    response = _submit(api_client, commit_sha=ACCEPTANCE_SHA)

    assert response.status_code == 200
    body = response.json()
    assert body["cached"] is True
    assert body["scan_id"] == seeded_scan
    assert body["status"] == "COMPLETED"
