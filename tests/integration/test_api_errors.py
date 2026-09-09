"""Error handling: predictable JSON, no leakage of internals."""

import pytest

from app.dependencies import get_commit_resolver
from app.errors import RepositoryUnavailableError
from tests.support import FakeCommitResolver

URL = "https://github.com/pyca/cryptography"


def test_404_bodies_have_the_error_envelope(api_client) -> None:
    for path in (
        "/api/v1/scans/missing",
        "/api/v1/findings/missing",
    ):
        body = api_client.get(path).json()
        assert set(body) == {"error"}
        assert set(body["error"]) == {"code", "message"}
        assert body["error"]["code"].endswith("_NOT_FOUND")


def test_422_on_a_bad_body_is_structured(api_client) -> None:
    response = api_client.post("/api/v1/scans", json={"repository_url": URL})

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_a_provider_failure_maps_to_502_without_a_body(api_client) -> None:
    api_client.app.dependency_overrides[get_commit_resolver] = lambda: FakeCommitResolver(
        fail_with=RepositoryUnavailableError("The provider could not be reached.")
    )

    response = api_client.post(
        "/api/v1/scans", json={"repository_url": URL, "commit_sha": "1f903f5"}
    )

    assert response.status_code == 502
    body = response.json()
    assert body["error"]["code"] == "REPOSITORY_UNAVAILABLE"
    assert "Traceback" not in body["error"]["message"]


def test_an_unexpected_error_is_a_generic_500(api_client, monkeypatch) -> None:
    def _boom(*_args, **_kwargs):
        raise RuntimeError("internal detail that must not leak")

    monkeypatch.setattr("app.api.v1.scans.get_scan_detail", _boom)

    response = api_client.get("/api/v1/scans/anything")

    assert response.status_code == 500
    body = response.json()
    assert body == {"error": {"code": "internal_error", "message": "Internal server error."}}
    assert "internal detail" not in response.text


@pytest.mark.parametrize("path", ["/health", "/api/v1/health"])
def test_health_needs_no_database(api_client, path) -> None:
    response = api_client.get(path)

    assert response.status_code == 200
    assert response.json()["status"] in {"ok", "healthy"}


def test_cors_headers_are_present_for_an_allowed_origin(api_client) -> None:
    response = api_client.get(
        "/api/v1/health", headers={"Origin": "http://localhost:5173"}
    )

    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert "access-control-allow-credentials" not in response.headers


def test_openapi_documents_every_endpoint(api_client) -> None:
    spec = api_client.get("/openapi.json").json()

    for path in (
        "/api/v1/scans",
        "/api/v1/scans/{scan_id}",
        "/api/v1/scans/{scan_id}/findings",
        "/api/v1/findings/{finding_id}",
        "/api/v1/review-queue",
        "/api/v1/review-items/{review_id}",
    ):
        assert path in spec["paths"], path

    post = spec["paths"]["/api/v1/scans"]["post"]
    assert post["summary"]
    assert "202" in post["responses"]
