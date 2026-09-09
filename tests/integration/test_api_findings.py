"""GET /api/v1/scans/{id}/findings and GET /api/v1/findings/{id}."""


def _all_items(api_client, scan_id, **params):
    params.setdefault("page_size", 100)
    return api_client.get(f"/api/v1/scans/{scan_id}/findings", params=params).json()


def test_the_findings_list_is_a_page_envelope(api_client, seeded_scan) -> None:
    body = _all_items(api_client, seeded_scan)

    assert set(body) == {"items", "page", "page_size", "total", "pages"}
    assert body["total"] == 2
    assert body["pages"] == 1
    assert len(body["items"]) == 2


def test_pagination_splits_the_result(api_client, seeded_scan) -> None:
    first = api_client.get(
        f"/api/v1/scans/{seeded_scan}/findings", params={"page": 1, "page_size": 1}
    ).json()
    second = api_client.get(
        f"/api/v1/scans/{seeded_scan}/findings", params={"page": 2, "page_size": 1}
    ).json()

    assert first["total"] == second["total"] == 2
    assert first["pages"] == 2
    assert len(first["items"]) == len(second["items"]) == 1
    assert first["items"][0]["id"] != second["items"][0]["id"]


def test_an_out_of_range_page_is_empty_not_an_error(api_client, seeded_scan) -> None:
    body = api_client.get(
        f"/api/v1/scans/{seeded_scan}/findings", params={"page": 99, "page_size": 50}
    ).json()

    assert body["items"] == []
    assert body["total"] == 2


def test_page_size_over_the_maximum_is_rejected(api_client, seeded_scan) -> None:
    response = api_client.get(
        f"/api/v1/scans/{seeded_scan}/findings", params={"page_size": 500}
    )

    assert response.status_code == 422


def test_page_below_one_is_rejected(api_client, seeded_scan) -> None:
    assert (
        api_client.get(
            f"/api/v1/scans/{seeded_scan}/findings", params={"page": 0}
        ).status_code
        == 422
    )


def test_filtering_by_algorithm(api_client, seeded_scan) -> None:
    rsa = _all_items(api_client, seeded_scan, algorithm="RSA")
    none = _all_items(api_client, seeded_scan, algorithm="AES")

    assert rsa["total"] == 2
    assert none["total"] == 0


def test_filtering_by_role_uses_a_validated_enum(api_client, seeded_scan) -> None:
    ok = api_client.get(
        f"/api/v1/scans/{seeded_scan}/findings", params={"role": "DIGITAL_SIGNATURE"}
    )
    bad = api_client.get(
        f"/api/v1/scans/{seeded_scan}/findings", params={"role": "NOT_A_ROLE"}
    )

    assert ok.status_code == 200
    assert bad.status_code == 422


def test_filtering_by_status_alias(api_client, seeded_scan) -> None:
    body = _all_items(api_client, seeded_scan, status="ACTIVE")
    assert body["total"] == 2
    assert _all_items(api_client, seeded_scan, status="RESOLVED")["total"] == 0


def test_ordering_is_deterministic(api_client, seeded_scan) -> None:
    first = _all_items(api_client, seeded_scan)["items"]
    second = _all_items(api_client, seeded_scan)["items"]

    assert [item["id"] for item in first] == [item["id"] for item in second]
    # band then confidence then file then line: the sign finding (HIGH band)
    # sorts before the key-generation finding (lower band).
    bands = [item["priority"] for item in first]
    assert bands == sorted(
        bands, key=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"].index
    )


def test_findings_for_a_missing_scan_are_a_404(api_client) -> None:
    response = api_client.get("/api/v1/scans/nope/findings")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "SCAN_NOT_FOUND"


def test_finding_detail_returns_the_canonical_blocks(api_client, seeded_scan) -> None:
    item = _all_items(api_client, seeded_scan)["items"][0]

    body = api_client.get(f"/api/v1/findings/{item['id']}").json()

    assert body["id"] == item["id"]
    assert body["fingerprint"] == item["fingerprint"]
    assert body["observed"]["algorithm"] == item["algorithm"]
    assert "role" not in body["observed"]
    assert "confidence" not in body["observed"]
    assert body["inference"]["role"] == item["role"]
    assert body["inference"]["rationale"]
    assert body["inference"]["evidence_basis"] is None
    assert body["migration"]["review_path"] == item["review_path"]
    assert body["migration"]["is_migration_candidate"] == item["is_migration_candidate"]
    assert body["impact"]["relationships"] == []
    assert body["impact"]["node_count"] == len(body["impact"]["nodes"])
    assert body["priority"]["level"] == item["priority"]
    assert body["priority"]["score"] is None
    assert body["priority"]["reasons"] == []


def test_finding_detail_for_a_missing_id_is_a_structured_404(api_client) -> None:
    response = api_client.get("/api/v1/findings/does-not-exist")

    assert response.status_code == 404
    assert response.json() == {
        "error": {"code": "FINDING_NOT_FOUND", "message": "Finding was not found."}
    }


def test_no_fact_appears_under_two_names_in_the_detail(api_client, seeded_scan) -> None:
    item = _all_items(api_client, seeded_scan)["items"][0]
    body = api_client.get(f"/api/v1/findings/{item['id']}").json()

    def leaves(value):
        if isinstance(value, dict):
            for key, inner in value.items():
                if isinstance(inner, dict | list):
                    yield from leaves(inner)
                else:
                    yield key
        elif isinstance(value, list):
            for inner in value:
                yield from leaves(inner)

    keys = list(leaves(body))
    assert keys.count("algorithm") == 1
    assert keys.count("role") == 1
    for banned in ("observed_algorithm", "detected_algorithm", "crypto_algorithm"):
        assert banned not in keys
