"""GET /api/v1/review-queue and PATCH /api/v1/review-items/{id}."""


def _queue(api_client, scan_id, **params):
    params["scan_id"] = scan_id
    params.setdefault("page_size", 100)
    return api_client.get("/api/v1/review-queue", params=params).json()


def test_the_queue_is_a_page_of_nested_rows(api_client, seeded_scan) -> None:
    body = _queue(api_client, seeded_scan)

    assert set(body) == {"items", "page", "page_size", "total", "pages"}
    assert body["total"] == 2
    row = body["items"][0]
    assert set(row) == {"review", "finding"}
    assert set(row["review"]) == {
        "id",
        "finding_id",
        "status",
        "assigned_to",
        "note",
        "created_at",
        "updated_at",
    }
    assert row["review"]["status"] == "OPEN"
    assert "source_excerpt" not in row["finding"]  # queue rows stay lean


def test_the_queue_is_paginated(api_client, seeded_scan) -> None:
    first = _queue(api_client, seeded_scan, page=1, page_size=1)
    assert first["total"] == 2
    assert first["pages"] == 2
    assert len(first["items"]) == 1


def test_the_queue_is_ordered_by_review_band(api_client, seeded_scan) -> None:
    rows = _queue(api_client, seeded_scan)["items"]
    bands = [row["finding"]["priority"] for row in rows]

    assert bands == sorted(
        bands, key=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"].index
    )


def test_filtering_the_queue_by_status(api_client, seeded_scan) -> None:
    review_id = _queue(api_client, seeded_scan)["items"][0]["review"]["id"]
    api_client.patch(f"/api/v1/review-items/{review_id}", json={"status": "IN_REVIEW"})

    open_rows = _queue(api_client, seeded_scan, status="OPEN")
    in_review = _queue(api_client, seeded_scan, status="IN_REVIEW")

    assert open_rows["total"] == 1
    assert [row["review"]["id"] for row in in_review["items"]] == [review_id]


def test_updating_open_to_in_review(api_client, seeded_scan) -> None:
    review_id = _queue(api_client, seeded_scan)["items"][0]["review"]["id"]

    response = api_client.patch(
        f"/api/v1/review-items/{review_id}",
        json={"status": "IN_REVIEW", "assigned_to": "bob", "note": "on it"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "IN_REVIEW"
    assert body["assigned_to"] == "bob"
    assert body["note"] == "on it"


def test_updating_in_review_to_reviewed(api_client, seeded_scan) -> None:
    review_id = _queue(api_client, seeded_scan)["items"][0]["review"]["id"]
    api_client.patch(f"/api/v1/review-items/{review_id}", json={"status": "IN_REVIEW"})

    response = api_client.patch(
        f"/api/v1/review-items/{review_id}", json={"status": "REVIEWED"}
    )

    assert response.status_code == 200
    assert response.json()["status"] == "REVIEWED"


def test_an_illegal_transition_is_a_409(api_client, seeded_scan) -> None:
    review_id = _queue(api_client, seeded_scan)["items"][0]["review"]["id"]

    response = api_client.patch(
        f"/api/v1/review-items/{review_id}", json={"status": "REVIEWED"}
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "INVALID_REVIEW_TRANSITION"


def test_an_unknown_status_value_is_a_422(api_client, seeded_scan) -> None:
    review_id = _queue(api_client, seeded_scan)["items"][0]["review"]["id"]

    response = api_client.patch(
        f"/api/v1/review-items/{review_id}", json={"status": "DONE"}
    )

    assert response.status_code == 422


def test_updating_a_missing_review_item_is_a_structured_404(api_client) -> None:
    response = api_client.patch(
        "/api/v1/review-items/missing", json={"status": "IN_REVIEW"}
    )

    assert response.status_code == 404
    assert response.json() == {
        "error": {
            "code": "REVIEW_ITEM_NOT_FOUND",
            "message": "Review item was not found.",
        }
    }
