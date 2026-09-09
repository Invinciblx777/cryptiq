"""The review-item workflow rules."""

import pytest

from app.db.models.enums import ReviewStatus
from app.db.repositories import assert_review_transition
from app.errors import InvalidReviewTransitionError

LEGAL = [
    (ReviewStatus.OPEN, ReviewStatus.IN_REVIEW),
    (ReviewStatus.IN_REVIEW, ReviewStatus.REVIEWED),
    (ReviewStatus.IN_REVIEW, ReviewStatus.OPEN),
    (ReviewStatus.REVIEWED, ReviewStatus.IN_REVIEW),
]
ILLEGAL = [
    (ReviewStatus.OPEN, ReviewStatus.REVIEWED),
    (ReviewStatus.REVIEWED, ReviewStatus.OPEN),
]


@pytest.mark.parametrize(("current", "target"), LEGAL)
def test_legal_moves_pass(current, target) -> None:
    assert_review_transition(current, target)


@pytest.mark.parametrize(("current", "target"), ILLEGAL)
def test_illegal_moves_raise_409(current, target) -> None:
    with pytest.raises(InvalidReviewTransitionError) as error:
        assert_review_transition(current, target)

    assert error.value.status_code == 409
    assert error.value.code == "INVALID_REVIEW_TRANSITION"


@pytest.mark.parametrize("status", list(ReviewStatus))
def test_a_no_op_move_is_allowed(status) -> None:
    assert_review_transition(status, status)
