"""The Page envelope computes its page count from the total."""

import pytest
from pydantic import ValidationError

from app.schemas.common import Page


def test_page_count_rounds_up() -> None:
    page = Page[int].build([1, 2, 3], page=1, page_size=50, total=1042)

    assert page.pages == 21
    assert page.page == 1
    assert page.page_size == 50
    assert page.total == 1042


def test_an_empty_result_has_zero_pages() -> None:
    page = Page[str].build([], page=1, page_size=50, total=0)

    assert page.pages == 0
    assert page.items == []


def test_an_exact_multiple_is_not_rounded_further() -> None:
    assert Page[int].build([], page=1, page_size=10, total=100).pages == 10


def test_page_and_page_size_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        Page[int](items=[], page=0, page_size=10, total=0, pages=0)
    with pytest.raises(ValidationError):
        Page[int](items=[], page=1, page_size=0, total=0, pages=0)
