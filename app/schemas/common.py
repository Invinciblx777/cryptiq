"""Shared API response shapes."""

from pydantic import BaseModel, Field


class Page[T](BaseModel):
    """One page of a larger result set.

    ``pages`` is the total number of pages at the current ``page_size``; it is
    0 when there are no items.
    """

    items: list[T]
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)
    total: int = Field(ge=0)
    pages: int = Field(ge=0)

    @classmethod
    def build(cls, items: list[T], *, page: int, page_size: int, total: int) -> "Page[T]":
        """Assemble a page, computing ``pages`` from ``total`` and ``page_size``."""
        pages = (total + page_size - 1) // page_size if total else 0
        return cls(items=items, page=page, page_size=page_size, total=total, pages=pages)
