"""Shared FastAPI dependencies."""

from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db.database import SessionLocal
from app.services.reference_resolver import CommitResolver


def get_db() -> Iterator[Session]:
    """Yield a request-scoped database session and close it afterwards."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def get_commit_resolver() -> CommitResolver:
    """Return the resolver that turns a short commit ref into a full SHA.

    A dependency so tests can substitute a resolver that never touches the
    network. The default is the GitHub provider, imported lazily.
    """
    from app.integrations.github import GitHubSourceProvider

    return GitHubSourceProvider()


DbSession = Annotated[Session, Depends(get_db)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
CommitResolverDep = Annotated[CommitResolver, Depends(get_commit_resolver)]
