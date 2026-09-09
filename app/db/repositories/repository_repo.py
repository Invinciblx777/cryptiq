"""Get-or-create for the analysed repository.

A repository is identified by (provider, owner, name); the canonical URL is
descriptive, not part of the identity. The unique constraint on those three
columns is the backstop, so a lost race re-reads the winning row rather than
raising.
"""

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models.repository import Repository
from app.engine.ingestion import RepositoryReference


def _existing(session: Session, ref: RepositoryReference) -> Repository | None:
    return session.scalars(
        select(Repository).where(
            Repository.provider == ref.provider,
            Repository.owner == ref.owner,
            Repository.name == ref.name,
        )
    ).first()


def get_or_create_repository(session: Session, ref: RepositoryReference) -> Repository:
    """Return the stored repository for a reference, creating it once.

    Never inserts a second row for the same (provider, owner, name): an
    existing row is returned as-is, and a concurrent insert is resolved by
    re-reading rather than duplicated.
    """
    found = _existing(session, ref)
    if found is not None:
        return found

    repository = Repository(
        provider=ref.provider,
        owner=ref.owner,
        name=ref.name,
        canonical_url=ref.canonical_url,
    )
    session.add(repository)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        raced = _existing(session, ref)
        if raced is None:
            raise
        return raced
    return repository
