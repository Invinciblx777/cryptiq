"""Repository get-or-create never duplicates a (provider, owner, name)."""

from app.db.models import Repository
from app.db.repositories import get_or_create_repository
from app.engine.ingestion import RepositoryReference

REF = RepositoryReference(
    provider="github",
    owner="pyca",
    name="cryptography",
    canonical_url="https://github.com/pyca/cryptography",
)


def test_a_new_reference_creates_one_row(session) -> None:
    repository = get_or_create_repository(session, REF)
    session.commit()

    assert repository.id
    assert session.query(Repository).count() == 1


def test_an_existing_identity_is_returned_not_duplicated(session) -> None:
    first = get_or_create_repository(session, REF)
    session.commit()

    other_url = RepositoryReference(
        provider="github",
        owner="pyca",
        name="cryptography",
        canonical_url="https://github.com/pyca/cryptography.git",
    )
    second = get_or_create_repository(session, other_url)
    session.commit()

    assert second.id == first.id
    assert session.query(Repository).count() == 1


def test_a_different_name_is_a_different_row(session) -> None:
    get_or_create_repository(session, REF)
    get_or_create_repository(
        session,
        RepositoryReference(
            provider="github",
            owner="pyca",
            name="pynacl",
            canonical_url="https://github.com/pyca/pynacl",
        ),
    )
    session.commit()

    assert session.query(Repository).count() == 2
