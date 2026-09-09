"""resolve_commit_reference: full SHAs pass through, short refs go to the provider."""

import pytest

from app.engine.ingestion import RepositoryReference
from app.errors import CommitNotFoundError, InvalidCommitShaError
from app.services import resolve_commit_reference
from tests.support import ACCEPTANCE_SHA, FakeCommitResolver

REF = RepositoryReference(
    provider="github",
    owner="pyca",
    name="cryptography",
    canonical_url="https://github.com/pyca/cryptography",
)


async def test_a_full_sha_is_returned_without_calling_the_resolver() -> None:
    resolver = FakeCommitResolver()

    result = await resolve_commit_reference(REF, ACCEPTANCE_SHA, resolver=resolver)

    assert result == ACCEPTANCE_SHA
    assert resolver.calls == 0


async def test_a_full_sha_is_lowercased() -> None:
    result = await resolve_commit_reference(
        REF, ACCEPTANCE_SHA.upper(), resolver=FakeCommitResolver()
    )
    assert result == ACCEPTANCE_SHA


async def test_a_short_ref_is_resolved_through_the_provider() -> None:
    resolver = FakeCommitResolver(full_sha=ACCEPTANCE_SHA)

    result = await resolve_commit_reference(REF, "1f903f5", resolver=resolver)

    assert result == ACCEPTANCE_SHA
    assert resolver.calls == 1


async def test_a_malformed_ref_never_reaches_the_provider() -> None:
    resolver = FakeCommitResolver()

    with pytest.raises(InvalidCommitShaError):
        await resolve_commit_reference(REF, "main", resolver=resolver)

    assert resolver.calls == 0


async def test_provider_errors_propagate() -> None:
    resolver = FakeCommitResolver(fail_with=CommitNotFoundError("Commit was not found."))

    with pytest.raises(CommitNotFoundError):
        await resolve_commit_reference(REF, "1f903f5", resolver=resolver)
