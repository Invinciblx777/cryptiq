"""Resolve a short commit reference to a full 40-character SHA.

The persisted Scan always stores the full SHA, so the API resolves a short
reference before creating a scan. A reference that is already 40 hex
characters is returned without a network call; anything shorter is resolved
through the provider, which is one lightweight API request, not a download.

GitHub stays behind the provider: this module only knows the ``resolve_commit``
protocol method.
"""

from typing import Protocol

from app.engine.ingestion import RepositoryReference
from app.engine.ingestion.validation import normalize_commit_sha

_FULL_SHA_LENGTH = 40


class CommitResolver(Protocol):
    """Resolves a repository reference and a ref to a full commit SHA."""

    async def resolve_commit(
        self, repository: RepositoryReference, commit_sha: str
    ) -> str: ...


def _default_resolver() -> CommitResolver:
    from app.integrations.github import GitHubSourceProvider

    return GitHubSourceProvider()


async def resolve_commit_reference(
    repository: RepositoryReference,
    ref: str,
    *,
    resolver: CommitResolver | None = None,
) -> str:
    """Return the full 40-character SHA for a 7-40 character ``ref``.

    Raises ``InvalidCommitShaError`` for a malformed ref and the provider's
    domain errors (``REPOSITORY_NOT_FOUND``, ``COMMIT_NOT_FOUND``,
    ``REPOSITORY_UNAVAILABLE``) when resolution fails.
    """
    normalized = normalize_commit_sha(ref)
    if len(normalized) == _FULL_SHA_LENGTH:
        return normalized
    provider = resolver or _default_resolver()
    return await provider.resolve_commit(repository, normalized)
