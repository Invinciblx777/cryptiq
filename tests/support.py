"""Helpers for building the archives and trees the ingestion tests need."""

import io
import stat
import struct
import tempfile
import zipfile
from pathlib import Path

from app.engine.ingestion.source import (
    RepositoryReference,
    SourceSnapshot,
    compute_content_hash,
    count_files,
)

TOP_LEVEL = "owner-repo-abc1234"

ACCEPTANCE_SHA = "1f903f5ed2e5e316f345a927555e48535829d8de"


class FakeCommitResolver:
    """A CommitResolver that returns a fixed full SHA, or raises.

    Lets the API's short-SHA path be exercised without a GitHub call.
    """

    def __init__(
        self,
        full_sha: str = ACCEPTANCE_SHA,
        *,
        fail_with: BaseException | None = None,
    ) -> None:
        self._full_sha = full_sha
        self._fail_with = fail_with
        self.calls = 0

    async def resolve_commit(self, repository, commit_sha: str) -> str:
        self.calls += 1
        if self._fail_with is not None:
            raise self._fail_with
        return self._full_sha


class FakeSourceProvider:
    """A SourceProvider that materialises a fixed tree in a temp directory.

    Lets the scan execution path be exercised end to end without touching the
    network. ``fail_with`` makes ``fetch_commit`` raise instead, for the
    failure-path tests.
    """

    def __init__(
        self,
        files: dict[str, bytes],
        *,
        commit_sha: str = ACCEPTANCE_SHA,
        fail_with: BaseException | None = None,
    ) -> None:
        self._files = files
        self._commit_sha = commit_sha
        self._fail_with = fail_with
        self.calls = 0
        self.root_path: Path | None = None

    async def fetch_commit(
        self, repository: RepositoryReference, commit_sha: str
    ) -> SourceSnapshot:
        self.calls += 1
        if self._fail_with is not None:
            raise self._fail_with
        root = Path(tempfile.mkdtemp(prefix="cryptiq-fake-source-"))
        write_tree(root, self._files)
        self.root_path = root
        return SourceSnapshot(
            root_path=root,
            repository=repository,
            commit_sha=self._commit_sha,
            content_hash=compute_content_hash(root),
            file_count=count_files(root),
        )


def build_zip(entries: dict[str, bytes], *, top_level: str | None = TOP_LEVEL) -> bytes:
    """Return a ZIP holding the given entries, optionally under one root directory."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in entries.items():
            full_name = f"{top_level}/{name}" if top_level else name
            archive.writestr(full_name, payload)
    return buffer.getvalue()


def build_raw_zip(names: list[str], payload: bytes = b"x") -> bytes:
    """Return a ZIP whose member names are written exactly as given."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in names:
            archive.writestr(name, payload)
    return buffer.getvalue()


def build_symlink_zip(link_name: str, target: str) -> bytes:
    """Return a ZIP holding a symbolic link entry beside a regular file."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo(link_name)
        info.create_system = 3  # Unix
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, target)
        archive.writestr("regular.py", b"x = 1\n")
    return buffer.getvalue()


def write_tree(root: Path, files: dict[str, bytes]) -> Path:
    """Write a file tree under root and return root."""
    for relative_path, payload in files.items():
        target = root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    return root


def build_understated_zip(name: str, payload: bytes) -> bytes:
    """Return a ZIP whose headers claim a member is one byte long.

    Both the local header and the central directory record the uncompressed
    size, so a bomb can declare almost nothing and expand on extraction. The
    true size is rewritten here to exercise the check that runs while the
    bytes are being written.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, payload)

    raw = buffer.getvalue()
    true_size = struct.pack("<I", len(payload))
    if raw.count(true_size) != 2:
        raise AssertionError("expected the size field in the local and central headers")
    return raw.replace(true_size, struct.pack("<I", 1))
