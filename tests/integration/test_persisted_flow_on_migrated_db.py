"""The full persisted flow runs on a database built by ``alembic upgrade head``.

No network: a FakeSourceProvider stands in for GitHub. The point is that the
schema Alembic produces is the schema the persistence layer writes to.
"""

import asyncio
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.db.models.enums import ScanJobStatus, ScanStatus
from app.db.models.scan import Scan
from app.db.models.scan_job import ScanJob
from app.engine.ingestion import RepositoryReference
from app.services.scan_service import create_scan
from app.workers import ScanWorker
from tests.support import FakeSourceProvider

PROJECT_ROOT = Path(__file__).resolve().parents[2]
REF = RepositoryReference(
    provider="github",
    owner="pyca",
    name="cryptography",
    canonical_url="https://github.com/pyca/cryptography",
)
SHA = "1f903f5ed2e5e316f345a927555e48535829d8de"
IMPORT = b"from cryptography.hazmat.primitives.asymmetric import rsa\n"
TREE = {"src/keys.py": IMPORT + b"def build():\n    return rsa.generate_private_key()\n"}


@pytest.fixture
def migrated_session_factory(tmp_path: Path) -> Iterator[sessionmaker]:
    db_path = tmp_path / "migrated.db"
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    command.upgrade(config, "head")

    engine = create_engine(f"sqlite:///{db_path}", future=True)

    @event.listens_for(engine, "connect")
    def _fk_on(connection, _record) -> None:
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    try:
        yield sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    finally:
        engine.dispose()


def test_scan_completes_on_a_freshly_migrated_database(migrated_session_factory) -> None:
    with migrated_session_factory() as session:
        scan_id = create_scan(session, repository=REF, commit_sha=SHA).scan.id

    worker = ScanWorker(
        session_factory=migrated_session_factory,
        worker_id="w-migrated",
        provider_factory=lambda: FakeSourceProvider(TREE),
    )
    assert worker.run_once() is True

    with migrated_session_factory() as session:
        scan = session.get(Scan, scan_id)
        job = session.query(ScanJob).filter_by(scan_id=scan_id).one()
        assert scan.status is ScanStatus.COMPLETED
        assert scan.finding_count > 0
        assert job.status is ScanJobStatus.COMPLETED


def test_downgrade_then_upgrade_still_supports_the_flow(migrated_session_factory, tmp_path) -> None:
    # Reuse the migrated database, cycle it, and run again.
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{tmp_path / 'migrated.db'}")
    command.downgrade(config, "base")
    command.upgrade(config, "head")

    with migrated_session_factory() as session:
        scan_id = create_scan(session, repository=REF, commit_sha=SHA).scan.id

    async def _execute() -> None:
        from app.services.scan_execution import execute_scan

        await execute_scan(
            scan_id,
            session_factory=migrated_session_factory,
            provider=FakeSourceProvider(TREE),
        )

    asyncio.run(_execute())

    with migrated_session_factory() as session:
        assert session.get(Scan, scan_id).status is ScanStatus.COMPLETED
