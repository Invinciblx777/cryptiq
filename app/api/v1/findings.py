"""Finding detail endpoint: the canonical persisted record for one finding."""

from typing import Annotated

from fastapi import APIRouter, Path

from app.dependencies import DbSession
from app.schemas.finding import FindingDetail
from app.services import finding_detail

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get(
    "/{finding_id}",
    response_model=FindingDetail,
    summary="Read one persisted finding in full",
    responses={404: {"description": "No finding with this id."}},
)
def get_finding_endpoint(
    finding_id: Annotated[str, Path(description="The finding's database id.")],
    session: DbSession,
) -> FindingDetail:
    """Return the finding's observed, inference, migration, impact and priority blocks.

    ``inference.evidence_basis`` is null, ``priority.score``/``reasons`` are
    absent and ``impact.relationships`` is empty: those are not persisted.
    """
    return finding_detail(session, finding_id)
