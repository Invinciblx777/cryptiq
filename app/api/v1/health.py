"""Liveness endpoint."""

from fastapi import APIRouter

from app import __version__
from app.schemas.health import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Report that the service process is up and serving requests."""
    return HealthResponse(status="ok", service="cryptiq", version=__version__)
