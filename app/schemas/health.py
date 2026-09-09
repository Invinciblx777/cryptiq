"""Schemas for the health endpoint."""

from pydantic import BaseModel


class HealthResponse(BaseModel):
    """Machine-readable liveness report."""

    status: str
    service: str
    version: str
