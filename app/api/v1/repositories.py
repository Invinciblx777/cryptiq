"""Repository routes.

There is no standalone repository endpoint in the MVP: repository identity is
nested inside every scan and finding response (``repository: {provider, owner,
name, url}``). This router exists as the seam for a future
``GET /api/v1/repositories`` listing and carries no routes yet.
"""

from fastapi import APIRouter

router = APIRouter(prefix="/repositories", tags=["repositories"])
