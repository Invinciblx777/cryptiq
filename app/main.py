"""FastAPI application factory and entry point."""

from fastapi import FastAPI

from app import __version__
from app.api.v1.health import router as health_router
from app.api.v1.router import api_router
from app.errors import register_error_handlers


def create_app() -> FastAPI:
    """Build the FastAPI application."""
    app = FastAPI(
        title="Cryptiq",
        version=__version__,
        description="Deterministic cryptographic static-analysis backend.",
    )
    register_error_handlers(app)
    app.include_router(api_router, prefix="/api/v1")
    # Unprefixed alias so process supervisors and load balancers can probe a
    # stable path that does not move with the API version.
    app.include_router(health_router, include_in_schema=False)
    return app


app = create_app()


def run() -> None:
    """Run the development server."""
    import uvicorn

    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
