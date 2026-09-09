"""Aggregate router for the v1 API."""

from fastapi import APIRouter

from app.api.v1 import findings, health, repositories, reviews, scans

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
api_router.include_router(reviews.router)
api_router.include_router(repositories.router)
