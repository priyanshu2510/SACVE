"""Control API (FastAPI)."""

from __future__ import annotations

import redis.asyncio as aioredis
import structlog
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import text

from src.api.routers import config, cves, jobs, scan, webhooks
from src.core.config import settings
from src.core.database import get_engine
from src.core.logging import configure_logging
from src.schemas.api import Health

log = structlog.get_logger(__name__)


def create_app() -> FastAPI:
    """Build the application (a factory so tests can create isolated instances)."""
    configure_logging()
    expose_docs = settings.ENVIRONMENT != "prod"  # the schema/Swagger UI are for development; keep them off in production
    app = FastAPI(
        title="CVE Auto-Remediation Control API", version="1.0.0",
        docs_url="/api/docs" if expose_docs else None, openapi_url="/api/openapi.json" if expose_docs else None,
    )  # fmt: skip
    for module in (scan, jobs, cves, config, webhooks):
        app.include_router(module.router)

    @app.get("/api/v1/health", response_model=Health, tags=["health"])
    async def health() -> JSONResponse:
        """Unauthenticated liveness / readiness probe for orchestrators (booleans only, never details)."""
        checks = {"database": False, "redis": False}
        try:
            async with get_engine().connect() as conn:
                await conn.execute(text("select 1"))
            checks["database"] = True
        except Exception as exc:  # noqa: BLE001
            log.error("health.database_down", error=str(exc))
        client = aioredis.from_url(settings.REDIS_URL, socket_connect_timeout=2)
        try:
            checks["redis"] = bool(await client.ping())
        except Exception as exc:  # noqa: BLE001
            log.error("health.redis_down", error=str(exc))
        finally:
            await client.aclose()
        ok = all(checks.values())
        body = Health(status="ok" if ok else "degraded", checks=checks, automation_enabled=settings.AUTOMATION_ENABLED)
        return JSONResponse(body.model_dump(), status_code=200 if ok else 503)

    return app


app = create_app()
