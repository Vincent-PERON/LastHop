from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any

import httpx
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import (
    audit,
    auth,
    auth_providers,
    auth_totp,
    backups,
    credentials,
    devices,
    discovery,
    endpoints,
    health,
    port_config,
    realtime,
    sites,
    ssh,
    tokens,
    topology,
)
from app.api import settings as settings_api
from app.config import Settings, get_settings
from app.db.session import close_db, init_db
from app.deps import get_principal
from app.logging import configure_logging
from app.redis_util import make_redis
from app.security.middleware import SecurityMiddleware
from app.security.oidc import OidcRegistry
from app.security.sessions import SessionStore
from app.services.jobs import default_dispatch
from app.services.local_admin import ensure_local_admin

log = logging.getLogger("lasthop")


def create_app(settings: Settings | None = None, oidc_transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    s = settings or get_settings()
    configure_logging()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        init_db(s)
        app.state.redis = make_redis(s)
        http = httpx.AsyncClient(timeout=10.0, transport=oidc_transport, follow_redirects=False)
        app.state.oidc = OidcRegistry(http)
        app.state.dispatch_job = default_dispatch
        app.state.sessions = SessionStore(app.state.redis, s.session_idle_seconds, s.session_absolute_seconds)
        await ensure_local_admin(s)
        yield
        await http.aclose()
        await app.state.redis.aclose()
        await close_db()

    # Pas de /docs ni /openapi.json publics : le schéma est servi authentifié ci-dessous.
    app = FastAPI(
        title="LastHop API", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan
    )
    app.state.settings = s

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[s.frontend_origin],  # une seule origine, jamais "*"
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Content-Type", "X-CSRF-Token"],
        max_age=600,
    )
    app.add_middleware(SecurityMiddleware, max_body=s.max_body_bytes)  # ajouté en dernier = le plus externe

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        # On ne renvoie ni la valeur saisie (`input`) ni le contexte : seulement le chemin et le type d'erreur.
        errs = [{"loc": e["loc"], "type": e["type"]} for e in exc.errors()]
        return JSONResponse({"detail": "Requête invalide", "errors": errs}, status_code=422)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        rid = getattr(request.state, "request_id", None)
        log.error("unhandled_exception", extra={"request_id": rid}, exc_info=exc)
        return JSONResponse({"detail": "Erreur interne", "request_id": rid}, status_code=500)

    for r in (
        health.router,
        auth.router,
        auth_providers.router,
        auth_totp.router,
        tokens.router,
        audit.router,
        settings_api.router,
        sites.router,
        credentials.router,
        devices.router,
        discovery.router,
        topology.router,
        port_config.router,
        endpoints.router,
        realtime.router,
        ssh.router,
        backups.router,
    ):
        app.include_router(r)

    @app.get("/api/v1/openapi.json", include_in_schema=False)
    async def openapi_json(_: Annotated[Any, Depends(get_principal)]) -> dict[str, Any]:
        return app.openapi()

    return app
