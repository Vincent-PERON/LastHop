from __future__ import annotations

from fastapi import APIRouter, Request, Response
from sqlalchemy import text

from app.db.session import get_session

router = APIRouter(tags=["health"])


@router.get("/healthz", include_in_schema=False)
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz", include_in_schema=False)
async def readyz(request: Request, response: Response) -> dict[str, str]:
    try:
        await request.app.state.redis.ping()
        async for s in get_session():
            await s.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001 - réponse volontairement sans détail
        response.status_code = 503
        return {"status": "unavailable"}
    return {"status": "ok"}
