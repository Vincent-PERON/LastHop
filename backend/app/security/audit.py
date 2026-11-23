"""Écriture dans l'audit log. La chaîne de hachage est calculée par la BDD (trigger)."""

from __future__ import annotations

import ipaddress
from typing import Any

from fastapi import Request
from sqlalchemy import insert, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditLog
from app.logging import redact
from app.security.rbac import Principal


def client_ip(request: Request) -> str | None:
    host = request.client.host if request.client else None
    try:
        return str(ipaddress.ip_address(host)) if host else None
    except ValueError:
        return None


async def record(
    session: AsyncSession,
    request: Request | None,
    action: str,
    *,
    principal: Principal | None = None,
    actor_type: str | None = None,
    actor_label: str | None = None,
    outcome: str = "success",
    target_type: str | None = None,
    target_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Ajoute l'événement dans la transaction courante (atomique avec l'action auditée). L'appelant commit."""
    safe = redact(details or {})  # défense en profondeur : jamais de secret dans l'audit
    await session.execute(
        insert(AuditLog).values(
            actor_type=actor_type or (principal.actor_type if principal else "anonymous"),
            actor_id=principal.actor_id if principal else None,
            actor_label=(principal.label if principal else actor_label),
            action=action,
            outcome=outcome,
            target_type=target_type,
            target_id=target_id,
            source_ip=client_ip(request) if request else None,
            request_id=getattr(request.state, "request_id", None) if request else None,
            details=safe,
        )
    )


async def verify_chain(session: AsyncSession) -> int | None:
    """None si la chaîne est intacte, sinon l'id de la première ligne rompue."""
    broken: int | None = (await session.execute(text("SELECT audit_verify()"))).scalar_one()
    return broken
