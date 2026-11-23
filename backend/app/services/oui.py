"""Base OUI IEEE (constructeur d'après les 3 premiers octets de la MAC) : import CSV et mise à jour périodique."""

from __future__ import annotations

import csv
import io
import re
from collections.abc import Awaitable, Callable
from urllib.parse import urlparse

import httpx
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import OuiEntry
from app.snmp.client import as_text

OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
ALLOWED_HOSTS = {"standards-oui.ieee.org"}
MAX_BYTES = 30_000_000
_ASSIGNMENT = re.compile(r"^[0-9A-Fa-f]{6}$")


def parse_oui_csv(content: str) -> list[tuple[str, str]]:
    """Format IEEE : Registry,Assignment,Organization Name,Organization Address (seul MA-L, préfixe de 24 bits)."""
    out: dict[str, str] = {}
    for row in csv.DictReader(io.StringIO(content)):
        if (row.get("Registry") or "MA-L") != "MA-L":
            continue
        a = (row.get("Assignment") or "").strip()
        name = as_text((row.get("Organization Name") or "").encode(), 255)
        if _ASSIGNMENT.match(a) and name:
            h = a.lower()
            out[f"{h[0:2]}:{h[2:4]}:{h[4:6]}:00:00:00"] = name
    return list(out.items())


async def import_entries(db: AsyncSession, entries: list[tuple[str, str]]) -> int:
    for i in range(0, len(entries), 2000):
        chunk = entries[i : i + 2000]
        stmt = pg_insert(OuiEntry).values([{"prefix": p, "vendor": v} for p, v in chunk])
        await db.execute(stmt.on_conflict_do_update(index_elements=["prefix"], set_={"vendor": stmt.excluded.vendor}))
    await db.commit()
    return len(entries)


async def download_oui(url: str = OUI_URL) -> str:
    """Téléchargement HTTPS, hôte en liste blanche, taille bornée, sans redirection."""
    u = urlparse(url)
    if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS:
        raise ValueError("source OUI non autorisée")
    buf = bytearray()
    async with httpx.AsyncClient(timeout=60.0, follow_redirects=False) as client, client.stream("GET", url) as r:
        r.raise_for_status()
        async for chunk in r.aiter_bytes():
            buf += chunk
            if len(buf) > MAX_BYTES:
                raise ValueError("fichier OUI trop volumineux")
    return buf.decode("utf-8", errors="replace")


async def update_oui(db: AsyncSession, fetch: Callable[[], Awaitable[str]] = download_oui) -> int:
    return await import_entries(db, parse_oui_csv(await fetch()))
