"""Paramètres d'administration : schéma (liste blanche), valeurs par défaut et lecture."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import AfterValidator, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AppSetting
from app.security.targets import validate_cidr_list

# clé -> (type validé strictement, valeur par défaut)
SCHEMA: dict[str, tuple[Any, Any]] = {
    "snmp_v2c_enabled": (bool, False),  # v2c désactivé par défaut
    "snmp_allowed_cidrs": (  # aucune cible SNMP autorisée tant que l'admin n'a rien déclaré
        Annotated[list[str], Field(max_length=64), AfterValidator(validate_cidr_list)],
        [],
    ),
    "trunk_min_tagged_vlans": (Annotated[int, Field(ge=1, le=4094)], 2),  # VLAN tagués mini pour qualifier un trunk
    "backup_interval_s": (Annotated[int, Field(ge=3600, le=604800)], 86400),  # sauvegardes planifiées (1 j par défaut)
    "backup_retention_days": (Annotated[int, Field(ge=7, le=3650)], 365),
    "topology_interval_s": (Annotated[int, Field(ge=300, le=86400)], 3600),
    "uplink_mac_threshold": (Annotated[int, Field(ge=2, le=10000)], 20),
    "retention_days": (Annotated[int, Field(ge=1, le=3650)], 90),
    "snmp_max_concurrency": (Annotated[int, Field(ge=1, le=500)], 20),
    "realtime_timeout_s": (Annotated[int, Field(ge=5, le=300)], 30),
}


async def all_values(db: AsyncSession) -> dict[str, Any]:
    stored = {r.key: r.value for r in (await db.execute(select(AppSetting))).scalars()}
    return {k: stored.get(k, default) for k, (_, default) in SCHEMA.items()}


async def get_value(db: AsyncSession, key: str) -> Any:
    return (await all_values(db))[key]
