"""CLI d'exploitation : `python -m app.cli audit-verify` (code retour 1 si la chaîne d'audit est rompue)."""

from __future__ import annotations

import asyncio
import sys

from app.config import get_settings
from app.db.session import build_engine
from app.security.audit import verify_chain


async def _audit_verify() -> int:
    engine = build_engine(get_settings())
    async with engine.connect() as conn:
        from sqlalchemy.ext.asyncio import AsyncSession

        async with AsyncSession(bind=conn) as s:
            broken = await verify_chain(s)
    await engine.dispose()
    if broken is None:
        print("audit_log : chaîne intacte")
        return 0
    print(f"audit_log : chaîne ROMPUE à partir de l'id {broken}")
    return 1


async def _reencrypt() -> int:
    """Re-chiffre les profils SNMP avec la clé active (après ajout d'une nouvelle clé dans le trousseau)."""
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.db.models import SnmpCredentialRow
    from app.security.crypto import keyring_from_settings
    from app.services.credentials_store import seal, unseal

    s = get_settings()
    ring = keyring_from_settings(s.master_keys, s.master_key_active)
    engine = build_engine(s)
    n = 0
    async with AsyncSession(engine) as db:
        for row in (await db.execute(select(SnmpCredentialRow))).scalars():
            if ring.needs_rotation(row.secret_blob):
                row.secret_blob, row.key_id = seal(ring, row.id, unseal(ring, row))
                n += 1
        await db.commit()
    await engine.dispose()
    print(f"{n} profil(s) re-chiffré(s) avec la clé {ring.active_kid}")
    return 0


async def _oui_import(content: str) -> int:
    """Import hors ligne (environnement isolé) d'un fichier oui.csv IEEE téléchargé par ailleurs."""
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.services.oui import import_entries, parse_oui_csv

    entries = parse_oui_csv(content)
    engine = build_engine(get_settings())
    async with AsyncSession(engine) as db:
        n = await import_entries(db, entries)
    await engine.dispose()
    print(f"{n} préfixe(s) OUI importé(s)")
    return 0


async def _local_admin_reset(username: str, password: str) -> int:
    """Secours : nouveau mot de passe du compte local (entrée standard), compte déverrouillé, changement imposé."""
    from app.db.session import close_db, init_db
    from app.security.passwords import PasswordPolicyError
    from app.services.local_admin import reset_local_password

    init_db(get_settings())
    try:
        ok = await reset_local_password(username, password)
    except PasswordPolicyError as exc:
        print(f"Mot de passe refusé : {exc}")
        return 1
    finally:
        await close_db()
    print("mot de passe réinitialisé (changement exigé à la prochaine connexion)" if ok else "compte local introuvable")
    return 0 if ok else 1


def main() -> None:
    if len(sys.argv) == 3 and sys.argv[1] == "local-admin-reset":
        # echo -n 'nouveau-mot-de-passe' | docker compose run --rm -T api python -m app.cli local-admin-reset admin
        sys.exit(asyncio.run(_local_admin_reset(sys.argv[2].lower(), sys.stdin.read().strip())))
    if sys.argv[1:] == ["audit-verify"]:
        sys.exit(asyncio.run(_audit_verify()))
    if sys.argv[1:] == ["reencrypt"]:
        sys.exit(asyncio.run(_reencrypt()))
    if len(sys.argv) == 3 and sys.argv[1] == "oui-import":
        import pathlib

        sys.exit(asyncio.run(_oui_import(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8", errors="replace"))))
    print("usage: python -m app.cli audit-verify | reencrypt | oui-import <oui.csv> | local-admin-reset <utilisateur>")
    sys.exit(2)


if __name__ == "__main__":
    main()
