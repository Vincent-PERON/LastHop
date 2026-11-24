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


async def _local_admin_disable_totp(username: str) -> int:
    """Secours : retire le TOTP du compte local (appareil perdu ET codes de secours épuisés)."""
    from app.db.session import close_db, init_db, session_scope
    from app.services.totp_service import disable_totp

    init_db(get_settings())
    try:
        async with session_scope() as db:
            ok = await disable_totp(db, username)
            await db.commit()
    finally:
        await close_db()
    print("TOTP désactivé" if ok else "compte local introuvable")
    return 0 if ok else 1


def _walk_anonymize(src: str, dst: str) -> int:
    """Anonymise un snmpwalk client : MAC/IP/noms/séries remplacés de façon cohérente (voir docs/ADD_DRIVER.md)."""
    import pathlib

    from app.snmp.offline import anonymize, parse_walk, to_snmprec

    walk = parse_walk(pathlib.Path(src).read_text(encoding="utf-8", errors="replace"))
    if not walk:
        print("Aucune ligne SNMP reconnue (attendu : sortie de `snmpwalk -On -Ox` ou fichier .snmprec)")
        return 1
    anon, rep = anonymize(walk)
    pathlib.Path(dst).write_text(to_snmprec(anon), encoding="utf-8")
    print(f"{len(anon)} lignes écrites dans {dst} : {rep.macs} MAC, {rep.ips} IP, {rep.strings} textes remplacés.")
    print("RELISEZ le fichier avant de le transmettre : l'outil ne peut pas deviner tous les textes sensibles.")
    return 0


def _diagnose_walk(src: str) -> int:
    import pathlib

    from app.services.diagnose import diagnose, render_text
    from app.snmp.offline import WalkClient, parse_walk

    walk = parse_walk(pathlib.Path(src).read_text(encoding="utf-8", errors="replace"))
    if not walk:
        print("Aucune ligne SNMP reconnue")
        return 1
    print(render_text(asyncio.run(diagnose(WalkClient(walk)))))
    return 0


def main() -> None:
    if len(sys.argv) == 4 and sys.argv[1] == "walk-anonymize":
        sys.exit(_walk_anonymize(sys.argv[2], sys.argv[3]))
    if len(sys.argv) == 3 and sys.argv[1] == "diagnose-walk":
        sys.exit(_diagnose_walk(sys.argv[2]))
    if len(sys.argv) == 3 and sys.argv[1] == "local-admin-disable-totp":
        sys.exit(asyncio.run(_local_admin_disable_totp(sys.argv[2].lower())))
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
    print(
        "usage: python -m app.cli audit-verify | reencrypt | oui-import <oui.csv> | "
        "local-admin-reset <utilisateur> | local-admin-disable-totp <utilisateur> | "
        "walk-anonymize <entrée> <sortie.snmprec> | diagnose-walk <fichier>"
    )
    sys.exit(2)


if __name__ == "__main__":
    main()
