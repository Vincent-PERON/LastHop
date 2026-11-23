import json
import os

from sqlalchemy import text

from app.db import session as dbsession
from tests.conftest import V3


async def test_reencrypt_with_new_active_key(client, as_role, lab, app, tmp_path) -> None:  # type: ignore[no-untyped-def]
    from app.config import Settings
    from app.security.crypto import KeyRing

    c = await as_role("lasthop-admins")
    cid = (await c.post("/api/v1/credentials", json={"name": "rot", "version": "v3", **V3})).json()["id"]
    async for s in dbsession.get_session():
        old = (
            await s.execute(
                text("SELECT secret_blob, key_id FROM snmp_credentials WHERE id=CAST(:i AS uuid)"), {"i": cid}
            )
        ).one()
    assert old[1] == "k1"
    ring_data = json.loads(open(os.environ["LASTHOP_MASTER_KEYS_FILE"]).read())
    ring_data["keys"]["k2"] = __import__("base64").b64encode(os.urandom(32)).decode()
    ring_data["active"] = "k2"
    kf = tmp_path / "keys.json"
    kf.write_text(json.dumps(ring_data))
    # exécute la CLI avec le nouveau trousseau
    from app import cli

    os.environ["LASTHOP_MASTER_KEYS_FILE"] = str(kf)
    try:
        from app.config import get_settings

        get_settings.cache_clear()
        assert await cli._reencrypt() == 0
    finally:
        os.environ["LASTHOP_MASTER_KEYS_FILE"] = "/run/secrets/master_keys.json"
        from app.config import get_settings

        get_settings.cache_clear()
    async for s in dbsession.get_session():
        new = (
            await s.execute(
                text("SELECT secret_blob, key_id FROM snmp_credentials WHERE id=CAST(:i AS uuid)"), {"i": cid}
            )
        ).one()
    assert new[1] == "k2" and new[0] != old[0]
    s2 = Settings(master_keys_file=str(kf))
    import uuid

    from app.db.models import SnmpCredentialRow
    from app.services.credentials_store import unseal

    row = SnmpCredentialRow(id=uuid.UUID(cid), name="x", version="v3", secret_blob=bytes(new[0]), key_id="k2")
    assert unseal(KeyRing(s2.master_keys, s2.master_key_active), row)["auth_key"] == V3["auth_key"]
