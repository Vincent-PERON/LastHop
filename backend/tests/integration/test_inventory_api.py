import httpx
from sqlalchemy import text

from app.db import session as dbsession
from tests.conftest import V3

V3_BODY = {"name": "lab-v3", "version": "v3", **V3}


async def _admin(as_role) -> httpx.AsyncClient:  # type: ignore[no-untyped-def]
    return await as_role("lasthop-admins")


async def _sql(q: str, **p):  # type: ignore[no-untyped-def]
    async for s in dbsession.get_session():
        return (await s.execute(text(q), p)).all()


async def test_credential_secrets_encrypted_never_returned_nor_audited_nor_logged(client, as_role, lab, caplog) -> None:  # type: ignore[no-untyped-def]
    c = await _admin(as_role)
    r = await c.post("/api/v1/credentials", json=V3_BODY)
    assert r.status_code == 201, r.text
    cid = r.json()["id"]
    for url in ("/api/v1/credentials", f"/api/v1/credentials/{cid}"):
        resp = await c.get(url) if url.endswith("credentials") else r
        assert "test-auth-key-1234" not in resp.text and "test-priv-key-1234" not in resp.text
    row = (
        await _sql(
            "SELECT secret_blob, key_id FROM audit_log, snmp_credentials WHERE snmp_credentials.id = CAST(:i AS uuid) LIMIT 1",
            i=cid,
        )
    )[0]
    assert b"test-auth-key-1234" not in bytes(row[0]) and row[1] == "k1"
    audit = await _sql("SELECT details::text FROM audit_log WHERE action='credential.create' ORDER BY id DESC LIMIT 1")
    assert "test-" not in audit[0][0] and "lasthop-test" not in audit[0][0]
    assert "test-auth-key" not in caplog.text


async def test_credential_validation_rules(client, as_role, lab) -> None:  # type: ignore[no-untyped-def]
    c = await _admin(as_role)
    bad = [
        {**V3_BODY, "auth_proto": "md5"},
        {**V3_BODY, "priv_proto": "des"},
        {**V3_BODY, "auth_proto": "sha1"},
        {**V3_BODY, "auth_key": "short"},
        {**V3_BODY, "community": "abcdefgh"},
        {"name": "x", "version": "v2c", "community": "public"},
        {"name": "x", "version": "v2c", "community": "abc"},
        {"name": "x", "version": "v2c", "community": "good-community-1", "auth_key": "whatever-key"},
        {**V3_BODY, "security_level": "noAuthNoPriv"},
    ]
    for body in bad:
        assert (await c.post("/api/v1/credentials", json=body)).status_code == 422, body
    legacy = await c.post(
        "/api/v1/credentials", json={**V3_BODY, "name": "old", "auth_proto": "sha1", "allow_legacy_algos": True}
    )
    assert legacy.status_code == 201 and legacy.json()["auth_proto"] == "sha1"
    assert (await c.post("/api/v1/credentials", json=V3_BODY)).status_code == 201
    assert (await c.post("/api/v1/credentials", json=V3_BODY)).status_code == 409  # nom unique


async def test_v2c_refused_when_globally_disabled(client, as_role) -> None:  # type: ignore[no-untyped-def]
    c = await _admin(as_role)  # snmp_v2c_enabled = false par défaut
    r = await c.post("/api/v1/credentials", json={"name": "v2", "version": "v2c", "community": "lab-aruba"})
    assert r.status_code == 409 and "désactivé" in r.json()["detail"]
    assert (await c.put("/api/v1/settings/snmp_v2c_enabled", json={"value": True})).status_code == 200
    assert (
        await c.post("/api/v1/credentials", json={"name": "v2", "version": "v2c", "community": "lab-aruba"})
    ).status_code == 201


async def test_credential_update_keeps_or_rotates_secret_and_delete_blocked_when_used(client, as_role, lab) -> None:  # type: ignore[no-untyped-def]
    c = await _admin(as_role)
    cid = (await c.post("/api/v1/credentials", json=V3_BODY)).json()["id"]
    before = (await _sql("SELECT secret_blob FROM snmp_credentials WHERE id=CAST(:i AS uuid)", i=cid))[0][0]
    assert (await c.put(f"/api/v1/credentials/{cid}", json={"name": "renamed"})).status_code == 200
    assert (await _sql("SELECT secret_blob FROM snmp_credentials WHERE id=CAST(:i AS uuid)", i=cid))[0][0] == before
    assert (await c.put(f"/api/v1/credentials/{cid}", json={"auth_key": "another-auth-key-77"})).status_code == 200
    assert (await _sql("SELECT secret_blob FROM snmp_credentials WHERE id=CAST(:i AS uuid)", i=cid))[0][0] != before
    assert (await c.put(f"/api/v1/credentials/{cid}", json={"community": "abcdefgh"})).status_code == 422
    dev = await c.post(
        "/api/v1/devices", json={"name": "d1", "mgmt_ip": lab["ip"], "role": "access", "credential_id": cid}
    )
    assert dev.status_code == 201
    assert (await c.delete(f"/api/v1/credentials/{cid}")).status_code == 409
    assert (await c.delete(f"/api/v1/devices/{dev.json()['id']}")).status_code == 204
    assert (await c.delete(f"/api/v1/credentials/{cid}")).status_code == 204


async def test_credential_blob_cannot_be_swapped_between_profiles(client, as_role, lab, app) -> None:  # type: ignore[no-untyped-def]
    import pytest

    from app.db.models import SnmpCredentialRow
    from app.security.crypto import CryptoError, keyring_from_settings
    from app.services.credentials_store import unseal

    c = await _admin(as_role)
    a = (await c.post("/api/v1/credentials", json=V3_BODY)).json()["id"]
    b = (await c.post("/api/v1/credentials", json={**V3_BODY, "name": "other"})).json()["id"]
    blob_a = (await _sql("SELECT secret_blob FROM snmp_credentials WHERE id=CAST(:i AS uuid)", i=a))[0][0]
    s = app.state.settings
    ring = keyring_from_settings(s.master_keys, s.master_key_active)
    import uuid

    forged = SnmpCredentialRow(id=uuid.UUID(b), name="x", version="v3", secret_blob=bytes(blob_a), key_id="k1")
    with pytest.raises(CryptoError):
        unseal(ring, forged)


async def test_rbac_on_inventory_and_credentials(client, as_role, lab) -> None:  # type: ignore[no-untyped-def]
    c = await _admin(as_role)
    cid = (await c.post("/api/v1/credentials", json=V3_BODY)).json()["id"]
    dev = (
        await c.post("/api/v1/devices", json={"name": "d1", "mgmt_ip": lab["ip"], "role": "core", "credential_id": cid})
    ).json()
    assert "credential_id" in dev
    await client.post("/api/v1/auth/logout")
    client.cookies.clear()
    v = await as_role("lasthop-viewers")
    assert (await v.get("/api/v1/devices")).status_code == 403  # inventaire : super admin uniquement
    assert (await v.get(f"/api/v1/devices/{dev['id']}")).status_code == 403
    assert (await v.get("/api/v1/credentials")).status_code == 403
    assert (await v.post("/api/v1/devices", json={})).status_code == 403
    assert (await v.post(f"/api/v1/devices/{dev['id']}/test")).status_code == 403
    assert (await v.post("/api/v1/discovery", json={"cidr": "10.0.0.0/30", "credential_id": cid})).status_code == 403


async def test_device_validation_and_target_allowlist(client, as_role, lab) -> None:  # type: ignore[no-untyped-def]
    c = await _admin(as_role)
    cid = (await c.post("/api/v1/credentials", json=V3_BODY)).json()["id"]
    base = {"name": "d", "role": "access", "credential_id": cid}
    for ip in ("127.0.0.1", "169.254.169.254", "224.0.0.5", "8.8.8.8", "not-an-ip", "10.0.0.0/8"):
        assert (await c.post("/api/v1/devices", json={**base, "mgmt_ip": ip})).status_code == 422, ip
    for bad in (
        {"role": "root"},
        {"snmp_port": 0},
        {"timeout_ms": 5},
        {"name": "<b>x</b>"},
        {"poll_interval_s": 1},
        {"zzz": 1},
    ):
        assert (await c.post("/api/v1/devices", json={**base, "mgmt_ip": lab["ip"], **bad})).status_code == 422, bad
    assert (
        await c.post(
            "/api/v1/devices", json={**base, "mgmt_ip": lab["ip"], "site_id": "00000000-0000-0000-0000-000000000000"}
        )
    ).status_code == 422
    ok = await c.post("/api/v1/devices", json={**base, "mgmt_ip": lab["ip"]})
    assert ok.status_code == 201
    assert (await c.post("/api/v1/devices", json={**base, "name": "d2", "mgmt_ip": lab["ip"]})).status_code == 409
    upd = await c.put(f"/api/v1/devices/{ok.json()['id']}", json={"role": "core", "poll_interval_s": 300})
    assert upd.status_code == 200 and upd.json()["role"] == "core"
    assert (await c.put(f"/api/v1/devices/{ok.json()['id']}", json={"mgmt_ip": "127.0.0.1"})).status_code == 422


async def test_no_allowlist_means_no_targets(client, as_role) -> None:  # type: ignore[no-untyped-def]
    c = await _admin(as_role)  # aucune plage autorisée (défaut) : refus
    cid = (await c.post("/api/v1/credentials", json=V3_BODY)).json()["id"]
    r = await c.post(
        "/api/v1/devices", json={"name": "d", "mgmt_ip": "10.1.1.1", "role": "access", "credential_id": cid}
    )
    assert r.status_code == 422
    assert (await c.post("/api/v1/discovery", json={"cidr": "10.1.1.0/30", "credential_id": cid})).status_code == 422


async def test_settings_allowlist_validation_and_inventory_audit(client, as_role) -> None:  # type: ignore[no-untyped-def]
    c = await _admin(as_role)
    for bad in (["0.0.0.0/0"], ["10.0.0.1/8"], ["127.0.0.0/8"], "10.0.0.0/8", [1]):  # noqa: S104
        assert (await c.put("/api/v1/settings/snmp_allowed_cidrs", json={"value": bad})).status_code == 422, bad
    assert (await c.put("/api/v1/settings/snmp_allowed_cidrs", json={"value": ["10.0.0.0/8"]})).status_code == 200
    site = await c.post("/api/v1/sites", json={"name": "Siège"})
    assert site.status_code == 201 and (await c.post("/api/v1/sites", json={"name": "Siège"})).status_code == 409
    actions = {r[0] for r in await _sql("SELECT action FROM audit_log")}
    assert {"site.create", "settings.update"} <= actions


async def test_device_list_exposes_port_counts_and_snmp_version(client, as_role, lab) -> None:  # type: ignore[no-untyped-def]
    from app.db.models import Interface

    c = await _admin(as_role)
    cid = (await c.post("/api/v1/credentials", json=V3_BODY)).json()["id"]
    did = (
        await c.post(
            "/api/v1/devices", json={"name": "d1", "mgmt_ip": lab["ip"], "role": "access", "credential_id": cid}
        )
    ).json()["id"]
    empty = (await c.get("/api/v1/devices")).json()[0]
    assert (empty["ports_total"], empty["ports_up"], empty["ports_down"], empty["snmp_version"]) == (0, 0, 0, "v3")
    async for s in dbsession.get_session():
        for idx, st in ((1, 1), (2, 1), (3, 2), (4, None)):
            s.add(Interface(device_id=did, if_index=idx, name=f"p{idx}", oper_status=st))
        await s.commit()
    one = (await c.get(f"/api/v1/devices/{did}")).json()
    assert (one["ports_total"], one["ports_up"], one["ports_down"]) == (4, 2, 2)
    await client.post("/api/v1/auth/logout")
    client.cookies.clear()
    v = await as_role("lasthop-viewers")  # un viewer ne voit pas l'inventaire (le graphe de topologie reste accessible)
    assert (await v.get("/api/v1/devices")).status_code == 403
    assert (await v.get("/api/v1/topology/graph")).status_code == 200
