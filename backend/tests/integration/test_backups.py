"""Sauvegarde des configurations (running + startup) par SSH, contre de faux switchs (tests-infra/sshsim)."""

import socket

import httpx
import pytest
from sqlalchemy import text

from app.db import session as dbsession
from tests.conftest import V3, wait_job

SSH_PASSWORD = "test-ssh-password-1234"
SECRETS = (
    "TopSecretCommunity",
    "$1$abcd$XyZ123SecretHashValue",
    "$9$VerySecretScryptHash",
    "MyAuthKey12345",
    "MyPrivKey12345",
)
PORT = {
    "cisco": 2201,
    "comware": 2202,
    "aruba": 2203,
    "run_ne_startup": 2204,
    "changed": 2205,
    "paging": 2206,
    "user_mode": 2207,
    "rejected": 2208,
    "empty": 2209,
    "silent": 2210,
    "legacy": 2211,
    "no_startup": 2212,
    "other_key": 2215,
    "slow": 2216,
    "cfg_cisco": 2217,  # modification de port : un faux équipement par syntaxe (test_port_config_api.py)
    "cfg_comware": 2218,
    "cfg_cx": 2219,
    "cfg_os": 2220,
    "cfg_reject": 2221,
}


@pytest.fixture(scope="session")
def ssh_ip() -> str:
    return socket.gethostbyname("sshsim")


async def _sql(q: str, **p):  # type: ignore[no-untyped-def]
    async for s in dbsession.get_session():
        return (await s.execute(text(q), p)).all()


async def make_device(
    c,
    ip,
    persona="cisco",
    *,
    driver="cisco_ios",
    trust=True,
    profile=True,
    password=SSH_PASSWORD,
    legacy=False,  # type: ignore[no-untyped-def]
    username="backup",
    name="sw1",
):
    cid = (await c.post("/api/v1/credentials", json={"name": f"snmp-{name}", "version": "v3", **V3})).json()["id"]
    body = {
        "name": name,
        "mgmt_ip": ip,
        "role": "access",
        "credential_id": cid,
        "driver": driver,
        "ssh_port": PORT[persona],
        "ssh_allow_legacy": legacy,
    }
    if profile:
        sid = (
            await c.post(
                "/api/v1/ssh-credentials", json={"name": f"ssh-{name}", "username": username, "password": password}
            )
        ).json()["id"]
        body["ssh_credential_id"] = sid
    dev = await c.post("/api/v1/devices", json=body)
    if dev.status_code != 201:
        print("DBGBODY", body, (await c.get("/api/v1/settings")).json())
    assert dev.status_code == 201, dev.text
    did = dev.json()["id"]
    if trust:
        await trust_key(c, did)
    return did


async def trust_key(c, did, expect=200):  # type: ignore[no-untyped-def]
    j = await wait_job(c, (await c.post(f"/api/v1/devices/{did}/ssh/hostkey")).json()["job_id"])
    assert j["status"] == "done", j
    r = await c.post(
        f"/api/v1/devices/{did}/ssh/trust", json={"job_id": j["id"], "fingerprint": j["result"]["fingerprint"]}
    )
    assert r.status_code == expect, r.text
    return j["result"]["fingerprint"]


async def backup(c, did):  # type: ignore[no-untyped-def]
    j = await wait_job(c, (await c.post(f"/api/v1/devices/{did}/backup")).json()["job_id"], timeout=60)
    run = (await c.get("/api/v1/backups/runs", params={"device_id": did, "limit": 1})).json()["items"][0]
    detail = (await c.get(f"/api/v1/backups/runs/{run['id']}")).json()
    return j, detail


def messages(detail) -> str:  # type: ignore[no-untyped-def]
    return "\n".join(f"{e['message']} {e['advice'] or ''}" for e in detail["events"])


@pytest.fixture
async def admin(client, as_role, lab3, inline_jobs):  # type: ignore[no-untyped-def]
    return await as_role("lasthop-admins")


async def test_cisco_backup_success_encrypted_masked_and_readable_log(admin, ssh_ip, caplog) -> None:  # type: ignore[no-untyped-def]
    did = await make_device(admin, ssh_ip, "cisco")
    j, run = await backup(admin, did)
    assert (
        j["status"] == "done"
        and run["status"] == "success"
        and run["results"] == {"running": "success", "startup": "success"}
    )
    assert run["summary"].startswith("Sauvegarde réussie") and run["trigger"] == "manual"
    log = messages(run)
    for phrase in (
        "Début de la sauvegarde de « sw1 »",
        "Connexion SSH établie",
        "Pagination désactivée",
        "première sauvegarde",
        "identiques : rien ne serait perdu",
    ):
        assert phrase in log, phrase
    assert [e["level"] for e in run["events"]][0] == "info" and run["events"][-1]["level"] == "ok"
    # stockage : chiffré et compressé, jamais en clair
    blobs = [bytes(r[0]) for r in await _sql("SELECT content_blob FROM config_backups WHERE status='success'")]
    assert len(blobs) == 2 and all(b"hostname sw-core" not in b and b"TopSecret" not in b for b in blobs)
    # consultation : secrets masqués par défaut ; contenu brut = accès audité
    versions = (await admin.get(f"/api/v1/devices/{did}/backups")).json()
    running = next(v for v in versions if v["kind"] == "running")
    masked = (await admin.get(f"/api/v1/backups/{running['id']}")).json()
    assert (
        masked["masked"]
        and "hostname sw-core" in masked["content"]
        and not any(s in masked["content"] for s in SECRETS)
    )
    raw = (await admin.get(f"/api/v1/backups/{running['id']}", params={"raw": "true"})).json()
    assert not raw["masked"] and "TopSecretCommunity" in raw["content"] and "--More--" not in raw["content"]
    actions = {
        r[0]
        for r in await _sql(
            "SELECT action FROM audit_log WHERE action LIKE 'backup.%' OR action LIKE 'ssh_%' OR action LIKE 'device.ssh%'"
        )
    }
    assert {"backup.run", "backup.view", "backup.view_raw", "ssh_credential.create", "device.ssh_trust"} <= actions
    # aucun secret nulle part : journal, audit, logs
    everything = (
        log
        + str(await _sql("SELECT details::text FROM audit_log"))
        + str(await _sql("SELECT detail, message FROM backup_events"))
        + caplog.text
    )
    assert SSH_PASSWORD not in everything and "TopSecretCommunity" not in everything


async def test_second_backup_is_unchanged_and_change_is_detected_with_diff(admin, ssh_ip) -> None:  # type: ignore[no-untyped-def]
    did = await make_device(admin, ssh_ip, "cisco")
    await backup(admin, did)
    _, run2 = await backup(admin, did)
    assert run2["results"] == {"running": "unchanged", "startup": "unchanged"}
    assert "identique à celle du" in messages(run2) and "aucun changement" in run2["summary"]
    assert (await _sql("SELECT count(*) FROM config_backups WHERE status='success'"))[0][0] == 2
    # la configuration change côté équipement (autre personnalité du faux switch)
    assert (await admin.put(f"/api/v1/devices/{did}", json={"ssh_port": PORT["changed"]})).status_code == 200
    _, run3 = await backup(admin, did)
    assert run3["results"]["running"] == "success" and "a changé depuis la sauvegarde du" in messages(run3)
    assert "ligne(s) ajoutée(s)" in messages(run3)
    versions = (await admin.get(f"/api/v1/devices/{did}/backups")).json()
    running = [v for v in versions if v["kind"] == "running" and v["status"] == "success"]
    assert len(running) == 2
    old, new = sorted(running, key=lambda v: v["created_at"])
    d = (await admin.get("/api/v1/backups/diff", params={"a": old["id"], "b": new["id"]})).json()
    assert (
        d["added"] >= 3
        and d["removed"] >= 1
        and "+ description poste-compta-v2" in d["diff"].replace("+ description", "+ description")
    )
    assert "TopSecretCommunity" not in d["diff"] and "interface Vlan99" in d["diff"]
    # une version « identique » donne accès au même contenu
    same = next(v for v in versions if v["status"] == "unchanged")
    assert (await admin.get(f"/api/v1/backups/{same['id']}")).json()["content"]


@pytest.mark.parametrize(
    ("persona", "driver", "needle"),
    [("comware", "comware", "sysname sw-dist"), ("aruba", "aruba_os", 'hostname "sw-acc"')],
)
async def test_other_vendors_and_startup_command_fallback(admin, ssh_ip, persona, driver, needle) -> None:  # type: ignore[no-untyped-def]
    did = await make_device(admin, ssh_ip, persona, driver=driver)
    _, run = await backup(admin, did)
    assert run["status"] == "success", messages(run)  # Aruba : `show startup-config` refusé -> repli sur `show config`
    v = next(x for x in (await admin.get(f"/api/v1/devices/{did}/backups")).json() if x["kind"] == "startup")
    assert needle in (await admin.get(f"/api/v1/backups/{v['id']}")).json()["content"]


async def test_running_different_from_startup_is_explained(admin, ssh_ip) -> None:  # type: ignore[no-untyped-def]
    did = await make_device(admin, ssh_ip, "run_ne_startup")
    _, run = await backup(admin, did)
    assert run["status"] == "success"
    warn = next(e for e in run["events"] if e["level"] == "warn")
    assert (
        "DIFFÉRENTE" in warn["message"]
        and "perdues au prochain redémarrage" in warn["message"]
        and "write memory" in warn["advice"]
    )


async def test_pagination_is_handled_even_when_it_cannot_be_disabled(admin, ssh_ip) -> None:  # type: ignore[no-untyped-def]
    did = await make_device(admin, ssh_ip, "paging")
    _, run = await backup(admin, did)
    assert run["status"] == "success", messages(run)
    v = next(x for x in (await admin.get(f"/api/v1/devices/{did}/backups")).json() if x["kind"] == "running")
    content = (await admin.get(f"/api/v1/backups/{v['id']}", params={"raw": "true"})).json()["content"]
    assert "--More--" not in content and content.rstrip().endswith("end") and content.count("hostname sw-core") == 3


FAILURES = [
    # (scénario, code attendu, extrait lisible du message)
    ("no_profile", "NO_SSH_PROFILE", "Aucun profil de connexion SSH"),
    ("generic", "UNSUPPORTED_DRIVER", "pas encore reconnu"),
    ("no_hostkey", "SSH_HOSTKEY_UNKNOWN", "n'a jamais été validée"),
    ("bad_password", "SSH_AUTH_FAILED", "refusé l'identifiant ou le mot de passe"),
    ("closed_port", "SSH_REFUSED", "refusé la connexion SSH"),
    ("user_mode", "SSH_PRIVILEGE_REQUIRED", "mode utilisateur"),
    ("rejected", "CLI_COMMAND_REJECTED", "refusé la commande"),
    ("empty", "CLI_OUTPUT_EMPTY", "vide ou trop courte"),
    ("changed_key", "SSH_HOSTKEY_CHANGED", "CHANGÉ"),
    ("legacy", "SSH_ALGO_MISMATCH", "aucun algorithme de chiffrement SSH en commun"),
    ("not_allowed", "TARGET_NOT_ALLOWED", "en dehors des réseaux autorisés"),
]


@pytest.mark.parametrize(("scenario", "code", "phrase"), FAILURES)
async def test_failures_are_explained_in_plain_language(admin, ssh_ip, scenario, code, phrase) -> None:  # type: ignore[no-untyped-def]
    kw: dict = {}
    persona = {
        "user_mode": "user_mode",
        "rejected": "rejected",
        "empty": "empty",
        "legacy": "legacy",
        "changed_key": "cisco",
    }.get(scenario, "cisco")
    if scenario == "no_profile":
        kw["profile"] = False
    if scenario == "generic":
        kw["driver"] = "generic"
    if scenario == "no_hostkey":
        kw["trust"] = False
    if scenario == "bad_password":
        kw["password"] = "wrong-password-1234"
    if scenario == "legacy":
        kw["legacy"] = True  # nécessaire pour approuver l'empreinte ; retiré ensuite pour provoquer l'échec
    did = await make_device(admin, ssh_ip, persona, **kw)
    if scenario == "legacy":
        assert (await admin.put(f"/api/v1/devices/{did}", json={"ssh_allow_legacy": False})).status_code == 200
    if scenario == "closed_port":
        assert (await admin.put(f"/api/v1/devices/{did}", json={"ssh_port": 2299})).status_code == 200
    if scenario == "changed_key":
        assert (await admin.put(f"/api/v1/devices/{did}", json={"ssh_port": PORT["other_key"]})).status_code == 200
    if scenario == "not_allowed":
        async for s in dbsession.get_session():
            await s.execute(
                text("UPDATE app_settings SET value='[\"10.254.0.0/16\"]'::jsonb WHERE key='snmp_allowed_cidrs'")
            )
            await s.commit()
    j, run = await backup(admin, did)
    assert (j["status"], j["error_code"]) == ("failed", code), messages(run)
    assert run["status"] == "failed" and run["error_code"] == code and run["summary"].startswith("Sauvegarde échouée")
    err = [e for e in run["events"] if e["level"] == "error"]
    assert err and phrase in err[0]["message"] and err[0]["advice"]  # « que faire » systématique
    for e in err:  # le message principal est du français, sans jargon technique
        assert not any(t in e["message"] for t in ("Traceback", "Exception", "asyncssh", "Errno"))
    assert run["events"][-1]["level"] == "error"  # la dernière ligne résume l'échec
    dev = (await admin.get(f"/api/v1/devices/{did}")).json()
    assert dev["last_backup_status"] == "failed"
    assert (await _sql("SELECT count(*) FROM config_backups"))[0][0] == 0  # rien d'incomplet n'est enregistré


async def test_legacy_algorithms_flag_fixes_old_device_and_is_audited(admin, ssh_ip) -> None:  # type: ignore[no-untyped-def]
    did = await make_device(
        admin, ssh_ip, "legacy", legacy=True
    )  # l'équipement ancien exige les algorithmes hérités même pour l'empreinte
    assert (await admin.put(f"/api/v1/devices/{did}", json={"ssh_allow_legacy": False})).status_code == 200
    _, run = await backup(admin, did)
    assert run["error_code"] == "SSH_ALGO_MISMATCH"
    assert (await admin.put(f"/api/v1/devices/{did}", json={"ssh_allow_legacy": True})).status_code == 200
    _, run = await backup(admin, did)
    assert run["status"] == "success", messages(run)
    ch = (
        await _sql(
            "SELECT details->'changed_fields' FROM audit_log WHERE action='device.update' ORDER BY id DESC LIMIT 1"
        )
    )[0][0]
    assert "ssh_allow_legacy" in ch


async def test_partial_backup_when_only_one_config_fails(admin, ssh_ip) -> None:  # type: ignore[no-untyped-def]
    did = await make_device(admin, ssh_ip, "no_startup")
    j, run = await backup(admin, did)
    assert (
        run["status"] == "partial"
        and run["results"]["running"] == "success"
        and run["results"]["startup"] == "failed:CLI_COMMAND_REJECTED"
    )
    assert run["summary"].startswith("Sauvegarde incomplète") and j["status"] == "done"
    assert any("startup :" in e["message"] and e["level"] == "error" for e in run["events"])
    assert (await admin.get("/api/v1/backups/runs", params={"status": "partial"})).json()["total"] == 1


async def test_timeouts_are_reported_not_hung(admin, ssh_ip, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr("app.services.ssh_backup.PROMPT_TIMEOUT", 2.0)
    monkeypatch.setattr("app.services.ssh_backup.COMMAND_TIMEOUT", 2.0)
    did = await make_device(admin, ssh_ip, "silent")
    _, run = await backup(admin, did)
    assert run["error_code"] == "CLI_PROMPT_TIMEOUT" and "n'a pas affiché son invite" in messages(run)
    assert (await admin.put(f"/api/v1/devices/{did}", json={"ssh_port": PORT["slow"]})).status_code == 200
    _, run = await backup(admin, did)
    assert run["error_code"] in ("CLI_TIMEOUT", "CLI_PROMPT_TIMEOUT")


async def test_hostkey_approval_requires_retyping_and_is_scoped(admin, client, ssh_ip, as_role) -> None:  # type: ignore[no-untyped-def]
    denied_before = (await _sql("SELECT count(*) FROM audit_log WHERE action='device.ssh_trust' AND outcome='denied'"))[
        0
    ][0]
    did = await make_device(admin, ssh_ip, "cisco", trust=False)
    j = await wait_job(admin, (await admin.post(f"/api/v1/devices/{did}/ssh/hostkey")).json()["job_id"])
    assert j["result"]["fingerprint"].startswith("SHA256:") and "public_key" in j["result"]
    bad = await admin.post(
        f"/api/v1/devices/{did}/ssh/trust", json={"job_id": j["id"], "fingerprint": "SHA256:wrongwrongwrong"}
    )
    assert bad.status_code == 422
    assert (await admin.get(f"/api/v1/devices/{did}")).json()[
        "ssh_host_fingerprint"
    ] is None  # rien n'est approuvé à l'aveugle
    ok = await admin.post(
        f"/api/v1/devices/{did}/ssh/trust", json={"job_id": j["id"], "fingerprint": j["result"]["fingerprint"]}
    )
    assert (
        ok.status_code == 200
        and (await admin.get(f"/api/v1/devices/{did}")).json()["ssh_host_fingerprint"] == j["result"]["fingerprint"]
    )
    # une vérification ne vaut que pour SON équipement
    import ipaddress as _ip

    other = await make_device(admin, str(_ip.ip_address(ssh_ip) + 1), "cisco", trust=False, name="sw2")
    assert (
        await admin.post(
            f"/api/v1/devices/{other}/ssh/trust", json={"job_id": j["id"], "fingerprint": j["result"]["fingerprint"]}
        )
    ).status_code == 404
    # changer l'adresse de management efface l'approbation (autre équipement)
    import ipaddress

    new_ip = str(ipaddress.ip_address(ssh_ip) + 7)
    assert (await admin.put(f"/api/v1/devices/{did}", json={"mgmt_ip": new_ip})).status_code == 200
    assert (await admin.get(f"/api/v1/devices/{did}")).json()["ssh_host_fingerprint"] is None
    denied = await _sql("SELECT count(*) FROM audit_log WHERE action='device.ssh_trust' AND outcome='denied'")
    assert denied[0][0] - denied_before == 1  # l'audit est append-only : on compte la différence


async def test_ssh_profiles_secrets_key_auth_and_validation(admin, ssh_ip) -> None:  # type: ignore[no-untyped-def]
    import asyncssh

    key = asyncssh.generate_private_key("ssh-ed25519")
    pem = key.export_private_key().decode()
    for bad in (
        {"auth_type": "password"},
        {"auth_type": "key", "password": "x"},
        {"auth_type": "key", "private_key": "x" * 60},
        {"auth_type": "password", "password": "x", "private_key": pem},
        {"auth_type": "password", "password": "x", "zzz": 1},
    ):
        assert (
            await admin.post("/api/v1/ssh-credentials", json={"name": "p", "username": "u", **bad})
        ).status_code == 422, bad
    r = await admin.post(
        "/api/v1/ssh-credentials",
        json={"name": "keyprof", "username": "keyuser", "auth_type": "key", "private_key": pem},
    )
    assert r.status_code == 201 and pem not in r.text and "private_key" not in r.json()
    assert pem not in (await admin.get("/api/v1/ssh-credentials")).text
    blob = bytes((await _sql("SELECT secret_blob FROM ssh_credentials WHERE name='keyprof'"))[0][0])
    assert b"PRIVATE KEY" not in blob and b"OPENSSH" not in blob
    # authentification par clé contre le faux switch
    cid = (await admin.post("/api/v1/credentials", json={"name": "s", "version": "v3", **V3})).json()["id"]
    did = (
        await admin.post(
            "/api/v1/devices",
            json={
                "name": "k1",
                "mgmt_ip": ssh_ip,
                "role": "access",
                "credential_id": cid,
                "driver": "cisco_ios",
                "ssh_port": 2201,
                "ssh_credential_id": r.json()["id"],
            },
        )
    ).json()["id"]
    await trust_key(admin, did)
    _, run = await backup(admin, did)
    assert run["status"] == "success", messages(run)
    assert (await admin.put(f"/api/v1/ssh-credentials/{r.json()['id']}", json={"password": "nope"})).status_code == 422
    assert (await admin.delete(f"/api/v1/ssh-credentials/{r.json()['id']}")).status_code == 204
    _, run = await backup(admin, did)  # profil supprimé : message clair
    assert run["error_code"] == "NO_SSH_PROFILE"


async def test_rbac_only_admins_can_see_or_run_backups(client, as_role, lab3, ssh_ip, inline_jobs, app) -> None:  # type: ignore[no-untyped-def]
    a = await as_role("lasthop-admins")
    did = await make_device(a, ssh_ip, "cisco")
    _, run = await backup(a, did)
    bid = (await a.get(f"/api/v1/devices/{did}/backups")).json()[0]["id"]
    await client.post("/api/v1/auth/logout")
    client.cookies.clear()
    assert (await client.get("/api/v1/backups/runs")).status_code == 401
    for role in ("lasthop-operators", "lasthop-viewers"):
        c = await as_role(role)
        for method, url in (
            ("GET", "/api/v1/backups/runs"),
            ("GET", f"/api/v1/backups/runs/{run['id']}"),
            ("GET", f"/api/v1/backups/{bid}"),
            ("GET", f"/api/v1/devices/{did}/backups"),
            ("POST", f"/api/v1/devices/{did}/backup"),
            ("POST", f"/api/v1/devices/{did}/ssh/hostkey"),
            ("GET", "/api/v1/ssh-credentials"),
        ):
            assert (await c.request(method, url)).status_code == 403, (role, url)
        assert (await c.get(f"/api/v1/devices/{did}")).status_code == 403, role  # fiche équipement : super admin
        await client.post("/api/v1/auth/logout")
        client.cookies.clear()


async def test_scheduler_only_picks_enabled_due_devices(admin, ssh_ip) -> None:  # type: ignore[no-untyped-def]
    from app.services.scheduler import create_due_backup_jobs

    d1 = await make_device(admin, ssh_ip, "cisco", name="a1")
    cid = (await admin.post("/api/v1/credentials", json={"name": "s2", "version": "v3", **V3})).json()["id"]
    import ipaddress

    d2 = (
        await admin.post(
            "/api/v1/devices",
            json={
                "name": "a2",
                "mgmt_ip": str(ipaddress.ip_address(ssh_ip) + 3),
                "role": "access",
                "credential_id": cid,
            },
        )
    ).json()["id"]
    assert d2
    assert (await admin.put(f"/api/v1/devices/{d1}", json={"backup_enabled": True})).status_code == 200
    async for s in dbsession.get_session():
        ids = await create_due_backup_jobs(s)
        again = await create_due_backup_jobs(s)
        kinds = [r[0] for r in (await s.execute(text("SELECT params->>'trigger' FROM jobs WHERE kind='backup'"))).all()]
    assert len(ids) == 1 and again == [] and kinds == ["scheduled"]
    assert (
        await admin.put("/api/v1/settings/backup_interval_s", json={"value": 100})
    ).status_code == 422  # minimum 1 h


async def test_retention_keeps_latest_and_referenced_versions(admin, ssh_ip) -> None:  # type: ignore[no-untyped-def]
    from app.services.retention import purge

    did = await make_device(admin, ssh_ip, "cisco")
    await backup(admin, did)
    await backup(admin, did)  # 2 versions « identiques » référencent la 1re
    assert (await admin.put("/api/v1/settings/backup_retention_days", json={"value": 7})).status_code == 200
    async for s in dbsession.get_session():
        await s.execute(text("UPDATE config_backups SET created_at = now() - interval '30 days'"))
        await s.execute(text("UPDATE backup_runs SET started_at = now() - interval '30 days'"))
        await s.commit()
        totals = await purge(s)
        left = (await s.execute(text("SELECT status, kind FROM config_backups ORDER BY kind"))).all()
    assert [tuple(r) for r in left] == [
        ("success", "running"),
        ("success", "startup"),
    ]  # la dernière version de chaque type survit
    assert totals["config_backups"] == 0 and totals["backup_runs"] == 2
    v = (await admin.get(f"/api/v1/devices/{did}/backups")).json()
    assert (await admin.get(f"/api/v1/backups/{v[0]['id']}")).status_code == 200


async def test_backup_through_real_celery_worker(client, as_role, lab3, ssh_ip, app) -> None:  # type: ignore[no-untyped-def]
    a = await as_role("lasthop-admins")
    did = await make_device(a, ssh_ip, "comware", driver="comware")
    j = await wait_job(a, (await a.post(f"/api/v1/devices/{did}/backup")).json()["job_id"], timeout=60)
    assert j["status"] == "done" and j["result"]["status"] == "success"
    assert (await a.get(f"/api/v1/devices/{did}")).json()["last_backup_status"] == "success"
    _ = httpx
