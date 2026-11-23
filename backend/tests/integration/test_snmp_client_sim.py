"""Client SNMP et drivers contre snmpsim (enregistrements .snmprec Aruba / Comware / Cisco)."""

import pytest

from app.drivers.registry import detect_driver
from app.services.probe import identify_target
from app.snmp import oids
from app.snmp.client import AUTH_FAILURE, TIMEOUT, SnmpClient, SnmpCredential, SnmpError, SnmpTarget, as_text

PORT = 1161
V3 = SnmpCredential(
    version="v3",
    username="lasthop-test",
    auth_proto="sha256",
    priv_proto="aes128",
    auth_key="test-auth-key-1234",
    priv_key="test-priv-key-1234",
)


def v2(community: str) -> SnmpCredential:
    return SnmpCredential(version="v2c", community=community)


def target(ip: str, cred: SnmpCredential, ctx: str = "", **kw: float) -> SnmpTarget:
    return SnmpTarget(host=ip, port=PORT, credential=cred, context_name=ctx, **{"timeout_s": 2, "retries": 0, **kw})


async def test_v2c_get(sim_ip: str) -> None:
    async with SnmpClient(target(sim_ip, v2("lab-aruba"))) as c:
        r = await c.get(oids.SYS_NAME)
    assert as_text(r[oids.SYS_NAME]) == "sw-access-aruba-01"


async def test_v3_authpriv_sha256_aes(sim_ip: str) -> None:
    async with SnmpClient(target(sim_ip, V3, ctx="lab-cisco")) as c:
        r = await c.get(oids.SYS_NAME)
    assert as_text(r[oids.SYS_NAME]) == "sw-core-cisco-01"


async def test_walk_getbulk_returns_subtree_only(sim_ip: str) -> None:
    async with SnmpClient(target(sim_ip, v2("lab-comware"))) as c:
        rows = [(o, as_text(v)) async for o, v in c.walk(oids.IF_DESCR, max_repetitions=2)]
    assert [v for _, v in rows][:3] == ["GigabitEthernet1/0/1", "GigabitEthernet1/0/2", "GigabitEthernet1/0/3"]
    assert len(rows) == 5  # 4 ports + Vlan-interface1
    assert all(o.startswith(oids.IF_DESCR + ".") for o, _ in rows)


async def test_walk_respects_max_rows(sim_ip: str) -> None:
    async with SnmpClient(target(sim_ip, v2("lab-comware"))) as c:
        rows = [r async for r in c.walk(oids.IF_DESCR, max_rows=2)]
    assert len(rows) == 2


async def test_wrong_community_is_reported_as_unreachable(sim_ip: str) -> None:
    with pytest.raises(SnmpError) as e:
        async with SnmpClient(target(sim_ip, v2("not-a-community"), timeout_s=1)) as c:
            await c.get(oids.SYS_NAME)
    assert e.value.code == TIMEOUT


async def test_wrong_v3_key_is_reported_as_auth_failure(sim_ip: str) -> None:
    bad = SnmpCredential(
        version="v3",
        username="lasthop-test",
        auth_proto="sha256",
        priv_proto="aes128",
        auth_key="wrong-auth-key-9999",
        priv_key="test-priv-key-1234",
    )
    with pytest.raises(SnmpError) as e:
        async with SnmpClient(target(sim_ip, bad, ctx="lab-aruba")) as c:
            await c.get(oids.SYS_NAME)
    assert e.value.code == AUTH_FAILURE


async def test_v3_requires_authpriv_whitelisted_algos(sim_ip: str) -> None:
    weak = SnmpCredential(
        version="v3", username="u", auth_proto="md5", priv_proto="des", auth_key="x" * 8, priv_key="y" * 8
    )
    with pytest.raises(SnmpError):
        async with SnmpClient(target(sim_ip, weak)) as c:
            await c.get(oids.SYS_NAME)


@pytest.mark.parametrize(
    ("community", "driver", "vendor", "model", "name"),
    [
        ("lab-aruba", "aruba_os", "HPE Aruba", "JL253A", "sw-access-aruba-01"),
        ("lab-comware", "comware", "HPE Comware", "HPE 5130-24G-4SFP+ EI", "sw-dist-comware-01"),
        ("lab-cisco", "cisco_ios", "Cisco", "WS-C2960X-48FPD-L", "sw-core-cisco-01"),
    ],
)
async def test_driver_detection_and_identity(
    sim_ip: str, community: str, driver: str, vendor: str, model: str, name: str
) -> None:
    ident = await identify_target(target(sim_ip, v2(community)))
    assert (ident.driver, ident.vendor, ident.model, ident.sys_name) == (driver, vendor, model, name)
    assert detect_driver(ident.sys_object_id).name == driver


async def test_model_falls_back_to_sysdescr_when_entity_mib_missing(sim_ip: str) -> None:
    # lab-comware n'a pas d'entPhysicalModelName : le modèle vient de sysDescr (multiligne)
    ident = await identify_target(target(sim_ip, v2("lab-comware")))
    assert ident.model == "HPE 5130-24G-4SFP+ EI" and "\n" not in ident.sys_descr


async def test_untrusted_ifalias_is_kept_raw_but_bounded(sim_ip: str) -> None:
    async with SnmpClient(target(sim_ip, v2("lab-aruba"))) as c:
        rows = [as_text(v) async for _, v in c.walk(oids.IF_ALIAS)]
    assert rows == [
        "<script>alert(1)</script>poste-compta"
    ]  # l'échappement se fait au rendu (front), jamais par v-html
