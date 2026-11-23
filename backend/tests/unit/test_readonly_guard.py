"""Garantie « SNMP en lecture seule » : aucune primitive d'écriture dans le code applicatif."""

import pathlib
import re

import app.snmp.client as client

FORBIDDEN = re.compile(r"set_cmd|setCmd|SetRequest|SetPDU|snmpset|\bset_with", re.IGNORECASE)


def test_no_snmp_write_primitive_in_source() -> None:
    root = pathlib.Path(client.__file__).parents[1]
    offenders = [str(p) for p in root.rglob("*.py") if FORBIDDEN.search(p.read_text(encoding="utf-8"))]
    assert offenders == []


def test_client_namespace_has_no_write_function() -> None:
    assert not any("set" in n.lower() and n.lower().endswith("cmd") for n in dir(client))
    assert {n for n in dir(client.SnmpClient) if not n.startswith("_")} == {"get", "walk"}


def test_weak_algorithms_not_available() -> None:
    assert "md5" not in client.AUTH_PROTOCOLS and not any("des" == k for k in client.PRIV_PROTOCOLS)
