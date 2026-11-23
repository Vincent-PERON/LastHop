import pytest

from app.security.targets import (
    TargetNotAllowed,
    check_address,
    expand_hosts,
    parse_discovery_cidr,
    validate_cidr_list,
)
from app.snmp.client import as_text


def test_forbidden_addresses_even_if_in_allowlist() -> None:
    for ip in ("127.0.0.1", "169.254.169.254", "224.0.0.1", "0.0.0.0", "::1"):  # noqa: S104
        with pytest.raises(TargetNotAllowed):
            check_address(ip, ["0.0.0.0/0", "::/0"])


def test_default_deny_and_allowlist() -> None:
    with pytest.raises(TargetNotAllowed):
        check_address("10.1.2.3", [])
    assert str(check_address("10.1.2.3", ["10.1.0.0/16"])) == "10.1.2.3"
    with pytest.raises(TargetNotAllowed):
        check_address("10.2.2.3", ["10.1.0.0/16"])


def test_discovery_range_rules() -> None:
    allowed = ["10.1.0.0/16"]
    assert parse_discovery_cidr("10.1.2.0/24", allowed).num_addresses == 256
    for bad in ("10.2.0.0/24", "10.0.0.0/8", "10.1.0.0/15", "garbage", "127.0.0.0/30"):
        with pytest.raises(TargetNotAllowed):
            parse_discovery_cidr(bad, allowed)
    with pytest.raises(TargetNotAllowed):  # > 1024 adresses
        parse_discovery_cidr("10.1.0.0/21", ["10.1.0.0/16"])
    assert len(expand_hosts(parse_discovery_cidr("10.1.2.0/24", allowed))) == 254


def test_allowlist_validation() -> None:
    assert validate_cidr_list(["10.0.0.0/8", "192.168.1.0/24"]) == ["10.0.0.0/8", "192.168.1.0/24"]
    for bad in (["0.0.0.0/0"], ["10.0.0.1/8"], ["127.0.0.0/8"], ["nope"], ["::/0"]):
        with pytest.raises(ValueError):
            validate_cidr_list(bad)


def test_as_text_sanitizes_untrusted_device_strings() -> None:
    assert as_text(b"sw-01\x00\x1b[31m evil\nsecond line") == "sw-01[31m evil"
    assert len(as_text(b"A" * 10_000)) == 255
    assert as_text(b"\xff\xfeok").endswith("ok")
    assert as_text(None) == ""
    assert "second" in as_text(b"a\nsecond", multiline=True)


def test_driver_literal_matches_registry() -> None:
    from typing import get_args

    from app.api.devices import DriverName
    from app.drivers.registry import DRIVER_NAMES

    assert set(get_args(DriverName)) == set(DRIVER_NAMES)
