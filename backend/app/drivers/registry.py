from __future__ import annotations

from app.drivers.base import Driver
from app.drivers.families import ArubaOsDriver, CiscoIosDriver, ComwareDriver, FortinetDriver, GenericDriver

_SPECIFIC: tuple[type[Driver], ...] = (ArubaOsDriver, ComwareDriver, CiscoIosDriver, FortinetDriver)
_ALL: tuple[type[Driver], ...] = (*_SPECIFIC, GenericDriver)
DRIVERS: dict[str, type[Driver]] = {d.name: d for d in _ALL}
DRIVER_NAMES = tuple(DRIVERS)


def detect_driver(sys_object_id: str) -> type[Driver]:
    for d in _SPECIFIC:
        if d.matches(sys_object_id):
            return d
    return GenericDriver


def get_driver(name: str) -> type[Driver]:
    return DRIVERS.get(name, GenericDriver)
