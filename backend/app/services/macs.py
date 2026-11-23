"""Normalisation des adresses MAC saisies (tous formats) et des identifiants dérivés."""

from __future__ import annotations

import re

_SEP = re.compile(r"[\s:.\-]")
_HEX = re.compile(r"^[0-9a-f]+$")


def parse_mac_input(value: str, *, allow_partial: bool = False) -> str:
    """aa:bb:cc:dd:ee:ff, aabb.ccdd.eeff, AA-BB-CC-DD-EE-FF, aabbccddeeff -> hex minuscule sans séparateur.

    Strict : uniquement des chiffres hexadécimaux (aucun joker SQL possible). Partiel : 2 à 11 chiffres."""
    hexa = _SEP.sub("", value.strip().lower())
    if not _HEX.match(hexa):
        raise ValueError("MAC invalide")
    if len(hexa) == 12 or (allow_partial and 2 <= len(hexa) < 12):
        return hexa
    raise ValueError("MAC invalide")


def to_canonical(hexa: str) -> str:
    return ":".join(hexa[i : i + 2] for i in range(0, 12, 2))
