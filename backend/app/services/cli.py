"""Aides pour les sessions CLI des équipements : profils par famille, nettoyage de sortie, masquage, comparaison."""

from __future__ import annotations

import difflib
import re
from collections.abc import Callable
from dataclasses import dataclass

ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][A-Z0-9]|\x1b[=>]|\x00")
# Marqueur de pagination + l'effacement que l'équipement envoie ensuite (retour chariot + espaces)
MORE = re.compile(
    r"[ \t]*(?:-{2,}\s*More\s*-{2,}|<-+\s*More\s*-+>|Press any key to continue[^\r\n]*)[ \t]*(?:\r[ \t]*)*", re.I
)


@dataclass(frozen=True)
class CliProfile:
    name: str
    prompt: re.Pattern[str]  # dernière ligne = invite d'exécution
    pager_off: tuple[str, ...]
    running: tuple[str, ...]  # commandes candidates, essayées dans l'ordre (versions de firmware différentes)
    startup: tuple[str, ...]
    needs_privilege: Callable[[str], bool]
    noise: tuple[re.Pattern[str], ...]  # lignes variables sans importance pour la comparaison running/startup


def _rx(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, re.I) for p in patterns)


PROFILES: dict[str, CliProfile] = {
    "cisco_ios": CliProfile(
        name="cisco_ios",
        prompt=re.compile(r"^[\w.\-/]+(?:\([\w\-/]+\))?[#>]\s*$"),
        pager_off=("terminal length 0",),
        running=("show running-config",),
        startup=("show startup-config",),
        needs_privilege=lambda p: p.rstrip().endswith(">"),  # mode utilisateur : `show running-config` y est refusé
        noise=_rx(
            r"^building configuration",
            r"^current configuration\s*:",
            r"^using \d+ out of",
            r"^!\s*last configuration change",
            r"^!\s*nvram config last updated",
            r"^!\s*no configuration change since",
            r"^\s*$",
            r"^!+\s*$",
        ),
    ),
    "comware": CliProfile(
        name="comware",
        prompt=re.compile(r"^(?:<[^<>\s]+>|\[[^\[\]\s]+\])\s*$"),
        pager_off=("screen-length disable",),
        running=("display current-configuration",),
        startup=("display saved-configuration",),
        needs_privilege=lambda p: False,  # niveau d'accès porté par le compte (role network-admin / level 3)
        noise=_rx(r"^#\s*$", r"^\s*$", r"^;.*(last|written)", r"^\s*version \d"),
    ),
    "aruba_os": CliProfile(
        name="aruba_os",
        prompt=re.compile(r"^[\w.\-/]+(?:\([\w\-/]+\))?[#>]\s*$"),
        pager_off=(
            "no page",
            "terminal length 1000",
        ),  # ArubaOS-Switch puis AOS-CX (la 2e peut être refusée : sans effet)
        running=("show running-config",),
        startup=("show startup-config", "show config"),  # AOS-CX puis ArubaOS-Switch / ProCurve
        needs_privilege=lambda p: p.rstrip().endswith(">"),
        noise=_rx(r"^;.*", r"^\s*$", r"^running configuration:", r"^startup configuration:"),
    ),
}

ERROR_MARKERS = re.compile(
    r"invalid input|% ?(?:unknown|ambiguous|incomplete|invalid)|unrecognized command|unknown command|"
    r"command not found|wrong parameter|syntax error|invalid command|not recognized",
    re.I,
)
ABSENT_MARKERS = re.compile(r"not present|no startup|is not found|no saved|does not exist", re.I)


def clean(text: str) -> str:
    """Retire séquences ANSI, retours chariot et artefacts de pagination ; normalise les fins de ligne."""
    t = MORE.sub("", ANSI.sub("", text)).replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip() for line in t.split("\n"))


def looks_like_error(output: str) -> bool:
    """Sortie très courte contenant un message d'erreur CLI (une vraie configuration est longue)."""
    head = output.strip()[:300]
    return len(output.strip()) < 400 and bool(ERROR_MARKERS.search(head))


def normalize(text: str, profile: CliProfile) -> str:
    lines = [ln.rstrip() for ln in text.split("\n")]
    return "\n".join(ln for ln in lines if not any(p.search(ln) for p in profile.noise))


# Masquage « au mieux » des secrets pour l'affichage par défaut (défense en profondeur ; le contenu brut reste chiffré en base)
_MASK_WORDS = r"password|secret|passphrase|community|key|auth-?key|priv-?key|encrypted-password|hash"
_MASK_QUALIFIERS = r"(?:\s+(?:\d{1,3}|cipher|simple|read|write|sha\d*|md5|aes\d*|des|hash|encrypted|manager|operator|user-name\s+\S+))*"
SNMPV3_RE = re.compile(r"(?i)(\b(?:auth|priv)\s+(?:sha\d*|md5|aes\d*|des)(?:\s+\d{1,3})?\s+)(\S+)")
SECRET_RE = re.compile(rf"(?i)(\b(?:{_MASK_WORDS})\b{_MASK_QUALIFIERS}\s+)(\"[^\"\n]+\"|[^\s\"]+)")
MASK = "********"


def mask_secrets(text: str) -> str:
    text = SNMPV3_RE.sub(lambda m: m.group(1) + MASK, text)
    return SECRET_RE.sub(lambda m: m.group(1) + MASK, text)


def diff_stats(old: str, new: str) -> tuple[int, int]:
    """(lignes ajoutées, lignes retirées)."""
    added = removed = 0
    for ln in difflib.ndiff(old.split("\n"), new.split("\n")):
        if ln.startswith("+ "):
            added += 1
        elif ln.startswith("- "):
            removed += 1
    return added, removed


def unified_diff(old: str, new: str, old_label: str, new_label: str) -> str:
    return "\n".join(difflib.unified_diff(old.split("\n"), new.split("\n"), old_label, new_label, lineterm="", n=3))
