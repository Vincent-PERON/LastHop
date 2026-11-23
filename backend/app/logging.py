"""Logs structurés JSON avec masquage systématique des données sensibles."""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import Any

SENSITIVE_KEYS = re.compile(
    r"pass(word)?|secret|token|community|authorization|cookie|api[_-]?key|authkey|privkey|master|credential|session|csrf",
    re.IGNORECASE,
)
# Motifs de valeurs à masquer même dans un message libre.
_VALUE_PATTERNS = [
    re.compile(r"lasthop_[0-9a-f]{8}\.[A-Za-z0-9_-]{20,}"),  # token d'API
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"),  # JWT
    re.compile(r"(?i)((?:password|secret|token|community)=)[^\s&]+"),
]
REDACTED = "[REDACTED]"
_STD_ATTRS = set(vars(logging.LogRecord("", 0, "", 0, "", (), None))) | {"message", "asctime", "taskName"}


def redact_text(text: str) -> str:
    for pat in _VALUE_PATTERNS:
        text = pat.sub(lambda m: (m.group(1) + REDACTED) if m.groups() else REDACTED, text)
    return text


def redact(value: Any, key: str | None = None) -> Any:
    if key is not None and SENSITIVE_KEYS.search(key):
        return REDACTED
    if isinstance(value, dict):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact_text(record.getMessage()),
        }
        for k, v in record.__dict__.items():
            if k not in _STD_ATTRS and not k.startswith("_"):
                payload[k] = redact(v, k)
        if record.exc_info and record.exc_info[0] is not None:
            # Type + message masqué ; la stack complète reste côté serveur uniquement.
            payload["exc_type"] = record.exc_info[0].__name__
            payload["exc"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(payload, ensure_ascii=False, default=str)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    for noisy in ("uvicorn.access",):  # l'access log uvicorn contiendrait des URLs/queries : on log nous-mêmes
        logging.getLogger(noisy).disabled = True
