import json
import logging

from app.logging import JsonFormatter, redact


def test_redacts_sensitive_keys_and_values() -> None:
    out = redact(
        {
            "snmp_community": "public123",
            "nested": {"authkey": "abc"},
            "ok": "hello",
            "msg": "Bearer eyJhbGciOiJSUzI1NiJ9.abcdefghi.sig12345",
        }
    )
    assert out["snmp_community"] == "[REDACTED]" and out["nested"]["authkey"] == "[REDACTED]"
    assert out["ok"] == "hello" and "eyJ" not in out["msg"]


def test_formatter_masks_tokens_in_message() -> None:
    rec = logging.LogRecord(
        "x", logging.INFO, "f", 1, "token lasthop_deadbeef.%s used password=hunter2", ("A" * 43,), None
    )
    rec.password = "hunter2"
    line = json.loads(JsonFormatter().format(rec))
    assert "A" * 43 not in line["msg"] and "hunter2" not in json.dumps(line)
