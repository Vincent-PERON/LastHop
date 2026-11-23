"""Sauvegarde des configurations (running + startup) par SSH, en LECTURE SEULE (commandes d'affichage uniquement)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import asyncssh
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import BackupEvent, BackupRun, ConfigBackup, Device, SshCredentialRow
from app.drivers.registry import get_driver
from app.security.crypto import CryptoError, KeyRing
from app.security.targets import TargetNotAllowed, check_address
from app.services import cli
from app.services.backup_messages import KIND_LABEL, fmt_size, human
from app.services.settings_store import all_values

log = logging.getLogger("lasthop.backup")

CONNECT_TIMEOUT = 10.0
LOGIN_TIMEOUT = 20.0
PROMPT_TIMEOUT = 15.0
COMMAND_TIMEOUT = 90.0
MAX_BYTES = 5 * 1024 * 1024
MIN_CONFIG_BYTES = 30
LEGACY = {
    "kex_algs": "+diffie-hellman-group14-sha1",
    "encryption_algs": "+aes128-cbc,aes256-cbc",
    "mac_algs": "+hmac-sha1",
    "server_host_key_algs": "+ssh-rsa",
}


class BackupError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code)
        self.code, self.detail = code, detail


# ----------------------------------------------------------------------------------------------- chiffrement


def seal_secret(keyring: KeyRing, cred_id: uuid.UUID, secrets: dict[str, str]) -> tuple[bytes, str]:
    return keyring.encrypt(json.dumps(secrets).encode(), f"ssh_credentials:{cred_id}"), keyring.active_kid


def unseal_secret(keyring: KeyRing, row: SshCredentialRow) -> dict[str, str]:
    data: dict[str, str] = json.loads(keyring.decrypt(row.secret_blob, f"ssh_credentials:{row.id}"))
    return data


def seal_config(keyring: KeyRing, backup_id: uuid.UUID, text: str) -> bytes:
    return keyring.encrypt(zlib.compress(text.encode("utf-8")), f"config_backups:{backup_id}")


def unseal_config(keyring: KeyRing, row: ConfigBackup) -> str:
    if row.content_blob is None:
        raise CryptoError("contenu absent")
    return zlib.decompress(keyring.decrypt(bytes(row.content_blob), f"config_backups:{row.id}")).decode("utf-8")


# ----------------------------------------------------------------------------------------------- SSH


def fingerprint(key: asyncssh.SSHKey) -> str:
    return str(key.get_fingerprint("sha256"))


def _classify(exc: BaseException) -> BackupError:
    """Traduit une exception asyncssh/réseau en code d'erreur compréhensible (sans jamais exposer de secret)."""
    detail = f"{type(exc).__name__}: {str(exc)[:200]}"
    if isinstance(exc, asyncssh.HostKeyNotVerifiable):
        return BackupError("SSH_HOSTKEY_CHANGED", detail)
    if isinstance(exc, asyncssh.PermissionDenied):
        return BackupError("SSH_AUTH_FAILED", detail)
    if isinstance(exc, asyncssh.KeyExchangeFailed) or "no matching" in str(exc).lower():
        return BackupError("SSH_ALGO_MISMATCH", detail)
    if isinstance(exc, ConnectionRefusedError):
        return BackupError("SSH_REFUSED", detail)
    if isinstance(exc, TimeoutError | OSError):
        return BackupError("SSH_UNREACHABLE", detail)
    return BackupError("SSH_ERROR", detail)


async def fetch_host_key(host: str, port: int, legacy: bool = False) -> tuple[str, str, str]:
    """Récupère la clé d'hôte SANS s'authentifier (aucun identifiant n'est envoyé). -> (clé OpenSSH, empreinte, algo)."""
    try:
        options = asyncssh.SSHClientConnectionOptions(config=[], **(LEGACY if legacy else {}))
        key = await asyncio.wait_for(asyncssh.get_server_host_key(host, port, options=options), CONNECT_TIMEOUT + 5)
    except Exception as exc:  # noqa: BLE001
        raise _classify(exc) from None
    if key is None:
        raise BackupError("SSH_ERROR", "aucune clé d'hôte reçue")
    return key.export_public_key("openssh").decode().strip(), fingerprint(key), key.algorithm.decode()


class CliSession:
    """Session CLI interactive (PTY) : détecte l'invite, désactive la pagination, lance des commandes d'AFFICHAGE fixes."""

    def __init__(self, conn: asyncssh.SSHClientConnection, profile: cli.CliProfile) -> None:
        self.conn, self.profile = conn, profile
        self.proc: Any = None
        self.prompt = ""
        self.buf = ""

    async def _read(self, wait_s: float) -> str:
        data = await asyncio.wait_for(self.proc.stdout.read(65536), wait_s)
        if not data:
            raise BackupError("SSH_ERROR", "connexion fermée par l'équipement")
        return str(data) if isinstance(data, str) else data.decode("utf-8", errors="replace")

    async def open(self) -> str:
        self.proc = await self.conn.create_process(term_type="vt100", term_size=(250, 50), encoding=None)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + PROMPT_TIMEOUT
        buf = ""
        while True:
            left = deadline - loop.time()
            if left <= 0:
                raise BackupError("CLI_PROMPT_TIMEOUT", f"dernières lignes reçues : {buf[-200:]!r}")
            try:
                buf += cli.clean(await self._read(left))
            except TimeoutError:
                raise BackupError("CLI_PROMPT_TIMEOUT", f"dernières lignes reçues : {buf[-200:]!r}") from None
            last = buf.rstrip("\n").split("\n")[-1].strip() if buf.strip() else ""
            if last and self.profile.prompt.match(last):
                self.prompt = last
                return last

    async def run(self, command: str, wait_s: float | None = None) -> str:
        self.proc.stdin.write((command + "\n").encode())
        loop = asyncio.get_running_loop()
        deadline = loop.time() + (wait_s if wait_s is not None else COMMAND_TIMEOUT)
        raw = ""
        while True:
            left = deadline - loop.time()
            if left <= 0:
                raise BackupError("CLI_TIMEOUT", f"commande « {command} » sans réponse complète")
            try:
                chunk = await self._read(left)
            except TimeoutError:
                raise BackupError("CLI_TIMEOUT", f"commande « {command} » sans réponse complète") from None
            raw += chunk
            if len(raw) > MAX_BYTES * 2:
                raise BackupError("BACKUP_TOO_LARGE", f"plus de {MAX_BYTES * 2} octets reçus")
            if cli.MORE.search(raw[-200:]):  # pagination résiduelle : on demande la page suivante
                self.proc.stdin.write(b" ")
                raw = cli.MORE.sub("", raw)
                continue
            text = cli.clean(raw)
            lines = text.split("\n")
            if len(lines) > 1 and lines[-1].strip() == self.prompt.strip():
                body = lines[:-1]
                if body and command.strip() in body[0]:  # écho de la commande
                    body = body[1:]
                return "\n".join(body).strip("\n")


@dataclass
class Fetched:
    kind: str
    text: str
    command: str


# ----------------------------------------------------------------------------------------------- journal humain


class RunLog:
    """Journal d'une sauvegarde : chaque ligne est écrite et validée tout de suite (visible même si le worker s'arrête)."""

    def __init__(self, db: AsyncSession, run: BackupRun) -> None:
        self.db, self.run = db, run

    async def add(self, level: str, message: str, advice: str | None = None, detail: str | None = None) -> None:
        self.db.add(BackupEvent(run_id=self.run.id, level=level, message=message, advice=advice, detail=detail))
        await self.db.commit()

    async def info(self, m: str) -> None:
        await self.add("info", m)

    async def ok(self, m: str) -> None:
        await self.add("ok", m)

    async def warn(self, m: str, advice: str | None = None) -> None:
        await self.add("warn", m, advice)

    async def fail(self, code: str, context: str = "", detail: str = "") -> None:
        what, advice = human(code)
        await self.add("error", (context + " " if context else "") + what, advice, detail or None)


# ----------------------------------------------------------------------------------------------- orchestration


async def _connect(dev: Device, cred: SshCredentialRow, secrets: dict[str, str]) -> asyncssh.SSHClientConnection:
    try:
        host_key = asyncssh.import_public_key(dev.ssh_host_key)  # type: ignore[arg-type]
    except (asyncssh.KeyImportError, TypeError, ValueError):
        raise BackupError("SSH_HOSTKEY_UNKNOWN", "clé épinglée illisible") from None
    opts: dict[str, Any] = {
        "host": str(dev.mgmt_ip),
        "port": dev.ssh_port,
        "username": cred.username,
        "known_hosts": ([host_key], [], []),
        "config": [],
        "agent_path": None,
        "connect_timeout": CONNECT_TIMEOUT,
        "login_timeout": LOGIN_TIMEOUT,
        "keepalive_interval": 15,
        "client_host_keys": None,
    }
    if cred.auth_type == "password":
        opts.update(password=secrets["password"], preferred_auth="password,keyboard-interactive", client_keys=None)
    else:
        try:
            key = asyncssh.import_private_key(secrets["private_key"], secrets.get("passphrase") or None)
        except (asyncssh.KeyImportError, asyncssh.KeyEncryptionError):
            raise BackupError("SSH_AUTH_FAILED", "clé privée du profil illisible ou passphrase incorrecte") from None
        opts.update(client_keys=[key], preferred_auth="publickey", password=None)
    if dev.ssh_allow_legacy:
        opts.update(LEGACY)
    try:
        return await asyncio.wait_for(asyncssh.connect(**opts), CONNECT_TIMEOUT + LOGIN_TIMEOUT + 5)
    except BackupError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _classify(exc) from None


async def _fetch_configs(
    conn: asyncssh.SSHClientConnection, profile: cli.CliProfile, rl: RunLog, dev: Device
) -> dict[str, Fetched | BackupError]:
    sess = CliSession(conn, profile)
    prompt = await sess.open()
    await rl.ok(f"Connecté : l'équipement affiche l'invite « {prompt} ».")
    if profile.needs_privilege(prompt):
        raise BackupError("SSH_PRIVILEGE_REQUIRED", f"invite reçue : {prompt!r}")
    for cmd in profile.pager_off:
        try:
            await sess.run(cmd, wait_s=15)
        except BackupError:
            continue  # commande de pagination non supportée par ce firmware : sans conséquence
    await rl.info("Pagination désactivée : la configuration sera reçue d'un seul bloc.")
    out: dict[str, Fetched | BackupError] = {}
    for kind, candidates in (("running", profile.running), ("startup", profile.startup)):
        await rl.info(f"Récupération de la {KIND_LABEL[kind]}…")
        last_detail = ""
        try:
            for cmd in candidates:
                text = await sess.run(cmd)
                if cli.looks_like_error(text):
                    last_detail = f"commande « {cmd} » → {text.strip()[:200]!r}"
                    continue
                if len(text.strip()) < MIN_CONFIG_BYTES:
                    raise BackupError("CLI_OUTPUT_EMPTY", f"commande « {cmd} » → {text.strip()[:200]!r}")
                if len(text.encode()) > MAX_BYTES:
                    raise BackupError("BACKUP_TOO_LARGE", f"{len(text.encode())} octets")
                out[kind] = Fetched(kind, text, cmd)
                break
            else:
                raise BackupError("CLI_COMMAND_REJECTED", last_detail)
        except BackupError as exc:
            if exc.code in ("CLI_TIMEOUT", "SSH_ERROR"):
                raise
            out[kind] = exc
    return out


async def _store(db: AsyncSession, keyring: KeyRing, dev: Device, run: BackupRun, f: Fetched, rl: RunLog) -> str:
    """Enregistre une version (ou constate qu'elle est identique). Retourne 'success' | 'unchanged'."""
    sha = hashlib.sha256(f.text.encode()).hexdigest()
    size = len(f.text.encode())
    last = (
        await db.execute(
            select(ConfigBackup)
            .where(ConfigBackup.device_id == dev.id, ConfigBackup.kind == f.kind)
            .order_by(ConfigBackup.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    label = KIND_LABEL[f.kind]
    if last is not None and last.sha256 == sha:
        db.add(
            ConfigBackup(
                device_id=dev.id,
                run_id=run.id,
                kind=f.kind,
                status="unchanged",
                sha256=sha,
                size_bytes=size,
                same_as_id=last.same_as_id or last.id,
            )
        )
        await db.commit()
        await rl.ok(
            f"La {label} ({fmt_size(size)}) est identique à celle du {last.created_at:%d/%m/%Y à %H:%M} : "
            "aucune nouvelle version enregistrée."
        )
        return "unchanged"
    bid = uuid.uuid4()
    db.add(
        ConfigBackup(
            id=bid,
            device_id=dev.id,
            run_id=run.id,
            kind=f.kind,
            status="success",
            sha256=sha,
            size_bytes=size,
            content_blob=seal_config(keyring, bid, f.text),
            key_id=keyring.active_kid,
        )
    )
    await db.commit()
    if last is None:
        await rl.ok(
            f"La {label} a été enregistrée ({fmt_size(size)}, {f.text.count(chr(10)) + 1} lignes) : première sauvegarde de cet équipement."
        )
    else:
        owner = last if last.status == "success" else await db.get(ConfigBackup, last.same_as_id)
        a = r = 0
        if owner is not None and owner.content_blob is not None:
            try:
                a, r = cli.diff_stats(unseal_config(keyring, owner), f.text)
            except CryptoError:
                pass
        await rl.ok(
            f"La {label} a changé depuis la sauvegarde du {last.created_at:%d/%m/%Y à %H:%M} "
            f"({a} ligne(s) ajoutée(s), {r} supprimée(s)). Nouvelle version enregistrée ({fmt_size(size)})."
        )
    return "success"


async def run_backup(db: AsyncSession, keyring: KeyRing, params: dict[str, Any]) -> dict[str, Any]:
    dev = (await db.execute(select(Device).where(Device.id == uuid.UUID(params["device_id"])))).scalar_one()
    run = BackupRun(
        device_id=dev.id,
        device_name=dev.name,
        trigger=params.get("trigger", "manual"),
        requested_by=params.get("requested_by"),
        results={},
    )
    db.add(run)
    await db.commit()
    rl = RunLog(db, run)
    who = f", demandée par {run.requested_by}" if run.requested_by else " (planifiée)"
    await rl.info(f"Début de la sauvegarde de « {dev.name} » ({dev.mgmt_ip}, port SSH {dev.ssh_port}){who}.")
    results: dict[str, str] = {}
    code: str | None = None
    try:
        code = await _execute(db, keyring, dev, run, rl, results)
    except Exception as exc:  # noqa: BLE001 - jamais de secret dans les traces
        log.exception("backup_internal_error", extra={"run_id": str(run.id)})
        await rl.fail("INTERNAL_ERROR", detail=f"{type(exc).__name__}")
        code = "INTERNAL_ERROR"
    ok_kinds = [k for k, v in results.items() if v in ("success", "unchanged")]
    status = "failed" if not ok_kinds else ("success" if len(ok_kinds) == 2 and not code else "partial")
    if status == "partial" and code is None:
        code = next((v.split(":", 1)[1] for v in results.values() if v.startswith("failed:")), None)
    run.status, run.error_code, run.results, run.finished_at = (
        status,
        code if status != "success" else None,
        results,
        datetime.now(UTC),
    )
    changed = [k for k, v in results.items() if v == "success"]
    if status == "success":
        run.summary = (
            "Sauvegarde réussie : "
            + (
                "nouvelle version de " + " et ".join(changed)
                if changed
                else "aucun changement depuis la dernière sauvegarde"
            )
            + "."
        )
    elif status == "partial":
        run.summary = f"Sauvegarde incomplète : {human(code or 'INTERNAL_ERROR')[0]}"
    else:
        run.summary = f"Sauvegarde échouée : {human(code or 'INTERNAL_ERROR')[0]}"
    await db.execute(
        update(Device).where(Device.id == dev.id).values(last_backup_at=datetime.now(UTC), last_backup_status=status)
    )
    await db.commit()
    await rl.add("ok" if status == "success" else ("warn" if status == "partial" else "error"), run.summary)
    return {
        "run_id": str(run.id),
        "status": status,
        "error_code": code if status == "failed" else None,
        "results": results,
    }


async def _execute(
    db: AsyncSession, keyring: KeyRing, dev: Device, run: BackupRun, rl: RunLog, results: dict[str, str]
) -> str | None:
    cfg = await all_values(db)
    profile = cli.PROFILES.get(get_driver(dev.driver).name)
    if profile is None:
        await rl.fail("UNSUPPORTED_DRIVER")
        return "UNSUPPORTED_DRIVER"
    if dev.ssh_credential_id is None:
        await rl.fail("NO_SSH_PROFILE")
        return "NO_SSH_PROFILE"
    try:
        check_address(str(dev.mgmt_ip), cfg["snmp_allowed_cidrs"])
    except TargetNotAllowed:
        await rl.fail("TARGET_NOT_ALLOWED")
        return "TARGET_NOT_ALLOWED"
    if not dev.ssh_host_key:
        await rl.fail("SSH_HOSTKEY_UNKNOWN")
        return "SSH_HOSTKEY_UNKNOWN"
    cred = (await db.execute(select(SshCredentialRow).where(SshCredentialRow.id == dev.ssh_credential_id))).scalar_one()
    secrets = unseal_secret(keyring, cred)
    await rl.info(
        f"Connexion SSH à {dev.mgmt_ip}:{dev.ssh_port} avec le profil « {cred.name} » (utilisateur {cred.username})."
    )
    conn: asyncssh.SSHClientConnection | None = None
    try:
        conn = await _connect(dev, cred, secrets)
        await rl.ok(
            "Connexion SSH établie : l'empreinte de l'équipement correspond à celle approuvée, authentification réussie."
        )
        fetched = await _fetch_configs(conn, profile, rl, dev)
    except BackupError as exc:
        await rl.fail(exc.code, detail=exc.detail)
        return exc.code
    finally:
        if conn is not None:
            conn.close()
    first_code: str | None = None
    for kind in ("running", "startup"):
        item = fetched.get(kind)
        if isinstance(item, BackupError):
            await rl.fail(item.code, context=f"{kind} :", detail=item.detail)
            results[kind] = f"failed:{item.code}"
            first_code = first_code or item.code
        elif item is not None:
            results[kind] = await _store(db, keyring, dev, run, item, rl)
    r, s = fetched.get("running"), fetched.get("startup")
    if isinstance(r, Fetched) and isinstance(s, Fetched):
        if cli.normalize(r.text, profile) != cli.normalize(s.text, profile):
            await rl.warn(
                "La configuration en cours (running) est DIFFÉRENTE de la configuration de démarrage (startup) : des modifications "
                "n'ont pas été enregistrées sur l'équipement et seraient perdues au prochain redémarrage.",
                "Si ces modifications sont voulues, enregistrez-les sur l'équipement (Cisco : write memory ; Comware : save ; Aruba : write memory).",
            )
        else:
            await rl.ok(
                "La configuration en cours et celle de démarrage sont identiques : rien ne serait perdu à un redémarrage."
            )
    return first_code
