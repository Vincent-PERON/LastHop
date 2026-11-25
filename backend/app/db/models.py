from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    ARRAY,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    FetchedValue,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, MACADDR, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Role(enum.StrEnum):
    viewer = "viewer"
    operator = "operator"
    admin = "admin"


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("issuer", "sub"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    issuer: Mapped[str] = mapped_column(String(255))
    sub: Mapped[str] = mapped_column(String(255))
    email: Mapped[str | None] = mapped_column(String(320))
    display_name: Mapped[str | None] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(Enum(Role, name="user_role"))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # Compte local (issuer = "local") uniquement : hash argon2id, verrouillage progressif, changement imposé
    password_hash: Mapped[str | None] = mapped_column(Text)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # TOTP optionnel (compte local) : secret chiffré AES-GCM, dernier pas accepté (anti-rejeu), codes de secours hachés
    totp_secret_blob: Mapped[bytes | None] = mapped_column(LargeBinary)
    totp_key_id: Mapped[str | None] = mapped_column(String(64))
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    totp_last_step: Mapped[int | None] = mapped_column(BigInteger)
    totp_recovery: Mapped[list[str]] = mapped_column(JSONB, default=list, server_default="[]")


LOCAL_ISSUER = "local"


class AuthProvider(Base):
    """Fournisseur d'identité configuré dans l'interface : OIDC (Keycloak, Entra ID, Google Workspace…) ou LDAP direct.
    Le secret (client_secret OIDC / mot de passe LDAP de service) est chiffré AES-GCM, lié à la ligne par l'AAD."""

    __tablename__ = "auth_providers"
    __table_args__ = (
        CheckConstraint("kind IN ('oidc','ldap')", name="ck_authprov_kind"),
        CheckConstraint(
            "default_role IS NULL OR default_role IN ('viewer','operator')", name="ck_authprov_default_role"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    kind: Mapped[str] = mapped_column(String(8))
    preset: Mapped[str] = mapped_column(String(16))
    name: Mapped[str] = mapped_column(String(100), unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    secret_blob: Mapped[bytes | None] = mapped_column(LargeBinary)
    key_id: Mapped[str | None] = mapped_column(String(64))
    role_map: Mapped[dict[str, str]] = mapped_column(JSONB, default=dict)
    default_role: Mapped[str | None] = mapped_column(String(16))
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ApiToken(Base):
    __tablename__ = "api_tokens"
    __table_args__ = (CheckConstraint("char_length(name) BETWEEN 1 AND 100"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    prefix: Mapped[str] = mapped_column(String(8), unique=True)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary(32))
    scopes: Mapped[list[str]] = mapped_column(ARRAY(String(32)))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    """Append-only. `id`, `prev_hash` et `row_hash` sont attribués par un trigger PostgreSQL (voir migration)."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False, server_default=FetchedValue())
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.clock_timestamp())
    actor_type: Mapped[str] = mapped_column(String(16))  # user | token | system | anonymous
    actor_id: Mapped[str | None] = mapped_column(String(64))
    actor_label: Mapped[str | None] = mapped_column(String(320))
    action: Mapped[str] = mapped_column(String(64), index=True)
    outcome: Mapped[str] = mapped_column(String(16), default="success")
    target_type: Mapped[str | None] = mapped_column(String(64))
    target_id: Mapped[str | None] = mapped_column(String(64))
    source_ip: Mapped[str | None] = mapped_column(INET)
    request_id: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    prev_hash: Mapped[bytes | None] = mapped_column(LargeBinary(32))
    row_hash: Mapped[bytes | None] = mapped_column(LargeBinary(32))


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[Any] = mapped_column(JSONB)
    updated_by: Mapped[str | None] = mapped_column(String(64))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Site(Base):
    __tablename__ = "sites"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SnmpCredentialRow(Base):
    """Profil d'identifiants SNMP. Les secrets ne vivent que dans `secret_blob` (AES-GCM) — jamais en clair."""

    __tablename__ = "snmp_credentials"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    version: Mapped[str] = mapped_column(String(8))  # v2c | v3
    v3_username: Mapped[str | None] = mapped_column(String(32))
    auth_proto: Mapped[str | None] = mapped_column(String(16))
    priv_proto: Mapped[str | None] = mapped_column(String(16))
    allow_legacy_algos: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    secret_blob: Mapped[bytes] = mapped_column(LargeBinary)
    key_id: Mapped[str] = mapped_column(String(64))
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    mgmt_ip: Mapped[str] = mapped_column(INET, unique=True)
    site_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    role: Mapped[str] = mapped_column(String(16))  # core | distribution | access
    driver: Mapped[str] = mapped_column(String(16), default="generic")
    vendor: Mapped[str | None] = mapped_column(String(64))
    model: Mapped[str | None] = mapped_column(String(64))
    sys_name: Mapped[str | None] = mapped_column(String(100))
    sys_descr: Mapped[str | None] = mapped_column(String(255))
    sys_object_id: Mapped[str | None] = mapped_column(String(128))
    is_l3: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    is_l2: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    credential_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("snmp_credentials.id", ondelete="RESTRICT"))
    snmp_port: Mapped[int] = mapped_column(Integer, default=161, server_default="161")
    timeout_ms: Mapped[int] = mapped_column(Integer, default=3000, server_default="3000")
    retries: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    max_repetitions: Mapped[int] = mapped_column(Integer, default=25, server_default="25")
    poll_interval_s: Mapped[int] = mapped_column(Integer, default=900, server_default="900")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    last_identified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_poll_status: Mapped[str | None] = mapped_column(String(32))
    snmp_context: Mapped[str] = mapped_column(String(32), default="", server_default="")
    last_learning_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_learning_status: Mapped[str | None] = mapped_column(String(32))
    chassis_mac: Mapped[str | None] = mapped_column(MACADDR)
    ssh_credential_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("ssh_credentials.id", ondelete="SET NULL"))
    ssh_port: Mapped[int] = mapped_column(Integer, default=22, server_default="22")
    ssh_allow_legacy: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    ssh_host_key: Mapped[str | None] = mapped_column(Text)  # clé publique OpenSSH épinglée (approuvée par un admin)
    backup_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    last_backup_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_backup_status: Mapped[str | None] = mapped_column(String(16))
    last_topology_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_topology_status: Mapped[str | None] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Job(Base):
    """Tâche asynchrone exécutée par le worker (test de connectivité, découverte ; temps réel au lot e)."""

    __tablename__ = "jobs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    kind: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    requested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    params: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)  # jamais de secret
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    error_code: Mapped[str | None] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DeviceVlan(Base):
    """VLAN connus d'un équipement : seuls ceux-ci peuvent être attribués à un de ses ports."""

    __tablename__ = "device_vlans"

    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True)
    vlan_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), default="", server_default="")


class Interface(Base):
    __tablename__ = "interfaces"
    __table_args__ = (UniqueConstraint("device_id", "if_index"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    if_index: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(64))
    descr: Mapped[str | None] = mapped_column(String(255))
    alias: Mapped[str | None] = mapped_column(String(255))
    if_type: Mapped[int | None] = mapped_column(Integer)
    bridge_port: Mapped[int | None] = mapped_column(Integer)
    oper_status: Mapped[int | None] = mapped_column(Integer)
    is_trunk: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    mac_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    pvid: Mapped[int | None] = mapped_column(Integer)  # VLAN non étiqueté du port (lu par SNMP)
    port_mode: Mapped[str | None] = mapped_column(String(8))  # access | trunk | hybrid
    tagged_vlans: Mapped[list[int]] = mapped_column(JSONB, default=list, server_default="[]")
    role_detected: Mapped[str] = mapped_column(String(8), default="access", server_default="access")
    role_reason: Mapped[str | None] = mapped_column(
        String(16)
    )  # lldp_neighbor | cdp_neighbor | trunk | mac_count | none
    role_override: Mapped[str | None] = mapped_column(String(8))  # access | uplink | NULL (auto)
    override_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    override_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    @property
    def role_effective(self) -> str:
        return self.role_override or self.role_detected


class Neighbor(Base):
    """Voisin annoncé (LLDP/CDP) sur un port local : observation brute, corrélée à l'inventaire."""

    __tablename__ = "neighbors"
    __table_args__ = (UniqueConstraint("device_id", "interface_id", "protocol", "remote_chassis_id", "remote_port_id"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    interface_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("interfaces.id", ondelete="CASCADE"))
    protocol: Mapped[str] = mapped_column(String(4))  # lldp | cdp
    remote_chassis_id: Mapped[str] = mapped_column(String(64))
    remote_port_id: Mapped[str] = mapped_column(String(128))
    remote_port_desc: Mapped[str | None] = mapped_column(String(255))
    remote_sysname: Mapped[str | None] = mapped_column(String(100))
    remote_sysdescr: Mapped[str | None] = mapped_column(String(255))
    remote_ip: Mapped[str | None] = mapped_column(INET)
    remote_is_network_device: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    matched_device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))
    matched_interface_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("interfaces.id", ondelete="SET NULL"))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ArpEntry(Base):
    """Table ARP courante d'un équipement L3 (remplacée à chaque collecte)."""

    __tablename__ = "arp_entries"

    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True)
    ip: Mapped[str] = mapped_column(INET, primary_key=True)
    mac: Mapped[str] = mapped_column(MACADDR, primary_key=True)
    vlan: Mapped[int | None] = mapped_column(Integer)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class FdbEntry(Base):
    """MAC apprises sur les ports NON uplink d'un équipement L2 (les entrées des uplinks ne sont pas conservées)."""

    __tablename__ = "fdb_entries"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    interface_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("interfaces.id", ondelete="CASCADE"))
    mac: Mapped[str] = mapped_column(MACADDR, index=True)
    vlan: Mapped[int | None] = mapped_column(Integer)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Endpoint(Base):
    """Un endpoint = (MAC, IP) localisé sur (équipement, port, VLAN). La MAC seule (ip NULL) si aucune entrée ARP."""

    __tablename__ = "endpoints"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    mac: Mapped[str] = mapped_column(MACADDR)
    ip: Mapped[str | None] = mapped_column(INET)
    vlan: Mapped[int | None] = mapped_column(Integer)
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))
    interface_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("interfaces.id", ondelete="SET NULL"))
    device_name: Mapped[str | None] = mapped_column(String(100))  # dénormalisés : survivent à la suppression
    port_name: Mapped[str | None] = mapped_column(String(64))
    hostname: Mapped[str | None] = mapped_column(String(253))
    hostname_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")


class EndpointHistory(Base):
    __tablename__ = "endpoint_history"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    endpoint_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("endpoints.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    change: Mapped[str] = mapped_column(String(16))  # appeared | moved | ip_changed | vlan_changed | disappeared
    old: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    new: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class OuiEntry(Base):
    __tablename__ = "oui"

    prefix: Mapped[str] = mapped_column(MACADDR, primary_key=True)  # trunc(mac) : 3 premiers octets
    vendor: Mapped[str] = mapped_column(String(255))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SshCredentialRow(Base):
    """Profil d'accès SSH (sauvegarde des configurations). Secret (mot de passe ou clé privée) chiffré AES-GCM."""

    __tablename__ = "ssh_credentials"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    username: Mapped[str] = mapped_column(String(64))
    auth_type: Mapped[str] = mapped_column(String(8))  # password | key
    secret_blob: Mapped[bytes] = mapped_column(LargeBinary)
    key_id: Mapped[str] = mapped_column(String(64))
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class BackupRun(Base):
    """Une opération de sauvegarde d'un équipement (running + startup) et son journal lisible (BackupEvent)."""

    __tablename__ = "backup_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"), index=True)
    device_name: Mapped[str] = mapped_column(String(100))
    trigger: Mapped[str] = mapped_column(String(10))  # manual | scheduled
    requested_by: Mapped[str | None] = mapped_column(String(320))
    status: Mapped[str] = mapped_column(String(10), default="running")  # running | success | partial | failed
    error_code: Mapped[str | None] = mapped_column(String(32))
    summary: Mapped[str | None] = mapped_column(Text)
    results: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class BackupEvent(Base):
    __tablename__ = "backup_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("backup_runs.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.clock_timestamp())
    level: Mapped[str] = mapped_column(String(8))  # info | ok | warn | error
    message: Mapped[str] = mapped_column(Text)  # phrase lisible par un humain
    advice: Mapped[str | None] = mapped_column(Text)  # « que faire »
    detail: Mapped[str | None] = mapped_column(Text)  # détail technique (administrateurs), nettoyé de tout secret


class ConfigBackup(Base):
    """Une version d'une configuration. Contenu compressé puis chiffré ; `unchanged` = identique à `same_as_id`."""

    __tablename__ = "config_backups"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("backup_runs.id", ondelete="SET NULL"))
    kind: Mapped[str] = mapped_column(String(8))  # running | startup
    status: Mapped[str] = mapped_column(String(10))  # success | unchanged
    content_blob: Mapped[bytes | None] = mapped_column(LargeBinary)
    key_id: Mapped[str | None] = mapped_column(String(64))
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    same_as_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("config_backups.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
