"""Transactional, per-instance identity allocation and retirement registry."""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import os
import sqlite3
import uuid


class IdentityRegistryError(RuntimeError):
    pass


@dataclass(frozen=True)
class RegisteredIdentity:
    instance_uuid: str
    hardware_identity_uuid: str
    machine_id: str
    hostname: str
    mac: str
    disk_serial: str


class IdentityRegistry:
    """Owner-only SQLite registry; deleted identities are permanently retired."""

    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(path.parent, 0o700)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS identities (
                    instance_uuid TEXT PRIMARY KEY,
                    hardware_identity_uuid TEXT NOT NULL UNIQUE,
                    machine_id TEXT NOT NULL UNIQUE,
                    hostname TEXT NOT NULL UNIQUE,
                    mac TEXT NOT NULL UNIQUE,
                    disk_serial TEXT NOT NULL UNIQUE,
                    retired_at TEXT,
                    created_at TEXT NOT NULL
                )
            """)

    def register(self, value: RegisteredIdentity) -> None:
        try:
            uuid.UUID(value.instance_uuid)
            uuid.UUID(value.hardware_identity_uuid)
        except ValueError as exc:
            raise IdentityRegistryError("identity registry received an invalid UUID") from exc
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO identities VALUES (?, ?, ?, ?, ?, ?, NULL, ?)",
                    (value.instance_uuid, value.hardware_identity_uuid, value.machine_id,
                     value.hostname, value.mac, value.disk_serial,
                     datetime.now(timezone.utc).isoformat()),
                )
                connection.execute("COMMIT")
        except sqlite3.IntegrityError as exc:
            raise IdentityRegistryError("identity was already issued or permanently retired") from exc

    def retire(self, instance_uuid: str) -> None:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            changed = connection.execute(
                "UPDATE identities SET retired_at=? WHERE instance_uuid=? AND retired_at IS NULL",
                (datetime.now(timezone.utc).isoformat(), instance_uuid),
            ).rowcount
            connection.execute("COMMIT")
        if not changed:
            raise IdentityRegistryError("active identity is unavailable for retirement")

    def is_registered(self, instance_uuid: str) -> bool:
        with closing(self._connect()) as connection:
            return connection.execute("SELECT 1 FROM identities WHERE instance_uuid=?", (instance_uuid,)).fetchone() is not None
