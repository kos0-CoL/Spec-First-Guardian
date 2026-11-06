#!/usr/bin/env python3
"""Almacen durable de la autoridad, con SQLite como backend inicial.

Contrato
--------
``AuthorityStore`` desacopla a la autoridad de SQLite. ``SQLiteAuthorityStore``
es la implementacion aprobada: usa WAL y ``synchronous=FULL``, y confirma en
una sola transaccion el cambio de estado de la solicitud, la emision del grant
y el evento de auditoria correspondiente. Ninguna capa superior importa
``sqlite3``.

Limite explicito
----------------
SQLite hace atomico el estado de la autoridad y su auditoria, pero no puede
hacer atomica una escritura del sistema de archivos. El gate registra intencion
y resultado en transacciones separadas; si la operacion fisica se ejecuta y su
resultado no puede registrarse, el resultado es INDETERMINATE y la autoridad
bloquea nuevas operaciones hasta reconciliar.

Evidencia historica
-------------------
La migracion lee los archivos JSON/JSONL anteriores y los deja intactos. El
resultado queda registrado en ``meta`` y como evento de auditoria, y puede
verificarse de nuevo sin reimportar nada.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sqlite3
import stat
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

import approval_service
import audit_chain
from audit_chain import GENESIS, AuditError

SCHEMA_VERSION = 1
LEGACY_MIGRATION_KEY = "legacy_migration"
HEALTH_STATES = (
    "HEALTHY",
    "AUDIT_INCOMPLETE",
    "AUDIT_CORRUPT",
    "AUDIT_UNAVAILABLE",
    "RECONCILIATION_REQUIRED",
)


class StoreError(RuntimeError):
    """El almacen no es utilizable o no puede confirmar la operacion."""


class StoreConflict(StoreError):
    """La transicion pretendida choca con el estado ya confirmado."""


class StoreNotFound(StoreConflict):
    """No existe el registro solicitado; no implica corrupcion."""


class MigrationError(StoreError):
    """La migracion no puede verificar o reconciliar la evidencia historica."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _parse_iso(value) -> datetime | None:
    if not value:
        return None
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=timezone.utc)


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _digest(value) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _decode(encoded: str, field: str) -> dict:
    try:
        value = json.loads(encoded)
    except (TypeError, ValueError) as error:
        raise StoreError(f"{field} ilegible") from error
    if not isinstance(value, dict):
        raise StoreError(f"{field} no es un objeto")
    return value


class AuthorityStore:
    """Contrato de persistencia de estado y auditoria.

    ``audit`` expone la misma superficie que ``audit_chain.AuditChain`` para que
    el gate pueda registrar intencion/resultado sin conocer el backend.
    """

    audit = None  # type: ignore[assignment]

    def save_request(self, request: dict, event: dict | None = None) -> None:
        raise NotImplementedError

    def get_request(self, request_id: str) -> dict:
        raise NotImplementedError

    def list_requests(self) -> list[dict]:
        raise NotImplementedError

    def get_grant(self, spec_id: str, version: str) -> tuple[dict, dict]:
        raise NotImplementedError

    def commit_approval(
        self,
        *,
        request_id: str,
        challenge_hash: str,
        record: dict,
        context: dict,
        audit_event: dict,
        replay: Iterable[tuple[str, str, str]] = (),
    ) -> int:
        raise NotImplementedError

    def events(self) -> list[dict]:
        raise NotImplementedError

    def verify_store(self) -> dict:
        raise NotImplementedError


class StoreAudit:
    """Sink de auditoria sobre el almacen; satisface el uso de ``AuditChain``."""

    def __init__(self, store: "SQLiteAuthorityStore") -> None:
        self.store = store

    def initialize(self) -> None:
        self.store.initialize_audit()

    def append(self, event: dict, *, allow_blocked: bool = False) -> dict:
        return self.store.append_event(event, allow_blocked=allow_blocked)

    def verify(self) -> tuple[bool, str, int]:
        return self.store.verify_chain()

    def is_blocked(self) -> bool:
        return self.store.audit_blocked()

    def health_state(self) -> str:
        return self.store.health_state()

    def block_reason(self) -> str:
        return self.store.block_reason()

    def mark_incomplete(self, reason: str, detail: dict | None = None) -> None:
        self.store.mark_incomplete(reason, detail)

    def clear_incomplete(self, operator: str, note: str) -> dict:
        return self.store.clear_incomplete(operator, note)


class SQLiteAuthorityStore(AuthorityStore):
    """Implementacion SQLite: WAL, sincronizacion completa y transacciones."""

    def __init__(self, path: Path | str, *, busy_timeout_ms: int = 5000) -> None:
        self.path = Path(path)
        self.busy_timeout_ms = int(busy_timeout_ms)
        self._lock = threading.RLock()
        self._poisoned = False
        self._prepare_file()
        self._initialize_schema()
        self.audit = StoreAudit(self)

    # -- archivo y conexion ----------------------------------------------
    def _prepare_file(self) -> None:
        parent = self.path.parent
        if not parent.is_absolute() or not self.path.is_absolute():
            raise StoreError("la ruta del almacen debe ser absoluta")
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            parent_info = os.lstat(parent)
        except OSError as error:
            raise StoreError("directorio del almacen inaccesible") from error
        if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
            raise StoreError("el directorio del almacen no es un directorio real")
        if parent_info.st_uid not in (0, os.getuid()):
            raise StoreError("propietario del directorio del almacen no autorizado")
        if stat.S_IMODE(parent_info.st_mode) & 0o077:
            raise StoreError("directorio del almacen accesible por grupo u otros")
        if os.path.lexists(self.path):
            info = os.lstat(self.path)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise StoreError("el almacen debe ser un archivo regular sin enlaces")
            if info.st_uid not in (0, os.getuid()):
                raise StoreError("propietario del almacen no autorizado")
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise StoreError("el almacen es accesible por grupo u otros")
        else:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
            os.close(descriptor)

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(
                str(self.path),
                timeout=self.busy_timeout_ms / 1000.0,
                isolation_level=None,
                check_same_thread=False,
            )
            connection.row_factory = sqlite3.Row
            connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
            mode = str(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]).lower()
            if mode != "wal":
                connection.close()
                raise StoreError(f"WAL no disponible (modo {mode})")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            return connection
        except sqlite3.Error as error:
            self._poisoned = True
            raise StoreError(f"almacen no disponible: {type(error).__name__}") from error

    @contextlib.contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                yield connection
                connection.execute("COMMIT")
            except BaseException:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    self._poisoned = True
                raise
            finally:
                connection.close()

    def _initialize_schema(self) -> None:
        statements = (
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT",
            "CREATE TABLE IF NOT EXISTS requests (request_id TEXT PRIMARY KEY, document TEXT NOT NULL,"
            " integrity TEXT NOT NULL, status TEXT NOT NULL, updated_at TEXT NOT NULL) STRICT",
            "CREATE TABLE IF NOT EXISTS grants (spec_id TEXT NOT NULL, version TEXT NOT NULL,"
            " document TEXT NOT NULL, context TEXT NOT NULL, authorization_event_id TEXT NOT NULL,"
            " created_at TEXT NOT NULL, PRIMARY KEY (spec_id, version)) STRICT",
            "CREATE TABLE IF NOT EXISTS audit_events (seq INTEGER PRIMARY KEY, at TEXT NOT NULL,"
            " prev TEXT NOT NULL, hash TEXT NOT NULL, event TEXT NOT NULL) STRICT",
            "CREATE TABLE IF NOT EXISTS replay (scope TEXT NOT NULL, identifier TEXT NOT NULL,"
            " expires_at TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (scope, identifier)) STRICT",
            "CREATE TABLE IF NOT EXISTS health (id INTEGER PRIMARY KEY CHECK (id = 1),"
            " state TEXT NOT NULL, reason TEXT NOT NULL, updated_at TEXT NOT NULL) STRICT",
        )
        try:
            with self._transaction() as connection:
                for statement in statements:
                    connection.execute(statement)
                row = connection.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
                if row is None:
                    connection.execute(
                        "INSERT INTO meta(key, value) VALUES('schema_version', ?)", (str(SCHEMA_VERSION),)
                    )
                elif int(row["value"]) != SCHEMA_VERSION:
                    raise StoreError("version de esquema no soportada")
                health = connection.execute("SELECT state FROM health WHERE id=1").fetchone()
                if health is None:
                    connection.execute(
                        "INSERT INTO health(id, state, reason, updated_at) VALUES(1, 'HEALTHY', '', ?)",
                        (_now_iso(),),
                    )
        except sqlite3.Error as error:
            self._poisoned = True
            raise StoreError("no se pudo inicializar el almacen") from error
        self._restrict_sidecars()

    def _restrict_sidecars(self) -> None:
        for suffix in ("-wal", "-shm"):
            candidate = self.path.with_name(self.path.name + suffix)
            try:
                if os.path.lexists(candidate):
                    os.chmod(candidate, 0o600)
            except OSError:
                raise StoreError("no se pudieron restringir los archivos auxiliares del almacen")

    def journal_mode(self) -> str:
        connection = self._connect()
        try:
            return str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()
        finally:
            connection.close()

    def synchronous_mode(self) -> str:
        connection = self._connect()
        try:
            value = str(connection.execute("PRAGMA synchronous").fetchone()[0]).lower()
        finally:
            connection.close()
        return {"0": "off", "1": "normal", "2": "full", "3": "extra"}.get(value, value)

    # -- auditoria --------------------------------------------------------
    def initialize_audit(self) -> None:
        with self._transaction() as connection:
            health = connection.execute("SELECT state FROM health WHERE id=1").fetchone()
            if health is None:
                connection.execute(
                    "INSERT INTO health(id, state, reason, updated_at) VALUES(1, 'HEALTHY', '', ?)",
                    (_now_iso(),),
                )

    def _health_row(self, connection: sqlite3.Connection) -> sqlite3.Row:
        row = connection.execute("SELECT state, reason FROM health WHERE id=1").fetchone()
        if row is None:
            raise StoreError("estado de salud ausente")
        return row

    def _set_health(self, connection: sqlite3.Connection, state: str, reason: str = "") -> None:
        if state not in HEALTH_STATES:
            raise StoreError("estado de salud desconocido")
        connection.execute(
            "UPDATE health SET state=?, reason=?, updated_at=? WHERE id=1",
            (state, reason, _now_iso()),
        )

    def _append_event(self, connection: sqlite3.Connection, event: dict, *, allow_blocked: bool) -> dict:
        if not isinstance(event, dict):
            raise AuditError("evento de auditoria invalido")
        health = self._health_row(connection)
        if health["state"] != "HEALTHY" and not allow_blocked:
            raise AuditError(f"auditoria bloqueada ({health['state']}) hasta reconciliacion")
        last = connection.execute("SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
        seq = int(last["seq"]) + 1 if last is not None else 1
        previous = str(last["hash"]) if last is not None else GENESIS
        at = _now_iso()
        record = {"seq": seq, "at": at, "prev": previous, "event": event}
        digest = hashlib.sha256(_canonical(record)).hexdigest()
        encoded = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        if len(encoded.encode("utf-8")) > audit_chain.MAX_EVENT_BYTES:
            raise AuditError("evento de auditoria demasiado grande")
        connection.execute(
            "INSERT INTO audit_events(seq, at, prev, hash, event) VALUES(?,?,?,?,?)",
            (seq, at, previous, digest, encoded),
        )
        return {**record, "hash": digest}

    def append_event(self, event: dict, *, allow_blocked: bool = False) -> dict:
        if self._poisoned:
            raise AuditError("almacen marcado no disponible")
        try:
            with self._transaction() as connection:
                return self._append_event(connection, event, allow_blocked=allow_blocked)
        except sqlite3.Error as error:
            self._poisoned = True
            raise AuditError("no se pudo persistir el evento de auditoria") from error

    def verify_chain(self) -> tuple[bool, str, int]:
        try:
            connection = self._connect()
        except StoreError as error:
            return False, str(error), 0
        try:
            rows = connection.execute("SELECT seq, at, prev, hash, event FROM audit_events ORDER BY seq").fetchall()
        except sqlite3.Error as error:
            return False, f"auditoria ilegible: {type(error).__name__}", 0
        finally:
            connection.close()
        expected_previous = GENESIS
        count = 0
        for row in rows:
            count += 1
            if int(row["seq"]) != count:
                return False, f"secuencia rota en el evento {count}", count - 1
            if str(row["prev"]) != expected_previous:
                return False, f"cadena rota en el evento {count}", count - 1
            try:
                event = json.loads(row["event"])
            except (TypeError, ValueError):
                return False, f"evento ilegible en la posicion {count}", count - 1
            record = {"seq": int(row["seq"]), "at": str(row["at"]), "prev": str(row["prev"]), "event": event}
            if hashlib.sha256(_canonical(record)).hexdigest() != str(row["hash"]):
                return False, f"hash alterado en el evento {count}", count - 1
            expected_previous = str(row["hash"])
        return True, "cadena integra", count

    def events(self) -> list[dict]:
        connection = self._connect()
        try:
            rows = connection.execute("SELECT seq, at, prev, hash, event FROM audit_events ORDER BY seq").fetchall()
        finally:
            connection.close()
        result = []
        for row in rows:
            result.append(
                {
                    "seq": int(row["seq"]),
                    "at": str(row["at"]),
                    "prev": str(row["prev"]),
                    "hash": str(row["hash"]),
                    "event": json.loads(row["event"]),
                }
            )
        return result

    def audit_blocked(self) -> bool:
        if self._poisoned:
            return True
        try:
            connection = self._connect()
        except StoreError:
            return True
        try:
            health = self._health_row(connection)
        except (StoreError, sqlite3.Error):
            return True
        finally:
            connection.close()
        if health["state"] != "HEALTHY":
            return True
        valid, _, _ = self.verify_chain()
        return not valid

    def health_state(self) -> str:
        if self._poisoned:
            return "AUDIT_UNAVAILABLE"
        try:
            connection = self._connect()
        except StoreError:
            return "AUDIT_UNAVAILABLE"
        try:
            health = self._health_row(connection)
        except (StoreError, sqlite3.Error):
            return "AUDIT_UNAVAILABLE"
        finally:
            connection.close()
        if health["state"] != "HEALTHY":
            return str(health["state"])
        valid, _, _ = self.verify_chain()
        return "HEALTHY" if valid else "AUDIT_CORRUPT"

    def block_reason(self) -> str:
        try:
            connection = self._connect()
        except StoreError as error:
            return str(error)
        try:
            health = self._health_row(connection)
            return str(health["reason"] or health["state"] or "AUDIT_UNAVAILABLE")
        except (StoreError, sqlite3.Error):
            return "AUDIT_UNAVAILABLE"
        finally:
            connection.close()

    def mark_incomplete(self, reason: str, detail: dict | None = None) -> None:
        try:
            with self._transaction() as connection:
                self._set_health(connection, "AUDIT_INCOMPLETE", str(reason or "AUDIT_INCOMPLETE"))
                payload = {"at": _now_iso(), "reason": str(reason), "detail": dict(detail or {})}
                self._append_event(connection, {"stage": "audit_incomplete", **payload}, allow_blocked=True)
        except (sqlite3.Error, StoreError, AuditError) as error:
            self._poisoned = True
            raise AuditError("no se pudo persistir el bloqueo de auditoria") from error

    def clear_incomplete(self, operator: str, note: str) -> dict:
        valid, reason, _ = self.verify_chain()
        if not valid:
            raise AuditError(f"no se puede reconciliar una cadena invalida: {reason}")
        try:
            with self._transaction() as connection:
                health = self._health_row(connection)
                if health["state"] == "HEALTHY":
                    raise AuditError("no hay auditoria incompleta")
                record = self._append_event(
                    connection,
                    {
                        "stage": "reconciled",
                        "operator": str(operator or ""),
                        "note": str(note or ""),
                        "previous_block": str(health["reason"] or health["state"]),
                    },
                    allow_blocked=True,
                )
                self._set_health(connection, "HEALTHY", "")
                return record
        except sqlite3.Error as error:
            self._poisoned = True
            raise AuditError("no se pudo persistir la reconciliacion") from error

    # -- solicitudes y grants --------------------------------------------
    def save_request(self, request: dict, event: dict | None = None) -> None:
        if not isinstance(request, dict) or not str(request.get("request_id") or ""):
            raise DeniedRequest("solicitud invalida")
        request_id = str(request["request_id"])
        document = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        integrity = _digest(request)
        status = str(request.get("status") or "PENDING_USER_APPROVAL")
        try:
            with self._transaction() as connection:
                connection.execute(
                    "INSERT INTO requests(request_id, document, integrity, status, updated_at)"
                    " VALUES(?,?,?,?,?) ON CONFLICT(request_id) DO UPDATE SET"
                    " document=excluded.document, integrity=excluded.integrity,"
                    " status=excluded.status, updated_at=excluded.updated_at",
                    (request_id, document, integrity, status, _now_iso()),
                )
                if event is not None:
                    self._append_event(connection, event, allow_blocked=False)
        except sqlite3.Error as error:
            self._poisoned = True
            raise StoreError("no se pudo persistir la solicitud") from error

    def get_request(self, request_id: str) -> dict:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT document, integrity FROM requests WHERE request_id=?", (str(request_id),)
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise StoreNotFound("solicitud desconocida o ilegible")
        request = _decode(row["document"], "solicitud")
        if _digest(request) != str(row["integrity"]):
            raise StoreConflict("la solicitud fue alterada despues de registrarse")
        return request

    def list_requests(self) -> list[dict]:
        connection = self._connect()
        try:
            rows = connection.execute("SELECT request_id, document, integrity FROM requests ORDER BY request_id").fetchall()
        finally:
            connection.close()
        result = []
        for row in rows:
            try:
                request = _decode(row["document"], "solicitud")
            except StoreError:
                result.append({"request_id": row["request_id"], "status": "CORRUPT"})
                continue
            if _digest(request) != str(row["integrity"]):
                result.append({"request_id": row["request_id"], "status": "CORRUPT"})
                continue
            result.append(request)
        return result

    def get_grant(self, spec_id: str, version: str) -> tuple[dict, dict]:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT document, context, authorization_event_id FROM grants WHERE spec_id=? AND version=?",
                (str(spec_id), str(version)),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise StoreNotFound("no hay autorizacion registrada para esa SPEC")
        approval = _decode(row["document"], "autorizacion")
        context = _decode(row["context"], "contexto de autorizacion")
        if str(approval.get("authorization_event_id") or "") != str(row["authorization_event_id"]):
            raise StoreConflict("autorizacion corrupta")
        return approval, context

    def commit_approval(
        self,
        *,
        request_id: str,
        challenge_hash: str,
        record: dict,
        context: dict,
        audit_event: dict,
        replay: Iterable[tuple[str, str, str]] = (),
    ) -> int:
        """Confirma estado, grant, replay y auditoria en una sola transaccion."""
        document = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        context_document = json.dumps(context, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        event_id = str(record.get("authorization_event_id") or "")
        if not event_id:
            raise StoreConflict("autorizacion sin identificador de evento")
        try:
            with self._transaction() as connection:
                row = connection.execute(
                    "SELECT document, integrity FROM requests WHERE request_id=?", (str(request_id),)
                ).fetchone()
                if row is None:
                    raise StoreConflict("solicitud desconocida")
                request = _decode(row["document"], "solicitud")
                if _digest(request) != str(row["integrity"]):
                    raise StoreConflict("la solicitud fue alterada despues de registrarse")
                if request.get("challenge_used") or request.get("status") == "APPROVED":
                    raise StoreConflict("desafio de aprobacion ya utilizado")
                if str(request.get("challenge_hash") or "") != str(challenge_hash):
                    raise StoreConflict("desafio de aprobacion invalido")
                challenge_expiry = _parse_iso(request.get("challenge_expires_at"))
                if challenge_expiry is None or datetime.now(timezone.utc) > challenge_expiry:
                    raise StoreConflict("desafio de aprobacion caducado")
                if str(record.get("fingerprint") or "") != str(request.get("fingerprint") or ""):
                    raise StoreConflict("la autorizacion no corresponde a la SPEC de la solicitud")
                if (str(record.get("spec_id") or ""), str(record.get("version") or "")) != (
                    str(request.get("spec_id") or ""), str(request.get("version") or "")
                ):
                    raise StoreConflict("la autorizacion no corresponde a la version solicitada")
                for scope, identifier, expires_at in replay:
                    try:
                        connection.execute(
                            "INSERT INTO replay(scope, identifier, expires_at, created_at) VALUES(?,?,?,?)",
                            (str(scope), str(identifier), str(expires_at), _now_iso()),
                        )
                    except sqlite3.IntegrityError as error:
                        raise StoreConflict("identificador de autenticacion ya utilizado") from error
                existing = connection.execute(
                    "SELECT authorization_event_id FROM grants WHERE spec_id=? AND version=?",
                    (str(record.get("spec_id")), str(record.get("version"))),
                ).fetchone()
                if existing is not None:
                    if str(existing["authorization_event_id"]) != event_id:
                        raise StoreConflict("ya existe una autorizacion distinta para esa SPEC")
                else:
                    connection.execute(
                        "INSERT INTO grants(spec_id, version, document, context, authorization_event_id, created_at)"
                        " VALUES(?,?,?,?,?,?)",
                        (
                            str(record.get("spec_id")),
                            str(record.get("version")),
                            document,
                            context_document,
                            event_id,
                            _now_iso(),
                        ),
                    )
                request["challenge_used"] = True
                request["status"] = "APPROVED"
                request["authorization_event_id"] = event_id
                encoded = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
                connection.execute(
                    "UPDATE requests SET document=?, integrity=?, status=?, updated_at=? WHERE request_id=?",
                    (encoded, _digest(request), "APPROVED", _now_iso(), str(request_id)),
                )
                audit = self._append_event(connection, audit_event, allow_blocked=False)
                return int(audit["seq"])
        except sqlite3.Error as error:
            self._poisoned = True
            raise StoreError("no se pudo confirmar la aprobacion") from error

    def verify_store(self) -> dict:
        valid, reason, count = self.verify_chain()
        result = {
            "valid": valid,
            "reason": reason,
            "events": count,
            "journal_mode": self.journal_mode(),
            "synchronous": self.synchronous_mode(),
            "health": self.health_state(),
            "path": str(self.path),
        }
        connection = self._connect()
        try:
            migration = connection.execute("SELECT value FROM meta WHERE key=?", (LEGACY_MIGRATION_KEY,)).fetchone()
            grants = connection.execute("SELECT COUNT(*) FROM grants").fetchone()[0]
            requests = connection.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
        finally:
            connection.close()
        result["grants"] = int(grants)
        result["requests"] = int(requests)
        result["migration"] = json.loads(migration["value"]) if migration is not None else None
        return result

    # -- migracion historica ---------------------------------------------
    def migrate_legacy(
        self,
        *,
        requests_dir: Path | str | None = None,
        approvals_dir: Path | str | None = None,
        audit_log: Path | str | None = None,
        key_store=None,
    ) -> dict:
        """Importa evidencia anterior verificada, sin modificar los originales.

        Idempotente: con las mismas fuentes no reimporta. Si encuentra
        conflictos, corrupcion o una cadena que no puede empalmarse, aborta sin
        modificar el almacen.
        """
        sources = {
            "requests": Path(requests_dir) if requests_dir is not None else None,
            "approvals": Path(approvals_dir) if approvals_dir is not None else None,
            "audit": Path(audit_log) if audit_log is not None else None,
        }
        digests = {name: self._source_digest(path) for name, path in sources.items()}
        if all(value is None for value in digests.values()):
            return self._empty_migration()
        existing = self._migration_record()
        if existing is not None and existing.get("source_digests") == digests and existing.get("status") == "completed":
            valid, reason, count = self.verify_chain()
            if not valid:
                raise MigrationError(f"la migracion registrada no verifica: {reason}")
            return {**existing, "already_migrated": True, "events": count}

        requests = self._read_legacy_requests(sources["requests"])
        grants = self._read_legacy_grants(sources["approvals"], key_store)
        legacy_events = self._read_legacy_events(sources["audit"])
        report = {
            "status": "completed",
            "migrated_at": _now_iso(),
            "source_digests": digests,
            "requests": len(requests),
            "grants": len(grants),
            "legacy_events": len(legacy_events),
            "imported_events": 0,
            "skipped_events": 0,
        }
        try:
            with self._transaction() as connection:
                for request in requests:
                    self._import_request(connection, request)
                for approval, context in grants:
                    self._import_grant(connection, approval, context)
                report["imported_events"], report["skipped_events"] = self._import_events(connection, legacy_events)
                connection.execute(
                    "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (LEGACY_MIGRATION_KEY, json.dumps(report, sort_keys=True, ensure_ascii=True)),
                )
                self._append_event(
                    connection,
                    {
                        "stage": "storage_migration",
                        "migrated_at": report["migrated_at"],
                        "requests": report["requests"],
                        "grants": report["grants"],
                        "legacy_events": report["legacy_events"],
                        "imported_events": report["imported_events"],
                        "skipped_events": report["skipped_events"],
                        "source_digests": digests,
                    },
                    allow_blocked=True,
                )
        except sqlite3.Error as error:
            self._poisoned = True
            raise MigrationError("no se pudo completar la migracion") from error
        return report

    @staticmethod
    def _source_digest(path: Path | None) -> str | None:
        if path is None or not os.path.lexists(path):
            return None
        if path.is_dir():
            parts = []
            for entry in sorted(path.glob("*")):
                if entry.is_file() and not entry.is_symlink():
                    parts.append({"name": entry.name, "sha256": hashlib.sha256(entry.read_bytes()).hexdigest()})
            return _digest(parts)
        if path.is_file() and not path.is_symlink():
            return hashlib.sha256(path.read_bytes()).hexdigest()
        return None

    @staticmethod
    def _empty_migration() -> dict:
        return {
            "status": "nothing_to_migrate",
            "valid": True,
            "requests": 0,
            "grants": 0,
            "legacy_events": 0,
            "imported_events": 0,
            "skipped_events": 0,
            "source_digests": {"requests": None, "approvals": None, "audit": None},
        }

    def _migration_record(self) -> dict | None:
        connection = self._connect()
        try:
            row = connection.execute("SELECT value FROM meta WHERE key=?", (LEGACY_MIGRATION_KEY,)).fetchone()
        finally:
            connection.close()
        if row is None:
            return None
        try:
            value = json.loads(row["value"])
        except ValueError as error:
            raise MigrationError("registro de migracion ilegible") from error
        return value if isinstance(value, dict) else None

    @staticmethod
    def _read_legacy_requests(directory: Path | None) -> list[dict]:
        if directory is None or not directory.exists():
            return []
        if directory.is_symlink() or not directory.is_dir():
            raise MigrationError("directorio de solicitudes legacy no verificable")
        result = []
        for path in sorted(directory.glob("REQ-*.json")):
            if path.is_symlink() or not path.is_file():
                raise MigrationError(f"solicitud legacy no verificable: {path.name}")
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as error:
                raise MigrationError(f"solicitud legacy ilegible: {path.name}") from error
            if not isinstance(payload, dict) or not isinstance(payload.get("request"), dict):
                raise MigrationError(f"solicitud legacy corrupta: {path.name}")
            request = payload["request"]
            if str(request.get("request_id") or "") != path.stem:
                raise MigrationError(f"identificador de solicitud no coincide con el archivo: {path.name}")
            if str(payload.get("integrity") or "") != _digest(request):
                raise MigrationError(f"integridad de solicitud no verificable: {path.name}")
            for field in ("spec_id", "project", "version", "fingerprint", "scope"):
                if not str(request.get(field) or "").strip():
                    raise MigrationError(f"solicitud legacy incompleta: {path.name}")
            result.append(request)
        return result

    @staticmethod
    def _read_legacy_grants(directory: Path | None, key_store) -> list[tuple[dict, dict]]:
        if directory is None or not directory.exists():
            return []
        if directory.is_symlink() or not directory.is_dir():
            raise MigrationError("directorio de autorizaciones legacy no verificable")
        result = []
        for path in sorted(directory.glob("*.json")):
            if path.is_symlink() or not path.is_file():
                raise MigrationError(f"autorizacion legacy no verificable: {path.name}")
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as error:
                raise MigrationError(f"autorizacion legacy ilegible: {path.name}") from error
            if not isinstance(payload, dict) or not isinstance(payload.get("approval"), dict):
                raise MigrationError(f"autorizacion legacy corrupta: {path.name}")
            approval = payload["approval"]
            context = payload.get("context")
            if not isinstance(context, dict) or not str(context.get("project") or ""):
                raise MigrationError(f"contexto de autorizacion corrupto: {path.name}")
            if key_store is not None and getattr(key_store, "configured", False):
                if not approval_service.verify_approval(approval, key_store=key_store):
                    raise MigrationError(f"firma de autorizacion no verificable: {path.name}")
            if not str(approval.get("authorization_event_id") or ""):
                raise MigrationError(f"autorizacion sin evento: {path.name}")
            result.append((approval, {"spec_path": str(context.get("spec_path") or ""), "project": str(context.get("project"))}))
        return result

    @staticmethod
    def _read_legacy_events(path: Path | None) -> list[dict]:
        if path is None or not os.path.lexists(path):
            return []
        if path.is_symlink() or not path.is_file():
            raise MigrationError("audit log legacy no verificable")
        try:
            raw_lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as error:
            raise MigrationError("audit log legacy ilegible") from error
        events = []
        expected_previous = GENESIS
        for index, raw in enumerate(raw_lines, start=1):
            if not raw.strip():
                raise MigrationError(f"linea vacia en audit log legacy ({index})")
            try:
                record = json.loads(raw)
            except ValueError as error:
                raise MigrationError(f"evento legacy ilegible en linea {index}") from error
            if not isinstance(record, dict):
                raise MigrationError(f"evento legacy invalido en linea {index}")
            stored = str(record.get("hash") or "")
            unsigned = {key: value for key, value in record.items() if key != "hash"}
            if int(unsigned.get("seq") or -1) != index:
                raise MigrationError(f"secuencia legacy rota en linea {index}")
            if str(unsigned.get("prev") or "") != expected_previous:
                raise MigrationError(f"cadena legacy rota en linea {index}")
            if hashlib.sha256(_canonical(unsigned)).hexdigest() != stored:
                raise MigrationError(f"hash legacy alterado en linea {index}")
            if not isinstance(unsigned.get("event"), dict):
                raise MigrationError(f"evento legacy sin cuerpo en linea {index}")
            expected_previous = stored
            events.append(unsigned | {"hash": stored})
        return events

    def _import_request(self, connection: sqlite3.Connection, request: dict) -> None:
        document = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        integrity = _digest(request)
        status = str(request.get("status") or "PENDING_USER_APPROVAL")
        row = connection.execute(
            "SELECT integrity FROM requests WHERE request_id=?", (str(request["request_id"]),)
        ).fetchone()
        if row is not None:
            if str(row["integrity"]) != integrity:
                raise MigrationError(f"solicitud en conflicto: {request['request_id']}")
            return
        connection.execute(
            "INSERT INTO requests(request_id, document, integrity, status, updated_at) VALUES(?,?,?,?,?)",
            (str(request["request_id"]), document, integrity, status, _now_iso()),
        )

    def _import_grant(self, connection: sqlite3.Connection, approval: dict, context: dict) -> None:
        event_id = str(approval.get("authorization_event_id") or "")
        row = connection.execute(
            "SELECT authorization_event_id FROM grants WHERE spec_id=? AND version=?",
            (str(approval.get("spec_id")), str(approval.get("version"))),
        ).fetchone()
        if row is not None:
            if str(row["authorization_event_id"]) != event_id:
                raise MigrationError(
                    f"autorizacion en conflicto: {approval.get('spec_id')} {approval.get('version')}"
                )
            return
        connection.execute(
            "INSERT INTO grants(spec_id, version, document, context, authorization_event_id, created_at)"
            " VALUES(?,?,?,?,?,?)",
            (
                str(approval.get("spec_id")),
                str(approval.get("version")),
                json.dumps(approval, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
                json.dumps(context, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
                event_id,
                _now_iso(),
            ),
        )

    def _import_events(self, connection: sqlite3.Connection, events: list[dict]) -> tuple[int, int]:
        if not events:
            return 0, 0
        last = connection.execute("SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
        current_count = int(last["seq"]) if last is not None else 0
        current_hash = str(last["hash"]) if last is not None else GENESIS
        if current_count > 0:
            stored = {
                int(row["seq"]): str(row["hash"])
                for row in connection.execute("SELECT seq, hash FROM audit_events").fetchall()
            }
            for record in events[:current_count]:
                if stored.get(int(record["seq"])) != str(record.get("hash")):
                    raise MigrationError("la cadena legacy no coincide con la cadena almacenada")
            if stored.get(current_count) != current_hash:
                raise MigrationError("cadena almacenada inconsistente")
        imported = 0
        skipped = 0
        for record in events:
            seq = int(record["seq"])
            if seq <= current_count:
                skipped += 1
                continue
            if seq != current_count + 1 or str(record.get("prev")) != current_hash:
                raise MigrationError("la cadena legacy no puede empalmarse sin reescribir historia")
            try:
                event = record["event"]
            except KeyError as error:
                raise MigrationError("evento legacy sin cuerpo") from error
            connection.execute(
                "INSERT INTO audit_events(seq, at, prev, hash, event) VALUES(?,?,?,?,?)",
                (
                    seq,
                    str(record.get("at")),
                    current_hash,
                    str(record["hash"]),
                    json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
                ),
            )
            current_count = seq
            current_hash = str(record["hash"])
            imported += 1
        return imported, skipped


class DeniedRequest(StoreError):
    """La solicitud no tiene la forma minima exigida por el almacen."""
