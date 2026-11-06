#!/usr/bin/env python3
"""Auditoria encadenada con registro de intencion y de resultado.

Cada evento incluye el hash del evento anterior, de modo que borrar, insertar o
alterar una linea rompe la cadena y es detectable. El registro se escribe antes
de ejecutar una operacion (intencion) y despues de ejecutarla (resultado).

Si el registro posterior falla, la operacion queda marcada como
``auditoria incompleta`` mediante un archivo de bloqueo: mientras exista, la
autoridad deniega nuevas operaciones hasta que un administrador reconcilie el
estado. No se devuelve nunca un resultado que afirme que la operacion quedo
registrada cuando falta el cierre.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64
MAX_EVENT_BYTES = 64 * 1024


class AuditError(RuntimeError):
    """El registro de auditoria no puede escribirse."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _canonical(record: dict) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


class AuditChain:
    """Registro append-only con cadena de hashes y bloqueo por auditoria incompleta."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.block_path = self.path.with_name(self.path.name + ".incomplete")
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self.init_path = self.path.with_name(self.path.name + ".initialized")
        self.health_path = self.path.with_name(self.path.name + ".health")
        self._poisoned = False

    def is_blocked(self) -> bool:
        if self._poisoned:
            return True
        if (os.path.lexists(self.init_path) or os.path.lexists(self.health_path)) and not os.path.lexists(self.path):
            return True
        try:
            os.lstat(self.block_path)
            return True
        except FileNotFoundError:
            try:
                health = json.loads(self.health_path.read_text(encoding="utf-8"))
                return health.get("state") != "HEALTHY"
            except FileNotFoundError:
                return os.path.lexists(self.init_path) or os.path.lexists(self.path) or os.path.lexists(self.health_path)
            except (OSError, ValueError, TypeError):
                return True
        except OSError:
            return True

    def block_reason(self) -> str:
        try:
            payload = json.loads(self.block_path.read_text(encoding="utf-8"))
            return str(payload.get("reason") or "AUDIT_INCOMPLETE")
        except (OSError, ValueError, TypeError):
            try:
                return self.health_path.read_text(encoding="utf-8").strip()
            except OSError:
                return "AUDIT_UNAVAILABLE"

    def _write_health(self, state: str) -> None:
        atomic_json_write(self.health_path, {"state": state, "updated_at": _now_iso()}, mode=0o600)

    def health_state(self) -> str:
        if self._poisoned:
            return "AUDIT_UNAVAILABLE"
        if self.is_blocked():
            try:
                payload = json.loads(self.block_path.read_text(encoding="utf-8"))
                return str(payload.get("reason") or "AUDIT_INCOMPLETE")
            except (OSError, ValueError, TypeError):
                try:
                    return str(json.loads(self.health_path.read_text(encoding="utf-8")).get("state") or "AUDIT_UNAVAILABLE")
                except (OSError, ValueError, TypeError):
                    return "AUDIT_UNAVAILABLE"
        valid, _, _ = self.verify()
        return "HEALTHY" if valid else "AUDIT_CORRUPT"

    def initialize(self) -> None:
        """Persist first-install evidence only if neither marker nor log exists."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(descriptor, "r+") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            if not os.path.lexists(self.path) and not os.path.lexists(self.init_path):
                audit_fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
                os.fsync(audit_fd)
                os.close(audit_fd)
                directory_fd = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
                atomic_json_write(self.init_path, {"initialized_at": _now_iso(), "nonce": secrets.token_hex(32)}, 0o600)
                self._write_health("HEALTHY")
            elif os.path.lexists(self.init_path) and not os.path.lexists(self.path):
                self._write_health("AUDIT_UNAVAILABLE")
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def mark_incomplete(self, reason: str, detail: dict | None = None) -> None:
        payload = {"at": _now_iso(), "reason": str(reason), "detail": detail or {}}
        self.block_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._write_health("AUDIT_INCOMPLETE")
            atomic_json_write(self.block_path, payload, mode=0o600)
            directory_fd = os.open(self.block_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError as error:
            self._poisoned = True
            try:
                self._write_health("AUDIT_UNAVAILABLE")
            except OSError:
                pass
            raise AuditError("no se pudo persistir el bloqueo de auditoria") from error

    def clear_incomplete(self, operator: str, note: str) -> dict:
        """Reconcilia el estado y deja constancia del cierre en la cadena."""
        valid, reason, _ = self.verify()
        if not valid and not (reason == "audit log ausente despues de inicializar" and os.path.lexists(self.block_path)):
            raise AuditError(f"no se puede reconciliar una cadena invalida: {reason}")
        previous = self.block_reason()
        event = self.append({"stage": "reconciled", "operator": str(operator or ""), "note": str(note or ""), "previous_block": previous}, allow_blocked=True)
        try:
            self.block_path.unlink()
            directory_fd = os.open(self.block_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            self._write_health("HEALTHY")
            self._poisoned = False
        except OSError as error:
            raise AuditError("evento de reconciliacion persistido pero no se pudo limpiar el bloqueo") from error
        return event

    def _last_hash(self) -> tuple[int, str]:
        valid, reason, count = self.verify()
        if reason == "audit log ausente despues de inicializar" and self.block_path.exists():
            return 0, GENESIS
        if not valid:
            if reason == "primera instalacion sin eventos":
                return 0, GENESIS
            raise AuditError(f"no se puede anexar: {reason}")
        if count == 0:
            return 0, GENESIS
        with self.path.open("rb") as handle:
            for raw in handle:
                last = raw
        try:
            record = json.loads(last)
        except (ValueError, UnboundLocalError) as error:
            raise AuditError("el audit log esta corrupto") from error
        return int(record["seq"]), str(record["hash"])

    def append(self, event: dict, *, allow_blocked: bool = False) -> dict:
        """Anade un evento y lo devuelve solo tras fsync confirmado."""
        if not isinstance(event, dict):
            raise AuditError("evento de auditoria invalido")
        if self.is_blocked() and not allow_blocked:
            raise AuditError("auditoria bloqueada hasta reconciliacion")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(self.lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
            lock = os.fdopen(descriptor, "r+")
        except OSError as error:
            self._poisoned = True
            raise AuditError(f"audit log no escribible: {error}") from error
        with lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                if self.is_blocked() and not allow_blocked:
                    raise AuditError("auditoria bloqueada hasta reconciliacion")
                seq, previous = self._last_hash()
                if seq == 0 and not os.path.lexists(self.init_path):
                    atomic_json_write(self.init_path, {"initialized_at": _now_iso(), "nonce": secrets.token_hex(32)}, 0o600)
                record = {"seq": seq + 1, "at": _now_iso(), "prev": previous, "event": event}
                record["hash"] = hashlib.sha256(_canonical(record)).hexdigest()
                encoded = (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")
                if len(encoded) > MAX_EVENT_BYTES:
                    raise AuditError("evento de auditoria demasiado grande")
                flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(self.path, flags, 0o600)
                created = os.fstat(descriptor).st_size == 0
                try:
                    remaining = memoryview(encoded)
                    while remaining:
                        written = os.write(descriptor, remaining)
                        if written <= 0:
                            raise AuditError("escritura parcial del audit log")
                        remaining = remaining[written:]
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                if created:
                    directory_fd = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
                self._write_health("HEALTHY")
                self._poisoned = False
                return record
            except (OSError, AuditError) as error:
                self._poisoned = True
                try:
                    self._write_health("AUDIT_UNAVAILABLE")
                except OSError:
                    pass
                if isinstance(error, AuditError):
                    raise
                raise AuditError("no se pudo escribir en el audit log") from error
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def verify(self) -> tuple[bool, str, int]:
        """Verifica toda la cadena; ausencia tras inicializar se considera pérdida."""
        try:
            handle = self.path.open("rb")
        except FileNotFoundError:
            if os.path.lexists(self.init_path) or os.path.lexists(self.health_path) or os.path.lexists(self.block_path):
                return False, "audit log ausente despues de inicializar", 0
            return True, "primera instalacion sin eventos", 0
        except OSError as error:
            return False, f"audit log ilegible: {type(error).__name__}", 0
        count = 0
        expected_prev = GENESIS
        try:
            with handle:
                for raw in handle:
                    if not raw.strip():
                        return False, f"linea vacia en auditoria en la linea {count + 1}", count
                    count += 1
                    try:
                        record = json.loads(raw)
                    except (ValueError, AttributeError):
                        return False, f"evento ilegible en la linea {count}", count
                    stored = str(record.pop("hash", "") or "")
                    if int(record.get("seq") or -1) != count:
                        return False, f"secuencia rota en la linea {count}", count
                    if str(record.get("prev") or "") != expected_prev:
                        return False, f"cadena rota en la linea {count}", count
                    if hashlib.sha256(_canonical(record)).hexdigest() != stored:
                        return False, f"hash alterado en la linea {count}", count
                    expected_prev = stored
        except (OSError, ValueError, TypeError) as error:
            return False, f"audit log ilegible o corrupto: {type(error).__name__}", count
        return True, "cadena integra", count


def atomic_json_write(path: Path | str, payload: dict, mode: int = 0o600) -> None:
    """Escribe JSON atomico, confirma archivo y directorio antes de retornar."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=str(target.parent), prefix=".sg-", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, target)
        temporary = ""
        directory_fd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass
