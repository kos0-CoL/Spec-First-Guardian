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

    # -- estado -----------------------------------------------------------
    def is_blocked(self) -> bool:
        return self.block_path.exists()

    def block_reason(self) -> str:
        try:
            return self.block_path.read_text(encoding="utf-8").strip()
        except OSError:
            return "auditoria incompleta"

    def mark_incomplete(self, reason: str, detail: dict | None = None) -> None:
        payload = {
            "at": _now_iso(),
            "reason": str(reason),
            "detail": detail or {},
        }
        self.block_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.block_path.with_name(self.block_path.name + ".tmp")
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.block_path)

    def clear_incomplete(self, operator: str, note: str) -> dict:
        """Reconcilia el estado y deja constancia del cierre en la cadena."""
        previous = self.block_reason()
        event = self.append(
            {
                "stage": "reconciled",
                "operator": str(operator or ""),
                "note": str(note or ""),
                "previous_block": previous,
            }
        )
        try:
            self.block_path.unlink()
        except FileNotFoundError:
            pass
        return event

    # -- escritura --------------------------------------------------------
    def _last_hash(self) -> tuple[int, str]:
        try:
            info = self.path.stat()
        except FileNotFoundError:
            return 0, GENESIS
        if not stat.S_ISREG(info.st_mode):
            raise AuditError("el audit log no es un archivo regular")
        with self.path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            if size == 0:
                return 0, GENESIS
            handle.seek(0)
            last = b""
            for line in handle:
                if line.strip():
                    last = line
        try:
            record = json.loads(last)
        except ValueError as error:
            raise AuditError("el audit log esta corrupto") from error
        return int(record.get("seq") or 0), str(record.get("hash") or "")

    def append(self, event: dict) -> dict:
        """Anade un evento y lo devuelve con ``seq`` y ``hash``."""
        if not isinstance(event, dict):
            raise AuditError("evento de auditoria invalido")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.lock_path.touch(mode=0o600, exist_ok=True)
            handle = self.lock_path.open("r+")
        except OSError as error:
            raise AuditError(f"audit log no escribible: {error}") from error
        with handle as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                seq, previous = self._last_hash()
                record = {
                    "seq": seq + 1,
                    "at": _now_iso(),
                    "prev": previous,
                    "event": event,
                }
                record["hash"] = hashlib.sha256(_canonical(record)).hexdigest()
                line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
                if len(line.encode("utf-8")) > MAX_EVENT_BYTES:
                    raise AuditError("evento de auditoria demasiado grande")
                descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                try:
                    os.write(descriptor, (line + "\n").encode("utf-8"))
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                return record
            except OSError as error:
                raise AuditError("no se pudo escribir en el audit log") from error
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    # -- verificacion -----------------------------------------------------
    def verify(self) -> tuple[bool, str, int]:
        """Verifica la cadena completa. Devuelve (valida, motivo, eventos)."""
        try:
            handle = self.path.open("rb")
        except FileNotFoundError:
            return True, "audit log vacio", 0
        except OSError as error:
            return False, f"audit log ilegible: {error}", 0
        count = 0
        expected_prev = GENESIS
        with handle:
            for raw in handle:
                if not raw.strip():
                    continue
                count += 1
                try:
                    record = json.loads(raw)
                except ValueError:
                    return False, f"evento ilegible en la linea {count}", count
                stored = str(record.pop("hash", "") or "")
                if int(record.get("seq") or -1) != count:
                    return False, f"secuencia rota en la linea {count}", count
                if str(record.get("prev") or "") != expected_prev:
                    return False, f"cadena rota en la linea {count}", count
                computed = hashlib.sha256(_canonical(record)).hexdigest()
                if computed != stored:
                    return False, f"hash alterado en la linea {count}", count
                expected_prev = stored
        return True, "cadena integra", count


def atomic_json_write(path: Path | str, payload: dict, mode: int = 0o600) -> None:
    """Escribe JSON de forma atomica con permisos restrictivos."""
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
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass
