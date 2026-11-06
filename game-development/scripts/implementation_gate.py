#!/usr/bin/env python3
"""Implementation Gate: intermediario real entre el agente y el filesystem.

El gate no se limita a devolver ``allowed``: resuelve la ruta contra el
workspace, autoriza la operacion con el motor de autorizacion y solo entonces
ejecuta la escritura. Toda decision (permitida o denegada) se registra en un
audit log; si no se puede registrar, la operacion se deniega.

Alcance real
------------

Controladas: creacion, modificacion, sobrescritura y borrado de archivos
mediante este intermediario.

NO controladas: cualquier escritura directa del agente con acceso al sistema de
archivos, ejecucion de procesos externos, instalacion de dependencias,
migraciones y cambios de configuracion realizados fuera del gate. El gate no
puede impedir esas vias por si solo; requieren aislamiento del sistema
operativo, contenedor o workspace de solo lectura.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))

import approval_service
import revocation_registry
import validate

REQUIRED_CONTEXT_FIELDS = (
    "agent",
    "project",
    "spec_id",
    "version",
    "requirement",
    "task",
    "operation_type",
    "path",
    "workspace_root",
)

FILE_OPERATIONS = ("create_file", "modify_file", "overwrite_file", "delete_file")
UNPROTECTED_OPERATIONS = (
    "execute_script",
    "install_dependency",
    "migration",
    "config_change",
    "subagent_operation",
    "external_process",
)


class PathSafetyError(ValueError):
    """La ruta solicitada no es escribible de forma segura dentro del workspace."""


@dataclass
class Decision:
    allowed: bool
    operation: str = ""
    spec_id: str = ""
    version: str = ""
    reasons: list = field(default_factory=list)
    executed: bool = False
    path: str | None = None
    digest: str | None = None

    def as_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "executed": self.executed,
            "operation": self.operation,
            "spec_id": self.spec_id,
            "version": self.version,
            "path": self.path,
            "digest": self.digest,
            "reasons": list(self.reasons),
        }


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def resolve_workspace(workspace_root) -> Path:
    if not workspace_root:
        raise PathSafetyError("workspace_root ausente")
    workspace = Path(str(workspace_root))
    if not workspace.is_absolute():
        raise PathSafetyError("workspace_root debe ser absoluto")
    try:
        resolved = workspace.resolve(strict=True)
    except OSError as error:
        raise PathSafetyError("workspace_root inexistente") from error
    if not resolved.is_dir():
        raise PathSafetyError("workspace_root no es un directorio")
    return resolved


def safe_target(workspace: Path, relative_path) -> Path:
    """Resuelve una ruta relativa sin traversal, rutas absolutas ni symlinks."""
    raw = str(relative_path or "").strip()
    if not raw or "\x00" in raw or "\\" in raw:
        raise PathSafetyError("ruta vacia o con caracteres no admitidos")
    if os.path.isabs(raw):
        raise PathSafetyError("no se admiten rutas absolutas")
    pure = PurePosixPath(raw)
    parts = pure.parts
    if not parts or any(part in ("..", ".", "") for part in parts):
        raise PathSafetyError("la ruta contiene segmentos no permitidos")
    current = workspace
    for part in parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise PathSafetyError("la ruta atraviesa un enlace simbolico")
    target = workspace.joinpath(*parts)
    if target.is_symlink():
        raise PathSafetyError("el destino es un enlace simbolico")
    try:
        target.resolve(strict=False).relative_to(workspace)
    except (ValueError, OSError) as error:
        raise PathSafetyError("la ruta escapa del workspace") from error
    if not target.parent.is_dir() or target.parent.is_symlink():
        raise PathSafetyError("el directorio padre no existe o es un enlace simbolico")
    return target


def _atomic_write(target: Path, content: str) -> str:
    data = content.encode("utf-8")
    directory = target.parent
    descriptor, temporary = tempfile.mkstemp(dir=str(directory), prefix=".sg-", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        temporary = ""
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)
    return hashlib.sha256(data).hexdigest()


class ImplementationGate:
    """Intermediario unico de operaciones de escritura."""

    def __init__(self, approval: dict | None, spec_path: Path, key_store=None, registry=None, audit_path: Path | str | None = None, workspace_root: Path | str | None = None) -> None:
        self.approval = approval
        self.spec_path = Path(spec_path)
        self.workspace_root = Path(workspace_root) if workspace_root is not None else None
        self.key_store = key_store if key_store is not None else approval_service.get_default_key_store(self.workspace_root)
        if registry is not None:
            self.registry = registry
        else:
            spec_id = str((approval or {}).get("spec_id") or "")
            self.registry = revocation_registry.RevocationRegistry.for_spec(spec_id, key_store=self.key_store, workspace_root=self.workspace_root) if spec_id else None
        self.audit_path = Path(audit_path) if audit_path is not None else self._default_audit_path()

    def _default_audit_path(self) -> Path:
        configured = os.environ.get("SPEC_GUARDIAN_AUDIT_LOG")
        if configured and configured.strip():
            return Path(configured.strip())
        return revocation_registry.default_revocations_dir().parent / "audit.jsonl"

    def _audit(self, request: dict, decision: Decision) -> None:
        record = {
            "at": _now_iso(),
            "decision": decision.as_dict(),
            "request": {k: request.get(k) for k in REQUIRED_CONTEXT_FIELDS},
        }
        try:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True, ensure_ascii=True) + "\n")
        except OSError as error:
            raise PermissionError("no se pudo registrar la operacion en el audit log") from error

    def authorize(self, request: dict) -> Decision:
        decision = Decision(allowed=False, operation=str((request or {}).get("operation_type") or ""))
        if not isinstance(request, dict):
            decision.reasons.append("contexto de operacion ausente")
            return decision
        missing = [field_name for field_name in REQUIRED_CONTEXT_FIELDS if not str(request.get(field_name) or "").strip()]
        if missing:
            decision.reasons.append("contexto incompleto: " + ", ".join(missing))
            return decision
        decision.spec_id = str(request.get("spec_id") or "")
        decision.version = str(request.get("version") or "")
        operation_type = str(request.get("operation_type") or "")
        if operation_type in UNPROTECTED_OPERATIONS:
            decision.reasons.append("operacion no ejecutable por el gate (via no controlada)")
            return decision
        if operation_type not in FILE_OPERATIONS:
            decision.reasons.append(f"tipo de operacion no soportado: {operation_type}")
            return decision
        if self.approval is None:
            decision.reasons.append("no hay autorizacion registrada")
            return decision
        try:
            workspace = resolve_workspace(request.get("workspace_root"))
            target = safe_target(workspace, request.get("path"))
        except PathSafetyError as error:
            decision.reasons.append(str(error))
            return decision
        if self.registry is None:
            decision.reasons.append("registro de revocaciones no disponible")
            return decision
        authorized = validate.authorize_operation(
            self.approval,
            {key: request.get(key) for key in REQUIRED_CONTEXT_FIELDS},
            key_store=self.key_store,
            spec_path=self.spec_path,
            registry=self.registry,
            workspace_root=workspace,
        )
        if not authorized:
            decision.reasons.append("operacion fuera del alcance autorizado o autorizacion no verificable")
            return decision
        decision.allowed = True
        decision.path = str(target)
        decision.reasons.append("operacion autorizada")
        return decision

    def execute(self, request: dict) -> Decision:
        decision = self.authorize(request)
        try:
            self._audit(request if isinstance(request, dict) else {}, decision)
        except PermissionError as error:
            denial = Decision(allowed=False, operation=decision.operation, spec_id=decision.spec_id, version=decision.version)
            denial.reasons.append(str(error))
            return denial
        if not decision.allowed:
            return decision
        workspace = resolve_workspace(request.get("workspace_root"))
        target = safe_target(workspace, request.get("path"))
        operation_type = str(request.get("operation_type") or "")
        content = request.get("content")
        try:
            if operation_type == "create_file":
                if target.exists():
                    raise PathSafetyError("el archivo ya existe")
                decision.digest = _atomic_write(target, str(content or ""))
            elif operation_type == "modify_file":
                if not target.exists() or not stat.S_ISREG(target.lstat().st_mode):
                    raise PathSafetyError("el archivo a modificar no existe o no es regular")
                decision.digest = _atomic_write(target, str(content or ""))
            elif operation_type == "overwrite_file":
                decision.digest = _atomic_write(target, str(content or ""))
            elif operation_type == "delete_file":
                if not target.exists() or not stat.S_ISREG(target.lstat().st_mode):
                    raise PathSafetyError("el archivo a borrar no existe o no es regular")
                target.unlink()
                decision.digest = None
        except (PathSafetyError, OSError) as error:
            failed = Decision(allowed=False, operation=decision.operation, spec_id=decision.spec_id, version=decision.version, path=str(target))
            failed.reasons.append(f"operacion no ejecutada: {error}")
            try:
                self._audit(request, failed)
            except PermissionError:
                pass
            return failed
        decision.executed = True
        decision.path = str(target)
        try:
            self._audit(request, decision)
        except PermissionError:
            pass
        return decision
