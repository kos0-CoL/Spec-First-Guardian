#!/usr/bin/env python3
"""Implementation Gate: ejecutor de escrituras de la autoridad (SPEC-001).

El gate corre **dentro del proceso de la autoridad**. Resuelve el workspace con
descriptores de directorio (``safe_fs``), autoriza la operacion con el motor de
autorizacion y ejecuta la escritura sin volver a resolver la ruta, eliminando la
ventana TOCTOU de las comprobaciones basadas en cadenas.

Antes de escribir registra la intencion y despues el resultado. Si el registro
posterior falla, marca la auditoria como incompleta y bloquea nuevas
operaciones hasta que un administrador reconcilie el estado.

Alcance real: ``create_file``, ``modify_file``, ``overwrite_file`` y
``delete_file``. Las operaciones fuera de esa lista se deniegan; las vias que el
gate no controla (procesos, shell, dependencias, migraciones) solo se impiden
con aislamiento del sistema operativo, no con este modulo.
"""

from __future__ import annotations

import os
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import approval_service
import audit_chain
import revocation_registry
import safe_fs
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

PathSafetyError = safe_fs.UnsafePathError


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
    authorization_event_id: str = ""
    audit_seq: int | None = None
    audit_complete: bool = True

    def as_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "executed": self.executed,
            "operation": self.operation,
            "spec_id": self.spec_id,
            "version": self.version,
            "path": self.path,
            "digest": self.digest,
            "authorization_event_id": self.authorization_event_id,
            "audit_seq": self.audit_seq,
            "audit_complete": self.audit_complete,
            "reasons": list(self.reasons),
        }


def resolve_workspace(workspace_root) -> Path:
    if not workspace_root:
        raise PathSafetyError("workspace_root ausente")
    workspace = Path(str(workspace_root))
    if not workspace.is_absolute():
        raise PathSafetyError("workspace_root debe ser absoluto")
    if workspace.is_symlink():
        raise PathSafetyError("workspace_root es un enlace simbolico")
    try:
        resolved = workspace.resolve(strict=True)
    except OSError as error:
        raise PathSafetyError("workspace_root inexistente") from error
    if not resolved.is_dir():
        raise PathSafetyError("workspace_root no es un directorio")
    return resolved


def _spec_relative(spec_path: Path, workspace: Path) -> str:
    try:
        relative = spec_path.resolve().relative_to(workspace)
    except (ValueError, OSError) as error:
        raise PathSafetyError("la SPEC no reside en el workspace protegido") from error
    return "/".join(safe_fs.split_relative(str(relative)))


class ImplementationGate:
    """Intermediario unico de operaciones de escritura de la autoridad."""

    def __init__(
        self,
        approval: dict | None,
        spec_path: Path,
        key_store=None,
        registry=None,
        audit_path: Path | str | None = None,
        workspace_root: Path | str | None = None,
    ) -> None:
        self.approval = approval
        self.spec_path = Path(spec_path)
        self.workspace_root = Path(workspace_root) if workspace_root is not None else None
        self.key_store = key_store if key_store is not None else approval_service.get_default_key_store(self.workspace_root)
        if registry is not None:
            self.registry = registry
        else:
            spec_id = str((approval or {}).get("spec_id") or "")
            self.registry = (
                revocation_registry.RevocationRegistry.for_spec(spec_id, key_store=self.key_store, workspace_root=self.workspace_root)
                if spec_id
                else None
            )
        if audit_path is None:
            raise PathSafetyError("el gate exige un audit log explicito")
        self.audit = audit_chain.AuditChain(audit_path)
        self._audit_unavailable = ""

    # -- auditoria --------------------------------------------------------
    def _record(self, stage: str, request: dict, decision: Decision) -> dict | None:
        event = {
            "stage": stage,
            "operation": decision.operation,
            "spec_id": decision.spec_id,
            "version": decision.version,
            "path": request.get("path"),
            "agent": request.get("agent"),
            "project": request.get("project"),
            "requirement": request.get("requirement"),
            "task": request.get("task"),
            "authorization_event_id": decision.authorization_event_id,
            "allowed": decision.allowed,
            "executed": decision.executed,
            "digest": decision.digest,
            "reasons": list(decision.reasons),
        }
        try:
            return self.audit.append(event)
        except audit_chain.AuditError:
            return None

    def _mark_incomplete(self, decision: Decision, detail: str) -> None:
        decision.audit_complete = False
        decision.reasons.append(f"auditoria incompleta: {detail}")
        try:
            self.audit.mark_incomplete(
                "fallo al registrar el resultado de la operacion",
                {"operation": decision.operation, "path": decision.path, "detail": detail},
            )
        except OSError as error:
            # Cannot persist the marker: poison this gate instance so it cannot
            # continue granting permissions in this process.
            self._audit_unavailable = str(error)

    # -- autorizacion -----------------------------------------------------
    def authorize(self, request: dict) -> Decision:
        decision = Decision(allowed=False, operation=str((request or {}).get("operation_type") or ""))
        if not isinstance(request, dict):
            decision.reasons.append("contexto de operacion ausente")
            return decision
        audit_valid, audit_reason, _ = self.audit.verify()
        if self._audit_unavailable or self.audit.is_blocked() or not audit_valid:
            decision.reasons.append(f"auditoria no saludable: {audit_reason}; operaciones bloqueadas hasta reconciliar")
            return decision
        missing = [name for name in REQUIRED_CONTEXT_FIELDS if not str(request.get(name) or "").strip()]
        if missing:
            decision.reasons.append("contexto incompleto: " + ", ".join(missing))
            return decision
        decision.spec_id = str(request.get("spec_id") or "")
        decision.version = str(request.get("version") or "")
        decision.authorization_event_id = str((self.approval or {}).get("authorization_event_id") or "")
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
            spec_relative = _spec_relative(self.spec_path, workspace)
            root_fd = safe_fs.open_root(workspace)
            try:
                spec_text = safe_fs.read_file(root_fd, spec_relative).decode("utf-8")
            finally:
                os.close(root_fd)
        except (PathSafetyError, UnicodeDecodeError) as error:
            decision.reasons.append(str(error))
            return decision
        if self.registry is None:
            decision.reasons.append("registro de revocaciones no disponible")
            return decision
        context = {key: request.get(key) for key in REQUIRED_CONTEXT_FIELDS}
        authorized = validate.authorize_operation(
            self.approval,
            context,
            key_store=self.key_store,
            spec_path=self.spec_path,
            registry=self.registry,
            workspace_root=workspace,
            spec_text=spec_text,
        )
        if not authorized:
            decision.reasons.append("operacion fuera del alcance autorizado o autorizacion no verificable")
            return decision
        decision.allowed = True
        decision.path = str(workspace.joinpath(*safe_fs.split_relative(str(request.get("path")))))
        decision.reasons.append("operacion autorizada")
        return decision

    # -- ejecucion --------------------------------------------------------
    def execute(self, request: dict) -> Decision:
        decision = self.authorize(request)
        intent = self._record("intent", request if isinstance(request, dict) else {}, decision)
        if intent is None:
            denial = Decision(allowed=False, operation=decision.operation, spec_id=decision.spec_id, version=decision.version)
            denial.reasons.append("no se pudo registrar la intencion: operacion denegada")
            denial.audit_complete = False
            return denial
        decision.audit_seq = int(intent.get("seq") or 0)
        if not decision.allowed:
            if self._record("denied", request, decision) is None:
                self._mark_incomplete(decision, "no se pudo registrar la denegacion")
            return decision

        workspace = resolve_workspace(request.get("workspace_root"))
        relative = str(request.get("path"))
        operation_type = str(request.get("operation_type"))
        content = str(request.get("content") or "").encode("utf-8")
        try:
            root_fd = safe_fs.open_root(workspace)
            try:
                if operation_type == "create_file":
                    decision.digest = safe_fs.write_file(root_fd, relative, content, mode="create")
                elif operation_type == "modify_file":
                    decision.digest = safe_fs.write_file(root_fd, relative, content, mode="modify")
                elif operation_type == "overwrite_file":
                    decision.digest = safe_fs.write_file(root_fd, relative, content, mode="overwrite")
                elif operation_type == "delete_file":
                    safe_fs.delete_file(root_fd, relative)
                    decision.digest = None
            finally:
                os.close(root_fd)
        except (PathSafetyError, OSError) as error:
            failed = Decision(
                allowed=False,
                operation=decision.operation,
                spec_id=decision.spec_id,
                version=decision.version,
                path=decision.path,
                audit_seq=decision.audit_seq,
            )
            reason = "el archivo ya existe" if isinstance(error, FileExistsError) else str(error)
            failed.reasons.append(f"operacion no ejecutada: {reason}")
            if self._record("result", request, failed) is None:
                self._mark_incomplete(failed, "no se pudo registrar el fallo de escritura")
            return failed

        decision.executed = True
        if self._record("result", request, decision) is None:
            self._mark_incomplete(decision, "la escritura se ejecuto pero no se pudo registrar el resultado")
        return decision
