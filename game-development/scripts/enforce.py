#!/usr/bin/env python3
"""Enforcement real: decision sobre operaciones de escritura (SPEC-001)."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import validate
import approval_service


def evaluate_write(operation: str, spec_path: Path, task_id: str = "TASK-001", approval_path: Path | None = None, operation_context: dict | None = None) -> dict:
    approval = validate.load_approval(approval_path) if approval_path else None
    allowed = False
    reason = "IMPLEMENTACION BLOQUEADA: PENDIENTE DE APROBACION HUMANA."
    if operation_context is not None:
        allowed = bool(validate.authorize_operation(approval, operation_context, key_store=approval_service.get_default_key_store()))
        spec_id = str(operation_context.get("spec_id") or "")
        version = str(operation_context.get("version") or "")
        if allowed and str(operation_context.get("path") or ""):
            if not validate.is_safe_path(Path(str(operation_context.get("workspace_root") or ".")), str(operation_context.get("path") or "")):
                allowed = False
        if allowed:
            return {
                "allowed": True,
                "operation": operation,
                "task_id": task_id,
                "spec_id": spec_id,
                "version": version,
                "reason": "Operacion verificada dentro del alcance autorizado.",
            }
        reason = "IMPLEMENTACION BLOQUEADA: LA OPERACION NO ESTA CONFORME AL ALCANCE AUTORIZADO."
        return {
            "allowed": False,
            "operation": operation,
            "task_id": task_id,
            "spec_id": spec_id,
            "version": version,
            "reason": reason,
        }
    result = validate.validate_spec(spec_path, approval=approval, key_store=approval_service.get_default_key_store())
    allowed = bool(result.get("implementation_allowed"))
    if allowed:
        return {
            "allowed": True,
            "operation": operation,
            "task_id": task_id,
            "spec_id": result.get("spec_id"),
            "version": result.get("version"),
            "reason": "Autorizacion verificada.",
        }
    reason = "IMPLEMENTACION BLOQUEADA: PENDIENTE DE APROBACION HUMANA." if str(result.get("status") or "").upper() != "APPROVED" else "IMPLEMENTACION BLOQUEADA: LA APROBACION NO PUEDE VERIFICARSE."
    return {
        "allowed": False,
        "operation": operation,
        "task_id": task_id,
        "spec_id": result.get("spec_id"),
        "version": result.get("version"),
        "reason": reason,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Evalua si una operacion de escritura esta autorizada (SPEC-001).")
    parser.add_argument("operation", help="Operacion de escritura a evaluar (p. ej. 'create_code').")
    parser.add_argument("spec", type=Path, help="Ruta a la especificacion (Markdown).")
    parser.add_argument("--task-id", default="TASK-001")
    parser.add_argument("--approval", type=Path, default=None)
    args = parser.parse_args(argv)
    decision = evaluate_write(args.operation, args.spec, task_id=args.task_id, approval_path=args.approval)
    print(json.dumps(decision, indent=2, ensure_ascii=False))
    return 0 if decision["allowed"] else 1


if __name__ == "__main__":
    sys.exit(main())
