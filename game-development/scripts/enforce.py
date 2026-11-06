#!/usr/bin/env python3
"""Enforcement real de operaciones de escritura (SPEC-001).

``evaluate`` calcula la decision; ``apply`` ejecuta la operacion a traves del
Implementation Gate, que es el unico intermediario que escribe. Sin contexto
completo de operacion la decision es denegar.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import approval_service
import implementation_gate
import revocation_registry
import validate


def _load_context(value: str | None) -> dict | None:
    if not value:
        return None
    if value == "-":
        try:
            data = json.load(sys.stdin)
        except ValueError:
            return None
        return data if isinstance(data, dict) else None
    path = Path(value)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def build_gate(spec_path: Path, approval_path: Path | None, context: dict) -> implementation_gate.ImplementationGate:
    approval = validate.load_approval(approval_path) if approval_path else None
    workspace_root = Path(str(context.get("workspace_root") or "")) if context.get("workspace_root") else None
    key_store = approval_service.get_default_key_store(workspace_root)
    spec_id = str((approval or {}).get("spec_id") or context.get("spec_id") or "")
    registry = revocation_registry.RevocationRegistry.for_spec(spec_id, key_store=key_store, workspace_root=workspace_root) if spec_id else None
    return implementation_gate.ImplementationGate(approval=approval, spec_path=spec_path, key_store=key_store, registry=registry, workspace_root=workspace_root)


def evaluate_write(operation: str, spec_path: Path, task_id: str = "", approval_path: Path | None = None, operation_context: dict | None = None) -> dict:
    """Decision de autorizacion para una operacion concreta."""
    if not isinstance(operation_context, dict):
        return {
            "allowed": False,
            "executed": False,
            "operation": operation,
            "task_id": task_id,
            "spec_id": None,
            "version": None,
            "path": None,
            "digest": None,
            "reasons": ["IMPLEMENTACION BLOQUEADA: OPERACION SIN CONTEXTO DE AUTORIZACION."],
        }
    context = dict(operation_context)
    if task_id and not context.get("task"):
        context["task"] = task_id
    if operation and not context.get("operation_type"):
        context["operation_type"] = operation
    gate = build_gate(Path(spec_path), approval_path, context)
    decision = gate.authorize(context)
    return decision.as_dict()


def apply_write(operation: str, spec_path: Path, approval_path: Path | None = None, operation_context: dict | None = None) -> dict:
    """Ejecuta la operacion si esta autorizada; deniega en cualquier otro caso."""
    if not isinstance(operation_context, dict):
        return {
            "allowed": False,
            "executed": False,
            "operation": operation,
            "task_id": "",
            "spec_id": None,
            "version": None,
            "path": None,
            "digest": None,
            "reasons": ["IMPLEMENTACION BLOQUEADA: OPERACION SIN CONTEXTO DE AUTORIZACION."],
        }
    context = dict(operation_context)
    if operation and not context.get("operation_type"):
        context["operation_type"] = operation
    gate = build_gate(Path(spec_path), approval_path, context)
    return gate.execute(context).as_dict()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evalua o aplica una operacion de escritura autorizada (SPEC-001).")
    subparsers = parser.add_subparsers(dest="mode", required=True)
    for name, help_text in (("evaluate", "Calcula la decision sin escribir."), ("apply", "Ejecuta la operacion a traves del gate.")):
        sub = subparsers.add_parser(name, help=help_text)
        sub.add_argument("--context", required=True, help="Contexto de operacion (JSON) o '-' para stdin.")
        sub.add_argument("--spec", type=Path, default=Path("game-development/specs/SPEC-001.md"))
        sub.add_argument("--approval", type=Path, default=None)
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    context = _load_context(args.context)
    if context is None:
        decision = {"allowed": False, "executed": False, "reasons": ["contexto de operacion ausente o ilegible"]}
    elif args.mode == "apply":
        decision = apply_write(str(context.get("operation_type") or ""), args.spec, approval_path=args.approval, operation_context=context)
    else:
        decision = evaluate_write(str(context.get("operation_type") or ""), args.spec, approval_path=args.approval, operation_context=context)
    print(json.dumps(decision, indent=2, ensure_ascii=False))
    return 0 if decision.get("allowed") else 1


if __name__ == "__main__":
    sys.exit(main())
